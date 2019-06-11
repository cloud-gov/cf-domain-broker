package broker

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"github.com/18f/cf-domain-broker/fakes"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jinzhu/gorm"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
	"github.com/miekg/dns"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Broker test entry point.
func TestBrokerSuite(t *testing.T) {
	suite.Run(t, new(BrokerSuite))
}

// Mocks and such.
type BrokerSuite struct {
	suite.Suite
	Broker   *DomainBroker
	Manager  routes.RouteManager
	Settings types.Settings
	logger   lager.Logger

	DB   *gorm.DB
	Mock sqlmock.Sqlmock
}


var (
	testDnsRecords = map[string]string{}
	kill chan syscall.Signal
	pebbleServer http.Server
)

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupSuite() {
	var (
		db  *sql.DB
		err error
	)

	db, s.Mock, err = sqlmock.New()
	require.NoError(s.T(), err)

	s.DB, err = gorm.Open("postgres", db)
	require.NoError(s.T(), err)
	s.DB.LogMode(true)

	settings := types.Settings{}

	logger := lager.NewLogger("domain-broker-test")
	loggerSession := logger.Session("test-suite")

	if err := s.DB.AutoMigrate(&models.DomainRoute{}, &models.UserData{}).Error; err != nil {
		s.Error(err)
	}

	rms := loggerSession.Session("route-manager")
	s.Manager = routes.RouteManager{
		Logger:        rms,
		IamSvc:        new(fakes.FakeIAMAPI),
		CloudFrontSvc: new(fakes.FakeCloudFrontAPI),
		ElbSvc:        new(fakes.FakeELBV2API),
		Settings:      settings,
		Db:            s.DB,
	}

	s.Broker = NewDomainBroker(s.Manager, rms)

	kill = make(chan syscall.Signal, 10)
}

// Teardown after each test.
func (s *BrokerSuite) TearDownTestSuite() {
	for i := 0; i < 10; i++ {
		kill <- syscall.SIGKILL
	}
}

func (s *BrokerSuite) TestDomainBroker_Services() {

	res, err := s.Broker.Services(context.Background())

	s.Nil(err, "expected ")
	s.Equal(1, len(res), "expected one service")        // one service
	s.Equal(2, len(res[0].Plans), "expected two plans") //two plans
}

func (s *BrokerSuite) TestDomainBroker_Bind() {
	b := s.Broker
	_, err := b.Bind(context.Background(), "", "", domain.BindDetails{}, false)
	s.NotNil(err, "expected error on bind")
}

func (s *BrokerSuite) TestDomainBroker_Unbind() {
	b := s.Broker
	_, err := b.Unbind(context.Background(), "", "", domain.UnbindDetails{}, false)
	s.NotNil(err, "expected error on unbind")
}

func (s *BrokerSuite) TestDomainBroker_GetBinding() {
	b := s.Broker
	_, err := b.GetBinding(context.Background(), "", "")
	s.NotNil(err, "expected error on unbind")
}

func (s *BrokerSuite) TestDomainBroker_LastBindingOperation() {
	b := s.Broker
	_, err := b.LastBindingOperation(context.Background(), "", "", domain.PollDetails{})
	s.NotNil(err, "expected error on last binding operation")
}

// startPebble will start the Pebble ACME server so we can have a local LE integration testing environment.
func startPebble(s *suite.Suite) {

	// create the base certificate fields.
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"General Services Administration"},
			Country:      []string{"US"},
			Province:     []string{"CO"},
			Locality:     []string{"Boulder"},
			PostalCode:   []string{"80301"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create a cert.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, priv)
	if err != nil {
		s.Error(err, "expected no error creating certificate")
	}

	// in-memory filesystem.
	fs := afero.NewMemMapFs()

	// save the certificate cert.
	caCrt, err := fs.Create("certificate.crt")
	if err != nil {
		s.Error(err, "expected no error creating certificate cert in-memory file.")
	}
	if err := pem.Encode(caCrt, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b}); err != nil {
		s.Error(err, "expected no error generating certificate pair")
	}
	defer caCrt.Close()

	// save the certificate private key.
	caKey, err := fs.Create("certificate.key")
	if err != nil {
		s.Error(err, "expected no error creating certificate key in-memory file")
	}
	if err := pem.Encode(caKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		s.Error(err, "expected no error generating certificate pair")
	}
	defer caKey.Close()

	cacrt, err := ioutil.ReadAll(caCrt)
	if err != nil {
		s.Error(err, "expected no error reading public key")
	}
	cakey, err := ioutil.ReadAll(caKey)
	if err != nil {
		s.Error(err, "expected no error reading private key")
	}

	// create the pebble config.
	config := &struct {
		Pebble struct {
			ListenAddress string
			HTTPPort      int
			TLSPort       int
			Certificate   string
			PrivateKey    string
		}
	}{
		Pebble: struct {
			ListenAddress string
			HTTPPort      int
			TLSPort       int
			Certificate   string
			PrivateKey    string
		}{ListenAddress: "0.0.0.0:14000", HTTPPort: 5002, TLSPort: 5001, Certificate: string(cacrt), PrivateKey: string(cakey)},
	}

	// build our DNS server
	go buildDnsTestServer(s)

	// set up pebble.
	logger := log.New(os.Stdout, "test", 0)
	clk := clock.New()
	localDb := db.NewMemoryStore(clk)
	localCa := ca.New(logger, localDb)
	localVa := va.New(logger, clk, 5002, 5001, false)

	wfeImpl := wfe.New(logger, clk, localDb, localVa, localCa, false)
	muxHandler := wfeImpl.Handler()

	logger.Printf("Listening on: %s\n", config.Pebble.ListenAddress)
	logger.Printf("ACME directory available at: https://%s%s",
		config.Pebble.ListenAddress, wfe.DirectoryPath)
	logger.Printf("Root CA certificate available at: https://%s%s",
		config.Pebble.ListenAddress, wfe.RootCertPath)
	pebbleServer = http.Server{
		Addr: "0.0.0.0:14000",
		TLSConfig: &tls.Config{

		},
	}
	err = http.ListenAndServeTLS(
		config.Pebble.ListenAddress,
		config.Pebble.Certificate,
		config.Pebble.PrivateKey,
		muxHandler)
}

func buildDnsTestServer(s *suite.Suite) {
	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)

	t := s.T()

	// start server
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	t.Logf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		t.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

var records = map[string]string{}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeTXT:
			txt := records[q.Name]
			if txt != "" {
				rr, _ := dns.NewRR(txt)
				m.Answer = append(m.Answer, rr)
			}
		}

	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}
