package gravel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pebble/ca"
	"github.com/letsencrypt/pebble/db"
	"github.com/letsencrypt/pebble/va"
	"github.com/letsencrypt/pebble/wfe"
	"github.com/miekg/dns"
	"github.com/spf13/afero"
)

type GravelHarness struct {
	Server        http.Server
	PublicKey     []byte
	PrivateKey    []byte
	HttpPort      int
	HttpsPort     int
	ListenAddress string
	DnsPort       int
	TestRecords   map[string]string

	t      *testing.T
	logger *log.Logger
	fs     afero.Fs
	clk    clock.Clock
}

func NewGravelHarness(t *testing.T) *GravelHarness {
	gh := &GravelHarness{
		fs:            afero.NewMemMapFs(),
		t:             t,
		logger:        log.New(os.Stdout, "test", 0),
		clk:           clock.New(),
		HttpPort:      5001,
		HttpsPort:     5002,
		ListenAddress: "0.0.0.0:14000",
		DnsPort:       5353,
		TestRecords:   make(map[string]string),
	}

	// build the DNS server and wait for it to boot.
	t.Log("booting dns server")
	go gh.buildDnsTestServer()
	time.Sleep(time.Second * 1)
	t.Log("dns server booted")

	// set our default resolver to be localhost:DnsPort so we can respond to DNS queries.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", fmt.Sprintf("localhost:%d", gh.DnsPort))
		},
	}

	// start pebble and wait for it to boot.
	t.Log("booting pebble")
	go gh.startPebble()
	time.Sleep(time.Second * 3)
	t.Log("pebble booted")

	return gh
}

func (g *GravelHarness) generateCerts() {
	var err error

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
		g.t.Error(err, "expected no error creating certificate")
	}

	// save the certificate cert.
	caCrt, err := g.fs.Create("certificate.crt")
	if err != nil {
		g.t.Error(err, "expected no error creating certificate cert in-memory file.")
	}
	if err := pem.Encode(caCrt, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b}); err != nil {
		g.t.Error(err, "expected no error generating certificate pair")
	}
	defer caCrt.Close()

	// save the certificate private key.
	caKey, err := g.fs.Create("certificate.key")
	if err != nil {
		g.t.Error(err, "expected no error creating certificate key in-memory file")
	}
	if err := pem.Encode(caKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		g.t.Error(err, "expected no error generating certificate pair")
	}
	defer caKey.Close()

	g.PublicKey, err = ioutil.ReadAll(caCrt)
	if err != nil {
		g.t.Error(err, "expected no error reading public key")
	}
	g.PrivateKey, err = ioutil.ReadAll(caKey)
	if err != nil {
		g.t.Error(err, "expected no error reading private key")
	}
}

// startPebble will start the Pebble ACME server so we can have a local LE integration testing environment.
func (g *GravelHarness) startPebble() {
	var err error

	localDb := db.NewMemoryStore(g.clk)
	localCa := ca.New(g.logger, localDb)
	localVa := va.New(g.logger, g.clk, g.HttpPort, g.HttpsPort, false)

	wfeImpl := wfe.New(g.logger, g.clk, localDb, localVa, localCa, false)
	muxHandler := wfeImpl.Handler()

	tconf := &tls.Config{}
	tconf.Certificates = make([]tls.Certificate, 1)
	tconf.Certificates[0], err = tls.X509KeyPair(g.PublicKey, g.PrivateKey)
	if err != nil {
		g.t.Error(err)
	}

	g.Server = http.Server{
		Addr: g.ListenAddress,
		TLSConfig: tconf,
		Handler: muxHandler,
	}

	g.logger.Printf("Listening on: %s\n", g.ListenAddress)
	g.logger.Printf("ACME directory available at: https://%s%s", g.ListenAddress, wfe.DirectoryPath)
	g.logger.Printf("Root CA certificate available at: https://%s%s", g.ListenAddress, wfe.RootCertPath)

	err = g.Server.ListenAndServeTLS("", "")
	if err != nil {
		g.t.Error(err, "expected pebble to start and run without errors")
	}
}

func (g *GravelHarness) buildDnsTestServer() {
	// attach request handler func
	dns.HandleFunc("service.", g.handleDnsRequest)

	// start server
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	g.t.Logf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		g.t.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func (g *GravelHarness) parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeTXT:
			txt := g.TestRecords[q.Name]
			if txt != "" {
				rr, _ := dns.NewRR(txt)
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func (g *GravelHarness) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		g.parseQuery(m)
	}

	w.WriteMsg(m)
}
