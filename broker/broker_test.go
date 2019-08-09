package broker

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/fakes"
	leproviders "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/18f/gravel"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/pborman/uuid"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/stretchr/testify/suite"
)

// Broker test entry point.
func TestBrokerSuite(t *testing.T) {
	suite.Run(t, new(BrokerSuite))
}

// Mocks and such.
type BrokerSuite struct {
	suite.Suite
	Broker   *DomainBroker
	Manager  *routes.RouteManager
	Settings types.Settings

	DB     *gorm.DB
	Gravel *gravel.Gravel

	logger lager.Logger
}

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupSuite() {

	var err error
	s.DB, err = gorm.Open("sqlite3", ":memory:")
	s.Require().NoError(err)

	// set up the gravel test harness.
	gravelOpts := gravel.NewDefaultGravelOpts()

	internalResolver := fmt.Sprintf("localhost:%d", gravelOpts.DnsOpts.DnsPort)

	gravelOpts.VAOpts.CustomResolverAddress = internalResolver
	gravelOpts.AutoUpdateAuthZRecords = true // enable to just give us the certificate.
	s.Gravel, err = gravel.New(gravelOpts)
	s.Require().NoError(err)

	// start the servers
	go s.Gravel.StartDnsServer()
	go s.Gravel.StartWebServer()

	settings := types.Settings{}
	settings.AcmeUrl = fmt.Sprintf("https://%s%s", s.Gravel.Opts.ListenAddress, s.Gravel.Opts.WfeOpts.DirectoryPath)

	// set up our test writers.
	testSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	logger := lager.NewLogger("domain-broker-test")
	logger.RegisterSink(testSink)
	loggerSession := logger.Session("test-suite")

	// migrate our DB to set up the schema.
	if err := s.DB.AutoMigrate(&models.DomainRoute{}, &models.UserData{}, &leproviders.DomainMessenger{}).Error; err != nil {
		s.Require().NoError(err)
	}

	resolvers := make(map[string]string)
	resolvers["localhost"] = internalResolver

	// set up our fakes. we need to create an elb so there's something the route manager can query for.
	elbSvc := fakes.NewMockELBV2API()
	iamSvc := fakes.NewMockIAMAPI()
	cloudfrontSvc := new(fakes.FakeCloudFrontAPI)

	// create 5 ELBs, and a random number (<= 25) of listeners on each to ensure there's some variety in it, so we can
	// ensure the least assigned logic works.
	for idx := 0; idx < 5; idx++ {
		elbString := fmt.Sprintf("test-elb-%d", idx)
		elbResp, _ := elbSvc.CreateLoadBalancer(&elbv2.CreateLoadBalancerInput{
			Name: aws.String(elbString),
		})
		for nidx := 0; nidx < rand.Intn(25); nidx++ {
			_, _ = elbSvc.CreateListener(&elbv2.CreateListenerInput{
				DefaultActions: []*elbv2.Action{{}},
				LoadBalancerArn: elbResp.LoadBalancers[0].LoadBalancerArn,
				Port:         aws.Int64(443),
				Protocol:     aws.String("HTTPS"),
				Certificates: make([]*elbv2.Certificate, rand.Intn(25)),
			})
		}
	}

	trmLogger := loggerSession.Session("test-route-manager")

	s.Manager, err = routes.NewManager(
		trmLogger,
		iamSvc,
		cloudfrontSvc,
		elbSvc,
		settings,
		s.DB,
		s.Gravel.Opts.DnsOpts.Provider,
		s.Gravel.Client,
		map[string]string{"localhost": fmt.Sprintf("localhost:%d", s.Gravel.Opts.DnsOpts.DnsPort)})
	s.Require().NoError(err)

	s.Broker = NewDomainBroker(s.Manager, trmLogger)
}

func (s *BrokerSuite) TestDomainBroker_Provision() {
	b := s.Broker

	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["%s"]}`, "test.service")),
	}

	res, err := b.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Error(err, "provisioning is throwing an error")
	}

	s.Require().NoError(err, "expected no error on provision")
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")
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
	s.NotNil(err, "expected error on get binding")
}

func (s *BrokerSuite) TestDomainBroker_LastBindingOperation() {
	b := s.Broker
	_, err := b.LastBindingOperation(context.Background(), "", "", domain.PollDetails{})
	s.NotNil(err, "expected error on last binding operation")
}
