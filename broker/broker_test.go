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
	"github.com/18f/cf-domain-broker/interfaces"
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
	Manager  routes.RouteManager
	Settings types.Settings

	DB     *gorm.DB
	Gravel *gravel.Gravel

	logger lager.Logger
}

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupSuite() {

	var err error
	s.DB, err = gorm.Open("sqlite3", "/Users/kevinmlloyd/Development/go/workspace/cf-domain-broker/broker/testdata/test.db")
	s.Require().NoError(err)

	// set up the gravel test harness.
	gravelOpts := gravel.NewDefaultGravelOpts()

	internalResolver := fmt.Sprintf("localhost:%d", gravelOpts.DnsOpts.DnsPort)

	gravelOpts.VAOpts.CustomResolverAddress = internalResolver // allows gravel to verify itself.
	gravelOpts.AutoUpdateAuthZRecords = true                   // enable to just give us the certificate.
	s.Gravel, err = gravel.New(gravelOpts)
	s.Require().NoError(err)

	// start the servers
	go s.Gravel.StartDnsServer()
	go s.Gravel.StartWebServer()

	settings := types.Settings{}
	settings.AcmeUrl = fmt.Sprintf("https://%s%s", s.Gravel.Opts.ListenAddress, s.Gravel.Opts.WfeOpts.DirectoryPath)
	settings.Email = "cloud-gov-operations@gsa.gov"
	resolvers := make(map[string]string)
	resolvers["localhost"] = internalResolver

	// migrate our DB to set up the schema.
	if err := s.DB.AutoMigrate(&models.DomainRoute{}, &models.UserData{}, &models.Domain{}, &models.Certificate{}, &leproviders.DomainMessenger{}).Error; err != nil {
		s.Require().NoError(err)
	}
	s.DB.SetLogger(s.Gravel.Logger) // use the gravel logger because lager.Logger doesn't have `Print`

	// set up our fakes. we need to create an elb so there's something the route manager can query for.
	elbSvc := fakes.NewMockELBV2API()
	iamSvc := fakes.NewMockIAMAPI()
	/*cloudfrontSvc := new(fakes.FakeCloudFrontAPI)*/

	// create 5 ELBs, and a random number (<= 25) of listeners on each to ensure there's some variety in it, so we can
	// ensure the least assigned logic works.
	for idx := 0; idx < 5; idx++ {
		elbString := fmt.Sprintf("test-elb-%d", idx)
		elbResp, _ := elbSvc.CreateLoadBalancer(&elbv2.CreateLoadBalancerInput{
			Name: aws.String(elbString),
		})
		for nidx := 0; nidx < rand.Intn(25); nidx++ {
			_, _ = elbSvc.CreateListener(&elbv2.CreateListenerInput{
				DefaultActions:  []*elbv2.Action{{}},
				LoadBalancerArn: elbResp.LoadBalancers[0].LoadBalancerArn,
				Port:            aws.Int64(443),
				Protocol:        aws.String("HTTPS"),
				Certificates:    make([]*elbv2.Certificate, rand.Intn(25)),
			})
		}
	}

	// set up our test writers.
	testSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	logger := lager.NewLogger("domain-broker-test")
	logger.RegisterSink(testSink)
	loggerSession := logger.Session("test-suite")
	trmLogger := loggerSession.Session("test-route-manager")

	s.Manager, err = routes.NewManager(
		trmLogger,
		iamSvc,
		&interfaces.CloudfrontDistribution{settings, nil},
		elbSvc,
		settings,
		s.DB,
	)
	s.Manager.Dns = s.Gravel.DnsServer.Opts.Provider
	s.Manager.AcmeHttpClient = s.Gravel.Client
	s.Manager.Resolvers = map[string]string{"localhost": fmt.Sprintf("localhost:%d", s.Gravel.Opts.DnsOpts.DnsPort)}
	s.Require().NoError(err)

	s.Broker = NewDomainBroker(&s.Manager, trmLogger)
}

func (s *BrokerSuite) TestDomainBroker_ProvisionDomainPlan() {
	b := s.Broker

	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service"]}`)),
	}

	res, err := b.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	var verifyRoute models.DomainRoute
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).First(&verifyRoute).Error; err != nil {
		s.Require().NoError(err, "there should be no error querying for the domain route")
	}

	s.Require().NotNil(verifyRoute, "the route must not be empty")

	localCert := &models.Certificate{}
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).First(&localCert).Error; err != nil {
		s.Require().NoError(err, "there should be no error when searching for the related certificate in the database")
	}

	s.Require().EqualValues(serviceInstanceId, verifyRoute.InstanceId, "service instance id must match deployed service instance")
	s.Require().EqualValues(cfdomainbroker.Provisioned, verifyRoute.State, "state must be provisioned")
	s.Require().NotNil(localCert, "certificate result must not be nil")
	s.Require().NotEmpty(localCert.Resource.Certificate, "certificate must not be empty")
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
