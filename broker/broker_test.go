package broker

import (
	"context"
	"fmt"
	"os"
	"testing"

	"code.cloudfoundry.org/lager"
	cf_domain_broker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/fakes"
	"github.com/18f/cf-domain-broker/gravel"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
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
	Gravel *gravel.GravelHarness

	logger lager.Logger
}

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupSuite() {

	var err error
	s.DB, err = gorm.Open("sqlite3", ":memory:")
	s.Require().NoError(err)

	// set up the gravel test harness.
	s.Gravel = gravel.NewGravelHarness(s.T())

	settings := types.Settings{}
	settings.AcmeUrl = fmt.Sprintf("https://%s/dir", s.Gravel.ListenAddress)

	// set up our test writers.
	testSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	logger := lager.NewLogger("domain-broker-test")
	logger.RegisterSink(testSink)
	loggerSession := logger.Session("test-suite")

	if err := s.DB.AutoMigrate(&models.DomainRoute{}, &models.UserData{}).Error; err != nil {
		s.Error(err)
	}

	resolvers := make(map[string]string)
	resolvers["localhost"] = fmt.Sprintf("localhost:%d", s.Gravel.DnsPort)

	rms := loggerSession.Session("route-manager")
	s.Manager = routes.RouteManager{
		Logger:         rms,
		IamSvc:         new(fakes.FakeIAMAPI),
		CloudFrontSvc:  new(fakes.FakeCloudFrontAPI),
		ElbSvc:         new(fakes.FakeELBV2API),
		Settings:       settings,
		Db:             s.DB,
		AcmeHttpClient: s.Gravel.Client,
		Resolvers:      resolvers,
	}

	s.Broker = NewDomainBroker(s.Manager, rms)
}

func (s *BrokerSuite) TestDomainBroker_Provision() {
	b := s.Broker

	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cf_domain_broker.DomainPlanId,
		RawParameters: []byte(`{"domains": ["test.service"]}`),
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
