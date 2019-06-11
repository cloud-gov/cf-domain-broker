package broker

import (
	"code.cloudfoundry.org/lager"
	"context"
	"database/sql"
	"github.com/18f/cf-domain-broker/fakes"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
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
