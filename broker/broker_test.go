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
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestBrokerSuite(t *testing.T) {
	suite.Run(t, new(BrokerSuite))
}

type BrokerSuite struct {
	suite.Suite
	Broker   *DomainBroker
	Manager  routes.RouteManager
	Cf       *cfclient.Client
	Settings types.Settings
	logger   lager.Logger

	DB   *gorm.DB
	Mock sqlmock.Sqlmock
}

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

	s.Cf, err = cfclient.NewClient(&cfclient.Config{})

	if err != nil {
		loggerSession.Fatal("cf-client-builder", err)
	}

	if err := s.DB.AutoMigrate(&models.DomainRoute{}, &types.ALBProxy{}, &models.Certificate{}, &models.UserData{}).Error; err != nil {
		loggerSession.Fatal("db-auto-migrate", err)
	}

	rms := loggerSession.Session("route-manager")
	s.Manager = routes.RouteManager{
		Logger:     rms,
		Iam:        new(fakes.FakeIAMAPI),
		CloudFront: new(fakes.FakeCloudFrontAPI),
		ElbSvc:     new(fakes.FakeELBV2API),
		Settings:   settings,
		Db:         s.DB,
	}

	s.Broker = NewDomainBroker(s.Manager, s.Cf, rms)
}

func (s *BrokerSuite) TestDomainBroker_Services(t *testing.T) {
	res, err := s.Broker.Services(context.Background())

	assert.Nil(t, err)
	assert.Equal(t, 1, len(res))          // one service
	assert.Equal(t, 2, len(res[0].Plans)) //two plans
}

//func TestBind(t *testing.T) {
//	b := DomainBroker{}
//	_, err := b.Bind(context.Background(), "", "", brokerapi.BindDetails{}, false)
//	assert.NotNil(t, err)
//}
//
//func TestUnbind(t *testing.T) {
//	b := DomainBroker{}
//	_, err := b.Unbind(context.Background(), "", "", brokerapi.UnbindDetails{}, false)
//	assert.NotNil(t, err)
//}
