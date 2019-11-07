package le_providers

import (
	"crypto"
	"net"
	"net/http"
	"testing"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/suite"
)

func TestClientSuite(t *testing.T) {
	suite.Run(t, new(ClientSuite))
}

type ClientSuite struct {
	suite.Suite

	logger lager.Logger
	user   *testUser
}

type testUser struct {
	gorm.Model
	Id           string `gorm:"primary_key"`
	Email        string `gorm:"not null"`
	Registration *registration.Resource
	PublicKey    crypto.PublicKey  `gorm:"type:varchar"`
	PrivateKey   crypto.PrivateKey `gorm:"type:varchar"`
}

func (u testUser) GetEmail() string {
	return u.Email
}

func (u testUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u testUser) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

func (s *ClientSuite) SetupSuite() {
	// build the user with the new key, instantiate a client
	s.user = &testUser{
		Email:      "test@gsa.gov",
		PublicKey:  "123",
		PrivateKey: "123",
	}
	s.logger = lager.NewLogger("test")
}

// todo (mxplusb): add better test.
func (s *ClientSuite) TestNewAcmeWithoutClient() {

	_, err := NewAcmeClient(nil, make(map[string]string), lego.NewConfig(s.user), ServiceBrokerDNSProvider{}, s.logger, "")
	if err != nil {
		s.Error(err, "error instantiating new acme client.")
	}

	s.Require().Error(err, "there should be an error when building the lego client without an http client")
}

func (s *ClientSuite) TestNewAcmeClientWithHttpClient() {

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	a, err := NewAcmeClient(client, make(map[string]string), lego.NewConfig(s.user), ServiceBrokerDNSProvider{}, s.logger, "")
	if err != nil {
		s.Error(err, "error instantiating new acme client.")
	}

	s.Require().NoError(err)
	s.Require().NotNil(a.Client)
}
