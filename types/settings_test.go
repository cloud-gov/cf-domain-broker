package types

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/suite"
)

type SettingsSuite struct {
	suite.Suite
}

// DomainBroker test entry point.
func TestSettingsSuite(t *testing.T) {
	suite.Run(t, new(SettingsSuite))
}

func (s *SettingsSuite) SetupTest() {}

func (s *SettingsSuite) TearDownTest() {}

func (s *SettingsSuite) TestGlobalSettingsResolverDecode() {
	runtimeSettings := &RuntimeSettings{}

	requiredVars := []string{"alb_names",
		"acme_url",
		"aws_access_key_id",
		"aws_default_region",
		"aws_secret_access_key",
		"broker_password",
		"broker_username",
		"bucket",
		"cf_api_address",
		"database_url",
		"email"}

	starter := "CF_DOMAIN_BROKER_TEST"

	for idx := range requiredVars {
		if err := os.Setenv(fmt.Sprintf("%s_%s", starter, strings.ToUpper(requiredVars[idx])), "testing1234"); err != nil {
			s.Require().NoError(err, "there should be no error setting the required env var.")
		}
	}

	if err := os.Setenv(fmt.Sprintf("%s_%s", starter, "RESOLVERS"), "google=8.8.8.8:53,cloudflare=1.1.1.1:53"); err != nil {
		s.Require().NoError(err, "there should be no error setting the required env var.")
	}

	if err := envconfig.Process(starter, runtimeSettings); err != nil {
		s.Require().NoError(err, "there should be no error trying to parse the arguments")
	}

	val, ok := runtimeSettings.Resolvers["google"]
	if !ok {
		s.Require().NotEmpty(runtimeSettings.Resolvers["google"], "the google resolver must exist.")
	}
	s.Require().NotEmpty(val, "the google resolver must not be empty.")
	s.Require().Equal("8.8.8.8:53", val, "the google resolver doesn't match.")

	val, ok = runtimeSettings.Resolvers["cloudflare"]
	if !ok {
		s.Require().NotEmpty(runtimeSettings.Resolvers["cloudflare"], "the cloudflare resolver must exist.")
	}
	s.Require().NotEmpty(val, "the cloudflare resolver must not be empty.")
	s.Require().Equal("1.1.1.1:53", val, "the cloudflare resolver doesn't match.")

	if err := os.Unsetenv(starter + "_RESOLVERS"); err != nil {
		s.Require().NoError(err, "there should be no error unsetting the resolvers env var.")
	}

	for idx := range requiredVars {
		if err := os.Unsetenv(fmt.Sprintf("%s_%s", starter, strings.ToUpper(requiredVars[idx]))); err != nil {
			s.Require().NoError(err, "there should be no error unsetting the required env var.")
		}
	}
}
