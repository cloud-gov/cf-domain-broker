package le_providers

import (
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/suite"
)

type DnsMessengerSuite struct {
	suite.Suite
	dm DomainMessenger
}

// DomainBroker test entry point.
func TestSettingsSuite(t *testing.T) {
	suite.Run(t, new(DnsMessengerSuite))
}

func (s *DnsMessengerSuite) SetupTest() {
	s.dm = DomainMessenger{
		Domain:     "test.domain",
		Token:      "1234qwer",
		KeyAuth:    "5678tyui",
		Message:    msg,
		InstanceId: uuid.New(),
		ValidUntil: time.Time{},
	}
}

func (s *DnsMessengerSuite) TearDownTest() {
	s.dm = DomainMessenger{}
}