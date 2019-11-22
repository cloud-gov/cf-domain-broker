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
		InstanceId: uuid.New(),
		ValidUntil: time.Time{},
	}
}

func (s *DnsMessengerSuite) TearDownTest() {}

func (s *DnsMessengerSuite) TestDnsMessageWriter() {

	tsVerification := `Please add the following text record to your DNS server. If you don't have the TXT record updated to the below value before the validity expires, you will need to create a new instance of this service.
TXT Record:			_acme-challenge.test.domain
TXT Record Value:	5678tyui
Valid Until:		Monday, 01-Jan-01 00:00:00 UTC
`

	ts := s.dm.String()
	s.Require().Equal(tsVerification, ts, "the domain messenger output should match.")
}
