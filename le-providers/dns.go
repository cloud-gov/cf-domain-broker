package le_providers

import (
	"bytes"
	"fmt"
	"text/tabwriter"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
)

// Internal DNS provider.
type ServiceBrokerDNSProvider struct {
	// db access
	db     *gorm.DB
	logger lager.Logger
}

func NewServiceBrokerDNSProvider(db *gorm.DB, logger lager.Logger) *ServiceBrokerDNSProvider {
	return &ServiceBrokerDNSProvider{db: db, logger: logger.Session("service-broker-dns-provider")}
}

// Set our default timeout to be 24 hours and check every 3 minutes.
func (s ServiceBrokerDNSProvider) Timeout() (timeout, interval time.Duration) {
	return cfdomainbroker.DomainCreateTimeout, cfdomainbroker.DomainCreateCheck
}

// Wrapper for storing the DNS instructions.
type DomainMessenger struct {
	gorm.Model
	Domain  string
	Token   string
	KeyAuth string

	// How long is left until the domain service needs to be authenticated.
	ValidUntil time.Time
}

// String wraps a tabwriter into a string format for ease of use.
func (d DomainMessenger) String() string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 4, 2, '\t', 0)
	fmt.Fprintf(w, "Domain\tToken\tKey Authentication\tValid Until\n")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.Domain, d.Token, d.KeyAuth, d.ValidUntil.Format(time.RFC850))
	w.Flush()
	return string(buf.String())
}

// Present our credentials to the handler.
func (s ServiceBrokerDNSProvider) Present(domain, token, keyAuth string) error {
	authRecord := &DomainMessenger{
		Domain:     domain,
		Token:      token,
		KeyAuth:    keyAuth,
		ValidUntil: time.Now().Add(cfdomainbroker.DomainCreateTimeout),
	}
	s.logger.Debug("present-dns-challenge", lager.Data{
		"record": *(authRecord),
	})
	if err := s.db.Create(authRecord).Error; err != nil {
		s.logger.Error("db-store-dns-challenge", err, lager.Data{
			"record": *(authRecord),
		})
		return err
	}
	return nil
}

// todo (mxplusb): this should remove old/solved records.
func (s ServiceBrokerDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}
