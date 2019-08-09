package le_providers

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"text/tabwriter"
	"time"

	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
)

// Internal DNS provider.
type ServiceBrokerDNSProvider struct {
	// Handler for sharing the DNS resolver records.
	Handler chan DomainMessenger

	// Db access
	Db *gorm.DB
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
	b := bufio.NewWriter(&buf)
	w := tabwriter.NewWriter(b, 0, 4, 2, '\t', 0)
	fmt.Fprintf(w, "Domain\tToken\tKey Authentication\tValid Until\n")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.Domain, d.Token, d.KeyAuth, d.ValidUntil.Format(time.RFC850))
	w.Flush()

	r := bufio.NewReader(&buf)
	bb, err := ioutil.ReadAll(r)
	if err != nil {
		// todo (mxplusb): this shouldn't panic but still needs to be fixed at some point.
		panic(err)
	}
	return string(bb)
}

// Present our credentials to the handler.
func (s ServiceBrokerDNSProvider) Present(domain, token, keyAuth string) error {
	if err := s.Db.Create(&DomainMessenger{
		Domain:     domain,
		Token:      token,
		KeyAuth:    keyAuth,
		ValidUntil: time.Now().Add(cfdomainbroker.DomainCreateTimeout),
	}).Error; err != nil {
		return err
	}
	return nil
}

// todo (mxplusb): this should remove old/solved records.
func (s ServiceBrokerDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}
