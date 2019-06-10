package le_providers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	cf_domain_broker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
	"io/ioutil"
	"net"
	"text/tabwriter"
	"time"
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
	return cf_domain_broker.DomainCreateTimeout, cf_domain_broker.DomainCreateCheck
}

// Wrapper for storing the DNS instructions.
type DomainMessenger struct {
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
	if err := s.Db.Create(DomainMessenger{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
		ValidUntil: time.Now().Add(cf_domain_broker.DomainCreateTimeout),
	}).Error; err != nil {
		return err
	}
	return nil
}

func (s ServiceBrokerDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}

// Validate will validate an external DNS record against Google's and Cloudflare's public DNS records.
func Validate(fqdn, token string) (bool, error) {
	ctx := context.Background()

	// if either dns servers resolves the record, it will be set to true.
	var googleValidated = false
	var cloudflareValdiated = false

	// create a DNS resolver which pokes google's public DNS address.
	googleResolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	gval, err := googleResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false, err
	}
	for idx := range gval {
		if gval[idx] == token {
			googleValidated = true
		}
	}

	// create a DNS resolver which pokes cloudflare's public DNS address.
	cloudflareResolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	cval, err := cloudflareResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false, err
	}
	for idx := range gval {
		if cval[idx] == token {
			cloudflareValdiated = true
		}
	}

	// true == 1 and false == 0 as helper functions because go doesn't support bitwise xor on booleans.
	// we need these so we can return `true | false`, depending on whichever resolves first.
	ifn := func(b bool) int {
		if b {
			return 1
		} else {
			return 0
		}
	}
	bfn := func(i int) bool {
		if i == 0 {
			return false
		} else {
			return true
		}
	}

	// return whichever one resolves.
	return bfn(ifn(googleValidated) | ifn(cloudflareValdiated)), nil
}
