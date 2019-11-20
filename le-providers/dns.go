package le_providers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"text/tabwriter"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
)

type ServiceBrokerDnsProviderSettings struct {
	Db         *gorm.DB
	Logger     lager.Logger
	InstanceId string
	LogLevel   int
}

// Internal DNS provider.
type ServiceBrokerDNSProvider struct {
	// db access
	db         *gorm.DB
	logger     lager.Logger
	instanceId string
	settings   *ServiceBrokerDnsProviderSettings
}

func NewServiceBrokerDNSProvider(settings *ServiceBrokerDnsProviderSettings) *ServiceBrokerDNSProvider {
	return &ServiceBrokerDNSProvider{
		db:         settings.Db,
		logger:     settings.Logger.Session("service-broker-dns-provider", lager.Data{"instance_id": settings.InstanceId}),
		instanceId: settings.InstanceId,
		settings:   settings,
	}
}

// Set our default timeout to be 24 hours and check every 3 minutes.
func (s ServiceBrokerDNSProvider) Timeout() (timeout, interval time.Duration) {
	return cfdomainbroker.DomainCreateTimeout, cfdomainbroker.DomainCreateCheck
}

// Wrapper for storing the DNS instructions.
type DomainMessenger struct {
	gorm.Model
	Domain     string
	Token      string
	KeyAuth    string
	InstanceId string

	// How long is left until the domain service needs to be authenticated.
	ValidUntil time.Time
}

// String wraps a tabwriter into a string format for ease of use.
// todo (mxplusb): figure out how to tell customers to set a short TTL on the TXT record.
func (d DomainMessenger) String() string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 4, 2, '\t', 0)
	if _, err := fmt.Fprintf(w, "TXT Record:\tValue:\tValid Until:\n"); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}
	if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", d.Domain, d.KeyAuth, d.ValidUntil.Format(time.RFC850)); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}
	if err := w.Flush(); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}
	return buf.String()
}

// Present our credentials to the handler.
func (s ServiceBrokerDNSProvider) Present(domain, token, keyAuth string) error {

	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	value := base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])

	authRecord := DomainMessenger{
		Domain:     domain,
		Token:      token,
		KeyAuth:    value,
		InstanceId: s.instanceId,
		ValidUntil: time.Now().Add(cfdomainbroker.DomainCreateTimeout),
	}
	s.logger.Debug("present-dns-challenge", lager.Data{
		"record": authRecord,
	})

	if s.settings.LogLevel == 1 {
		if err := s.db.Debug().Create(&authRecord).Error; err != nil {
			s.logger.Error("db-debug-store-dns-challenge", err, lager.Data{
				"record": authRecord,
			})
			return err
		}
	} else {
		if err := s.db.Create(&authRecord).Error; err != nil {
			s.logger.Error("db-store-dns-challenge", err, lager.Data{
				"record": authRecord,
			})
			return err
		}
	}
	return nil
}

// todo (mxplusb): this should remove old/solved records.
func (s ServiceBrokerDNSProvider) CleanUp(domain, token, keyAuth string) error {
	authRecord := DomainMessenger{
		InstanceId: s.instanceId,
	}
	if err := s.db.Delete(&authRecord).Error; err != nil {
		s.logger.Error("db-delete-dns-challenge-failure", err)
		return err
	}
	return nil
}
