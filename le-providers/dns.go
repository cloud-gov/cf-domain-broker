package le_providers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
)

const (
	msg = `Please add the text record to your DNS server. If the TXT record isn't set to the below value before the validity expires, you will need to create a new instance of this service.`
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
	Message    string
	InstanceId string

	// How long is left until the domain service needs to be authenticated.
	ValidUntil time.Time
}

// String wraps a tabwriter into a string format for ease of use.
// todo (mxplusb): figure out how to tell customers to set a short TTL on the TXT record.
func (d DomainMessenger) String() string {
	var buf []byte
	w := bytes.NewBuffer(buf)

	updatedRecord := fmt.Sprintf("_acme-challenge.%s", d.Domain)

	if _, err := fmt.Fprintf(w, "\nTXT Record:\t\t\t%s\n", updatedRecord); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}

	if _, err := fmt.Fprintf(w, "TXT Record Value:\t%s\n", d.KeyAuth); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}

	if _, err := fmt.Fprintf(w, "Valid Until:\t\t%s\n", d.ValidUntil.Format(time.RFC850)); err != nil {
		// todo (mxplusb): no panic
		panic(err)
	}

	return w.String()
}

// Present our credentials to the handler.
func (s ServiceBrokerDNSProvider) Present(domain, token, keyAuth string) error {

	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	value := base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])

	authRecord := DomainMessenger{
		Domain:     fmt.Sprintf("_acme-challenge.%s", domain),
		Token:      token,
		KeyAuth:    value,
		Message:    msg,
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
