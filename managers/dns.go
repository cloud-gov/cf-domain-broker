package managers

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/jinzhu/gorm"
)

const (
	msg = `In order to properly use this, you need to first ensure the desired domain name you want is created with the value of the 'cname' field so the domain is resolvable. Then, create the TXT record using the attached values. You can set whatever TTL value you want on the TXT record, but our recommendation is better. Once you've doneIf the TXT record isn't set to the below value before the validity expires, you will need to create a new instance of this service.`
)

type ServiceBrokerDnsProviderSettings struct {
	Db         *gorm.DB
	Logger     lager.Logger
	InstanceId string
	LogLevel   int
	// This should be the hostname of the ELB.
	ELBTarget string
}

// Internal DNS provider.
type ServiceBrokerDNSProvider struct {
	// db access
	db         *gorm.DB
	logger     lager.Logger
	instanceId string
	settings   *ServiceBrokerDnsProviderSettings
	elbTarget  string
}

func NewServiceBrokerDNSProvider(settings *ServiceBrokerDnsProviderSettings) *ServiceBrokerDNSProvider {
	return &ServiceBrokerDNSProvider{
		db:         settings.Db,
		logger:     settings.Logger.Session("service-broker-dns-provider", lager.Data{"instance_id": settings.InstanceId}),
		instanceId: settings.InstanceId,
		settings:   settings,
		elbTarget:  settings.ELBTarget,
	}
}

// Set our default timeout to be 24 hours and check every 3 minutes.
func (s ServiceBrokerDNSProvider) Timeout() (timeout, interval time.Duration) {
	return cfdomainbroker.DomainCreateTimeout, cfdomainbroker.DomainCreateCheck
}

// Wrapper for storing the DNS instructions.
type DomainMessenger struct {
	gorm.Model `json:"-"`
	Domain     string `json:"domain"`
	TxtRecord  string `json:"txt_record"`
	Token      string `json:"-"`
	KeyAuth    string `json:"txt_value"`
	Message    string `json:"message"`
	InstanceId string `json:"-"`
	TTL        int    `json:"ttl"`
	CNAME      string `json:"cname"`

	// How long is left until the domain service needs to be authenticated.
	ValidUntil time.Time `json:"valid_until"`
}

// Present our credentials to the handler.
func (s ServiceBrokerDNSProvider) Present(domain, token, keyAuth string) error {

	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	value := base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])

	authRecord := DomainMessenger{
		Domain:     domain,
		Token:      token,
		KeyAuth:    value,
		Message:    msg,
		TTL:        60,
		TxtRecord:  fmt.Sprintf("_acme-challenge.%s", domain),
		InstanceId: s.instanceId,
		CNAME:      s.elbTarget,
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
