package le_providers

import (
	"fmt"
	"net/http"

	"code.cloudfoundry.org/lager"
	cf_domain_broker "github.com/18f/cf-domain-broker"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/miekg/dns"
)

// Implementation and helper struct for working with custom ACME resources.
type AcmeClient struct {
	Client      *lego.Client
	Resolvers   map[string]string
	DNSProvider challenge.Provider
	AcmeConfig  *lego.Config
	InstanceId  string

	goodResolution int
	logger         lager.Logger
}

// NewAcmeClient generates a new client with the target config.
func NewAcmeClient(client *http.Client, resolvers map[string]string, config *lego.Config, provider challenge.Provider, logger lager.Logger, instanceId string) (*AcmeClient, error) {
	a := &AcmeClient{
		Resolvers:  resolvers,
		AcmeConfig: config,
		logger: logger.Session("acme-client", lager.Data{
			"resolvers": resolvers,
		}),
		InstanceId: instanceId,
	}

	a.AcmeConfig.HTTPClient = client

	a.logger.Debug("instantiating-new-acme-client")

	var err error
	a.Client, err = lego.NewClient(config)
	if err != nil {
		a.logger.Error("acme-client-new-client", err)
		return &AcmeClient{}, err
	}

	// add the nameserver resolvers to the dns provider.
	var nameservers []string
	for k := range resolvers {
		nameservers = append(nameservers, resolvers[k])
	}
	a.logger.Debug("using-nameservers", lager.Data{
		"nameservers": nameservers,
	})

	// if the implementation is our custom variant, set a required field.
	switch v := provider.(type) {
	case ServiceBrokerDNSProvider:
		v.instanceId = instanceId
	default:
	}

	if err = a.Client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers(nameservers), dns01.WrapPreCheck(a.preCheck)); err != nil {
		a.logger.Error("acme-client-challenge-set-dns01-provider", err)
		return &AcmeClient{}, err
	}

	a.logger.Info("instantiated-new-acme-client")

	return a, nil
}

func (a *AcmeClient) preCheck(domain, fqdn, value string, check dns01.PreCheckFunc) (b bool, e error) {
	lsession := a.logger.Session("dns-pre-check", lager.Data{
		"domain": domain,
		"fqdn":   fqdn,
		"value":  value,
	})

	var resolverStates []bool
	for localProvider, localAddress := range a.Resolvers {
		llsession := lsession.Session("provider-check", lager.Data{
			"target": localProvider,
			"host":   localAddress,
			"record": fqdn,
		})
		llsession.Debug("building-resolver")

		dnsClient := dns.Client{}
		msg := &dns.Msg{}
		msg.SetQuestion(fqdn, dns.TypeTXT)

		reply, _, err := dnsClient.Exchange(msg, localAddress)
		if err != nil {
			llsession.Error("dns-exchange-error", err)
			return false, err
		}

		// nil check, skip if not resolving.
		if len(reply.Answer) == 0 {
			llsession.Debug("no-answer-from-dns")
			continue
		}

		if t, ok := reply.Answer[0].(*dns.TXT); ok {
			// if the txt record resolves as intended, mark this resolver as true.
			for idx := range t.Txt {
				if t.Txt[idx] == value {
					llsession.Debug("found-target-txt-record", lager.Data{
						"txt": t.Txt[idx],
					})
					resolverStates = append(resolverStates, true)
				}
			}
		}
	}

	lsession.Debug("checking-resolver-state")

	var goodResolvers int

	// loop to see how many resolvers are good.
	for idx := range resolverStates {
		if resolverStates[idx] {
			goodResolvers += 1
		}
	}

	lsession.Debug("resolver-state-check-complete", lager.Data{
		"global-resolver-state": fmt.Sprintf("%d/%d", goodResolvers, len(a.Resolvers)),
	})

	switch {
	case a.goodResolution == cf_domain_broker.GoodResolutionCount: // we've waited awhile and all the records are resolving multiple times, so things are good.
	lsession.Info("stable-dns-resolution")
		return true, nil
	case goodResolvers < len(a.Resolvers): // not everything is resolving properly.
	lsession.Info("not-all-resolvers-found-record")
		return false, nil
	case goodResolvers == len(a.Resolvers): // not waited long enough but resolution is good.
	lsession.Info("testing-dns-resolution-stability")
		a.goodResolution += 1
		return false, nil
	default: // required by law
		return false, nil
	}
}
