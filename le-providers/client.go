package le_providers

import (
	"net/http"

	"code.cloudfoundry.org/lager"
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

	logger lager.Logger
}

// NewAcmeClient generates a new client with the target config.
func NewAcmeClient(client *http.Client, resolvers map[string]string, config *lego.Config, provider challenge.Provider, logger lager.Logger) (*AcmeClient, error) {
	a := &AcmeClient{
		Resolvers:  resolvers,
		AcmeConfig:config,
		logger: logger.Session("acme-client", lager.Data{
			"resolvers": resolvers,
		}),
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
	for k, _ := range resolvers {
		nameservers = append(nameservers, resolvers[k])
	}
	a.logger.Debug("using-nameservers", lager.Data{
		"nameservers": nameservers,
	})



	if err = a.Client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers(nameservers), dns01.WrapPreCheck(a.preCheck)); err != nil {
		a.logger.Error("acme-client-challenge-set-dns01-provider", err)
		return &AcmeClient{}, err
	}

	a.logger.Info("instantiated-new-acme-client")

	return a, nil
}

func (a *AcmeClient) preCheck(domain, fqdn, value string, check dns01.PreCheckFunc) (b bool, e error) {
	lsession := a.logger.Session("dns-pre-check")

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

	// true == 1 and false == 0 as helper functions because go doesn't support bitwise xor on booleans.
	// we need these so we can return `true | false`, depending on whichever resolves first.
	itobfn := func(b bool) int {
		if b {
			return 1
		} else {
			return 0
		}
	}
	btoifn := func(i int) bool {
		if i == 0 {
			return false
		} else {
			return true
		}
	}

	lsession.Debug("checking-resolver-state")

	var state = false

	// for every resolver, if any resolver returns positive, we can resolve this record.
	for idx := range resolverStates {
		if btoifn(itobfn(resolverStates[idx]) | itobfn(state)) {
			state = true
		}
	}
	lsession.Debug("resolver-state-check-complete", lager.Data{
		"global-resolver-state": state,
	})

	// return whichever one resolves.
	return state, nil
}
