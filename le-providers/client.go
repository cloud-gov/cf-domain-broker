package le_providers

import (
	"context"
	"net"
	"net/http"

	"code.cloudfoundry.org/lager"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/lego"
	"github.com/xenolf/lego/challenge"
)

// Implementation and helper struct for working with custom ACME resources.
type AcmeClient struct {
	Client      *lego.Client
	Resolvers   map[string]string
	DNSProvider challenge.Provider
	HttpClient  *http.Client

	logger lager.Logger
}

// NewAcmeClient generates a new client with the target config.
func NewAcmeClient(client *http.Client, resolvers map[string]string, config *lego.Config, provider challenge.Provider, logger lager.Logger) (*AcmeClient, error) {
	a := &AcmeClient{
		Resolvers:  resolvers,
		HttpClient: client,
		logger: logger.Session("acme-client", lager.Data{
			"resolvers": resolvers,
		}),
	}

	// if the pointer doesn't contain a nil reference, use the client provided.
	if client != nil {
		config.HTTPClient = client
	}

	a.logger.Debug("instantiating-new-acme-client")

	var err error
	a.Client, err = lego.NewClient(config)
	if err != nil {
		a.logger.Error("acme-client-new-client", err)
		return &AcmeClient{}, err
	}

	if err = a.Client.Challenge.SetDNS01Provider(provider, dns01.WrapPreCheck(a.preCheck)); err != nil {
		a.logger.Error("acme-client-challenge-set-dns01-provider", err)
		return &AcmeClient{}, err
	}

	a.logger.Info("instantiated-new-acme-client")

	return a, nil
}

func (a *AcmeClient) preCheck(domain, fqdn, value string, check dns01.PreCheckFunc) (b bool, e error) {
	lsession := a.logger.Session("dns-pre-check")
	ctx := context.Background()

	var state = false
	var resolverStates []bool
	for localProvider, localAddress := range a.Resolvers {
		llsession := lsession.Session("provider-check", lager.Data{
			"target": localProvider,
			"host":   localAddress,
		})
		llsession.Debug("building-resolver")

		// create a DNS resolver for the map item.
		localResolver := net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", localAddress)
			},
		}

		// look up the txt record.
		val, err := localResolver.LookupTXT(ctx, fqdn)
		if err != nil {
			llsession.Error("resolver-failure", err)
			return false, err
		}

		// if the txt record resolves as intended, mark this resolver as true.
		for idx := range val {
			if val[idx] == value {
				llsession.Debug("found-target-txt-record", lager.Data{
					"txt": val[idx],
				})
				resolverStates = append(resolverStates, true)
			}
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

	lsession.Debug("checking-resolver-state")
	// for every resolver, if any resolver returns positive, we can resolve this record.
	for idx := range resolverStates {
		if bfn(ifn(resolverStates[idx]) | ifn(state)) {
			state = true
		}
	}
	lsession.Debug("resolver-state-check-complete", lager.Data{
		"global-resolver-state": state,
	})

	// return whichever one resolves.
	return state, nil
}
