package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"code.cloudfoundry.org/lager"
	"github.com/pivotal-cf/brokerapi"

	"github.com/18F/cf-domain-broker-alb/cf"
	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/18F/cf-domain-broker-alb/models"
)

type Options struct {
	Domains []string `json:"domains"`
}

type CdnServiceBroker struct {
	manager  models.RouteManagerIface
	cfclient cf.Client
	settings config.Settings
	logger   lager.Logger
}

func New(
	manager models.RouteManagerIface,
	cfclient cf.Client,
	settings config.Settings,
	logger lager.Logger,
) *CdnServiceBroker {
	return &CdnServiceBroker{
		manager:  manager,
		cfclient: cfclient,
		settings: settings,
		logger:   logger,
	}
}

var (
	MAX_HEADER_COUNT = 10
)

func (*CdnServiceBroker) Services(context context.Context) ([]brokerapi.Service, error) {
	var service brokerapi.Service
	buf, err := ioutil.ReadFile("./catalog.json")
	if err != nil {
		return []brokerapi.Service{}, err
	}
	err = json.Unmarshal(buf, &service)
	if err != nil {
		return []brokerapi.Service{}, err
	}
	return []brokerapi.Service{service}, nil
}

func (b *CdnServiceBroker) Provision(
	context context.Context,
	instanceID string,
	details brokerapi.ProvisionDetails,
	asyncAllowed bool,
) (brokerapi.ProvisionedServiceSpec, error) {
	spec := brokerapi.ProvisionedServiceSpec{}

	if !asyncAllowed {
		return spec, brokerapi.ErrAsyncRequired
	}

	options, err := b.parseProvisionDetails(details)
	if err != nil {
		return spec, err
	}

	_, err = b.manager.Get(instanceID)
	if err == nil {
		return spec, brokerapi.ErrInstanceAlreadyExists
	}

	_, err = b.manager.Create(instanceID, options.Domains)
	if err != nil {
		return spec, err
	}

	return brokerapi.ProvisionedServiceSpec{IsAsync: true}, nil
}

func (b *CdnServiceBroker) LastOperation(
	context context.Context,
	instanceID, operationData string,
) (brokerapi.LastOperation, error) {
	route, err := b.manager.Get(instanceID)
	if err != nil {
		return brokerapi.LastOperation{
			State:       brokerapi.Failed,
			Description: "Service instance not found",
		}, nil
	}

	if err := b.manager.Poll(route); err != nil {
		b.logger.Error("Error during update", err, lager.Data{
			"domains": route.Domains,
			"state":   route.State,
		})
	}

	switch route.State {
	case models.Provisioning:
		description, err := b.manager.GetDNSInstructions(route)
		if err != nil {
			return brokerapi.LastOperation{}, err
		}
		return brokerapi.LastOperation{
			State:       brokerapi.InProgress,
			Description: description,
		}, nil
	default:
		return brokerapi.LastOperation{
			State: brokerapi.Succeeded,
			Description: fmt.Sprintf(
				"Service instance provisioned; CDN domain %s",
				strings.Join(route.Domains, ", "),
			),
		}, nil
	}
}

func (b *CdnServiceBroker) Deprovision(
	context context.Context,
	instanceID string,
	details brokerapi.DeprovisionDetails,
	asyncAllowed bool,
) (brokerapi.DeprovisionServiceSpec, error) {
	err := b.manager.Destroy(instanceID)
	if err != nil {
		return brokerapi.DeprovisionServiceSpec{}, err
	}

	return brokerapi.DeprovisionServiceSpec{IsAsync: false}, nil
}

func (b *CdnServiceBroker) Bind(
	context context.Context,
	instanceID, bindingID string,
	details brokerapi.BindDetails,
) (brokerapi.Binding, error) {
	return brokerapi.Binding{}, errors.New("service does not support bind")
}

func (b *CdnServiceBroker) Unbind(
	context context.Context,
	instanceID, bindingID string,
	details brokerapi.UnbindDetails,
) error {
	return errors.New("service does not support bind")
}

func (b *CdnServiceBroker) Update(
	context context.Context,
	instanceID string,
	details brokerapi.UpdateDetails,
	asyncAllowed bool,
) (brokerapi.UpdateServiceSpec, error) {
	if !asyncAllowed {
		return brokerapi.UpdateServiceSpec{}, brokerapi.ErrAsyncRequired
	}

	options, err := b.parseUpdateDetails(details)
	if err != nil {
		return brokerapi.UpdateServiceSpec{}, err
	}

	err = b.manager.Update(instanceID, options.Domains)
	if err != nil {
		return brokerapi.UpdateServiceSpec{}, err
	}

	return brokerapi.UpdateServiceSpec{IsAsync: true}, nil
}

// createBrokerOptions will attempt to take raw json and convert it into the "Options" struct.
func (b *CdnServiceBroker) createBrokerOptions(details []byte) (options Options, err error) {
	if len(details) == 0 {
		err = errors.New("must be invoked with configuration parameters")
		return
	}
	options = Options{}
	err = json.Unmarshal(details, &options)
	if err != nil {
		return
	}
	return
}

// parseProvisionDetails will attempt to parse the update details and then verify that BOTH least "domain" and "origin"
// are provided.
func (b *CdnServiceBroker) parseProvisionDetails(details brokerapi.ProvisionDetails) (options Options, err error) {
	options, err = b.createBrokerOptions(details.RawParameters)
	if err != nil {
		return
	}
	if len(options.Domains) == 0 {
		err = errors.New("must pass non-empty `domains`")
		return
	}
	return
}

// parseUpdateDetails will attempt to parse the update details and then verify that at least "domain" or "origin"
// are provided.
func (b *CdnServiceBroker) parseUpdateDetails(details brokerapi.UpdateDetails) (options Options, err error) {
	options, err = b.createBrokerOptions(details.RawParameters)
	if err != nil {
		return
	}
	if len(options.Domains) == 0 {
		err = errors.New("must pass non-empty `domains`")
		return
	}
	err = b.checkDomain(options.Domains, details.PreviousValues.OrgID)
	if err != nil {
		return
	}
	return
}

func (b *CdnServiceBroker) checkDomain(domains []string, orgGUID string) error {
	var errorlist []string
	orgName := "<organization>"

	for _, domain := range domains {
		if _, err := b.cfclient.GetDomainByName(domain); err != nil {
			b.logger.Error("Error checking domain", err, lager.Data{
				"domain":  domain,
				"orgGUID": orgGUID,
			})
			if orgName == "<organization>" {
				org, err := b.cfclient.GetOrgByGuid(orgGUID)
				if err == nil {
					orgName = org.Name
				}
			}
			errorlist = append(errorlist, fmt.Sprintf("`cf create-domain %s %s`", orgName, domain))
		}
	}

	if len(errorlist) > 0 {
		if len(errorlist) > 1 {
			return fmt.Errorf("Multiple domains do not exist; create them with:\n%s", strings.Join(errorlist, "\n"))
		}
		return fmt.Errorf("Domain does not exist; create it with %s", errorlist[0])
	}

	return nil
}
