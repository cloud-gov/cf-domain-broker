package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/interfaces"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/cloudfoundry-community/go-cfclient"

	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
)

type DomainBroker struct {
	Manager interfaces.RouteManager
	Cf      *cfclient.Client
	logger  lager.Logger
}

// Get the list of plans and service the broker has to offer.
func (d *DomainBroker) Services(ctx context.Context) ([]domain.Service, error) {

	logSession := d.logger.Session("get-services")
	logSession.Info("get-services")

	return []domain.Service{
		{
			ID:          cfdomainbroker.DomainServiceId,
			Name:        cfdomainbroker.DomainServiceName,
			Description: cfdomainbroker.DomainServiceDescription,
			Bindable:    true,
			Plans:       d.servicePlans(),
			Metadata: &domain.ServiceMetadata{
				DisplayName:         cfdomainbroker.DomainServiceMetadataDisplayName,
				LongDescription:     cfdomainbroker.DomainServiceMetadataLongDescription,
				DocumentationUrl:    cfdomainbroker.DomainServiceMetadataDocumentationUrl,
				SupportUrl:          cfdomainbroker.DomainServiceMetadataSupportUrl,
				ImageUrl:            cfdomainbroker.DomainServiceMetadataImageUrl,
				ProviderDisplayName: cfdomainbroker.DomainServiceMetadataProviderDisplayName,
			},
			Tags: []string{
				"cloud.gov",
				"cdn",
				"custom",
				"domains",
				"aws",
			},
		},
	}, nil
}

func (d *DomainBroker) servicePlans() []domain.ServicePlan {
	plans := make([]domain.ServicePlan, 0)

	plans = append(plans, domain.ServicePlan{
		ID:          cfdomainbroker.CDNPlanId,
		Name:        cfdomainbroker.CDNPlanName,
		Description: "This plan provides a custom domain name with CDN services through AWS Cloudfront.",
		Metadata: &domain.ServicePlanMetadata{
			// todo (mxplusb): make sure these cover the points we care about.
			Bullets: []string{
				"Each deployment will create an AWS Cloudfront instance on your behalf",
				"Creates and maintains a Let's Encrypt SSL certificate for your custom domain.",
				"Check your ATO to ensure you can use AWS Cloudfront",
			},
			DisplayName: "Custom-Domain-With-CDN",
		},
	})

	plans = append(plans, domain.ServicePlan{
		ID:          cfdomainbroker.DomainPlanId,
		Name:        cfdomainbroker.DomainPlanName,
		Description: "This plan provides a custom domain name for your application.",
		Metadata: &domain.ServicePlanMetadata{
			// todo (mxplusb): make sure these cover the points we care about.
			Bullets: []string{
				"Creates and maintains a Let's Encrypt SSL certificate for your custom domain.",
				"Does not create a CDN service for you.",
			},
			DisplayName: "Custom-Domain",
		},
	})

	return plans
}

func (d *DomainBroker) Provision(ctx context.Context, instanceID string, details domain.ProvisionDetails, asyncAllowed bool) (domain.ProvisionedServiceSpec, error) {
	spec := domain.ProvisionedServiceSpec{}
	spec.IsAsync = asyncAllowed

	// generate a new session.
	lsession := d.logger.Session("provision", lager.Data{
		"instance-id":   instanceID,
		"async-request": asyncAllowed,
	})

	if !asyncAllowed {
		lsession.Error("async-required", apiresponses.ErrAsyncRequired)
		return spec, apiresponses.ErrAsyncRequired
	}

	// check to make sure it's a supported plan.
	planId := ""
	for _, plan := range d.servicePlans() {
		if plan.ID == details.PlanID {
			planId = plan.ID
		}
	}

	// if not, throw.
	if planId == "" {
		err := errors.New("plan_id not recognized")
		lsession.Error("plan-not-found", err)
		return spec, err
	}

	// figure out the payload and assign.
	var domOpts types.DomainPlanOptions
	var cdnOpts types.CdnPlanOptions
	var domainstring types.DomainString

	switch planId {
	case cfdomainbroker.CDNPlanId:
		if err := json.Unmarshal(details.GetRawParameters(), &cdnOpts); err != nil {
			lsession.Error("unmarshal-cdn-opts", err)
			return spec, err
		}
	case cfdomainbroker.DomainPlanId:
		if err := json.Unmarshal(details.GetRawParameters(), &domainstring); err != nil {
			lsession.Error("unmarshal-domain-opts", err)
			return spec, err
		}
		var domainModels []models.Domain
		for _, domain := range domainstring.Domains {
			var domainModel models.Domain
			domainModel.Value = domain
			domainModels = append(domainModels, domainModel)
		}
		if len(domainModels) > 0 {
			domOpts.Domains = domainModels
		}
	}
	lsession.Info("creating new service instance.", lager.Data{
		"plan-id": planId,
	})

	// check for duplicates.
	_, err := d.Manager.Get(instanceID)
	if err == nil {
		lsession.Error("duplicate-instance", err)
		return spec, apiresponses.ErrInstanceAlreadyExists
	}

	tags := map[string]string{
		"Organization": details.OrganizationGUID,
		"Space":        details.SpaceGUID,
		"Service":      details.ServiceID,
		"Plan":         details.PlanID,
	}

	_, err = d.Manager.Create(instanceID, domOpts, cdnOpts, tags)
	if err != nil {
		lsession.Error("create-instance", err, lager.Data{
			"tags": tags,
		})
		return spec, err
	}

	return domain.ProvisionedServiceSpec{IsAsync: true}, nil
}

func (d *DomainBroker) Deprovision(ctx context.Context, instanceID string, details domain.DeprovisionDetails, asyncAllowed bool) (domain.DeprovisionServiceSpec, error) {
	route, err := d.Manager.Get(instanceID)
	if err != nil {
		return domain.DeprovisionServiceSpec{}, err
	}

	err = d.Manager.Disable(route)
	if err != nil {
		return domain.DeprovisionServiceSpec{}, nil
	}

	return domain.DeprovisionServiceSpec{IsAsync: true}, nil

}

func (d *DomainBroker) GetInstance(ctx context.Context, instanceID string) (domain.GetInstanceDetailsSpec, error) {
	return domain.GetInstanceDetailsSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

//finish
func (d *DomainBroker) Update(ctx context.Context, instanceID string, details domain.UpdateDetails, asyncAllowed bool) (domain.UpdateServiceSpec, error) {

	options, err := d.parseUpdateDetails(details)
	if err != nil {
		return domain.UpdateServiceSpec{}, err
	}

	emptyCDN := types.CdnPlanOptions{}
	err = d.Manager.Update(instanceID, options, emptyCDN)
	if err != nil {
		return domain.UpdateServiceSpec{}, err
	}

	return domain.UpdateServiceSpec{}, nil
}

func (d *DomainBroker) LastOperation(ctx context.Context, instanceID string, details domain.PollDetails) (domain.LastOperation, error) {
	lastOp := domain.LastOperation{}

	lsession := d.logger.Session("last-operation", lager.Data{
		"instance-id": instanceID,
	})

	r, err := d.Manager.Get(instanceID)
	if err != nil {
		lsession.Error("route-manager-get", err)
		return lastOp, err
	}

	err = d.Manager.Poll(r)
	if err != nil {
		d.logger.Error("error-during-poll", err)
		return domain.LastOperation{}, apiresponses.NewFailureResponse(err, 409, "cannot reconcile queried state with desired state")
	}

	switch r.State {
	case cfdomainbroker.Provisioning:
		instructions, err := d.Manager.GetDNSInstructions(r)
		if err != nil {
			return domain.LastOperation{}, err
		}
		return domain.LastOperation{
			State:       domain.InProgress,
			Description: instructions.String(),
		}, nil
	case cfdomainbroker.Deprovisioning:
		return domain.LastOperation{
			State:       domain.InProgress,
			Description: fmt.Sprintf("deprovisioning in progress"),
		}, nil
	default:
		return domain.LastOperation{
			State:       domain.Succeeded,
			Description: fmt.Sprintf("provisioned"),
		}, nil
	}
	return lastOp, nil
}

func (*DomainBroker) Bind(ctx context.Context, instanceID, bindingID string, details domain.BindDetails, asyncAllowed bool) (domain.Binding, error) {
	return domain.Binding{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func (*DomainBroker) Unbind(ctx context.Context, instanceID, bindingID string, details domain.UnbindDetails, asyncAllowed bool) (domain.UnbindSpec, error) {
	return domain.UnbindSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func (*DomainBroker) GetBinding(ctx context.Context, instanceID, bindingID string) (domain.GetBindingSpec, error) {
	return domain.GetBindingSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func (*DomainBroker) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details domain.PollDetails) (domain.LastOperation, error) {
	return domain.LastOperation{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func NewDomainBroker(mgr interfaces.RouteManager, logger lager.Logger) *DomainBroker {
	return &DomainBroker{
		Manager: mgr,
		logger:  logger.Session("route-Manager"),
	}
}

func (d *DomainBroker) createDomainBrokerOptions(details []byte) (options types.DomainPlanOptions, err error) {
	if len(details) == 0 {
		err = errors.New("must be invoked with configurations parameters")
		return
	}

	options = types.DomainPlanOptions{}
	err = json.Unmarshal(details, &options)
	if err != nil {
		return
	}
	return
}

func (d *DomainBroker) parseUpdateDetails(details domain.UpdateDetails) (options types.DomainPlanOptions, err error) {
	options, err = d.createDomainBrokerOptions(details.GetRawParameters())
	if err != nil {
		return
	}

	if len(options.Domains) == 0 {
		err = errors.New("must pass non-empty `domaions`")
		return
	}

	var domains []string
	for _, domain := range options.Domains {
		domains = append(domains, domain.Value)
	}

	err = d.checkDomain(domains, details.PreviousValues.OrgID)
	return
}

func (d *DomainBroker) checkDomain(domains []string, orgGUID string) error {
	var errorList []string
	orgName := "<organization>"
	for _, domain := range domains {
		if _, err := d.Cf.GetDomainByName(domain); err != nil {
			d.logger.Error("Error checking domain", err, lager.Data{
				"domain":  domain,
				"orgGUID": orgGUID,
			})
			if orgName == "<organization>" {
				org, err := d.Cf.GetOrgByGuid(orgGUID)
				if err == nil {
					orgName = org.Name
				}
			}
			errorList = append(errorList, fmt.Sprintf("`cf create-domain %s %s", orgName, domain))
		}
	}

	if len(errorList) > 0 {
		if len(errorList) > 1 {
			return fmt.Errorf("Multiple domains do not exist; create them with:\n%s", strings.Join(errorList, "\n"))
		}
		return fmt.Errorf("Domain does not exist; create it with %s", errorList[0])
	}
	return nil
}
