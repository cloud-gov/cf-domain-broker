package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
)

type DomainBroker struct {
	Manager *routes.RouteManager
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

	switch planId {
	case cfdomainbroker.CDNPlanId:
		if err := json.Unmarshal(details.GetRawParameters(), &cdnOpts); err != nil {
			lsession.Error("unmarshal-cdn-opts", err)
			return spec, err
		}
	case cfdomainbroker.DomainPlanId:
		if err := json.Unmarshal(details.GetRawParameters(), &domOpts); err != nil {
			lsession.Error("unmarshal-domain-opts", err)
			return spec, err
		}
	}
	lsession.Info("creating new service instance.", lager.Data{
		"plan-id": planId,
	})

	// check for duplicates.
	resp, err := d.Manager.Get(instanceID)
	if err != nil {
		lsession.Error("get-instance", err)
		// todo (mxplusb): make it not throw this error.
		return spec, apiresponses.NewFailureResponse(err, http.StatusInternalServerError, "route not found")
	}
	if resp.InstanceId == instanceID {
		lsession.Info("duplicate-instances")
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

func (*DomainBroker) Deprovision(ctx context.Context, instanceID string, details domain.DeprovisionDetails, asyncAllowed bool) (domain.DeprovisionServiceSpec, error) {
	panic("implement me")
}

func (*DomainBroker) GetInstance(ctx context.Context, instanceID string) (domain.GetInstanceDetailsSpec, error) {
	return domain.GetInstanceDetailsSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func (*DomainBroker) Update(ctx context.Context, instanceID string, details domain.UpdateDetails, asyncAllowed bool) (domain.UpdateServiceSpec, error) {
	panic("implement me")
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

	lastOp.Description = r.DNSChallenge.String()
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

func NewDomainBroker(mgr *routes.RouteManager, logger lager.Logger) *DomainBroker {
	return &DomainBroker{
		Manager: mgr,
		logger:  logger.Session("route-Manager"),
	}
}
