package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/managers"
	"github.com/18f/cf-domain-broker/types"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
)

type DomainBrokerSettings struct {
	Logger             lager.Logger
	GlobalQueueManager *managers.GlobalQueueManager
}

type DomainBroker struct {
	logger             lager.Logger
	settings           *DomainBrokerSettings
	globalQueueManager *managers.GlobalQueueManager
}

func NewDomainBroker(settings *DomainBrokerSettings) *DomainBroker {
	db := &DomainBroker{
		settings:           settings,
		logger:             settings.Logger.Session("domain-broker"),
		globalQueueManager: settings.GlobalQueueManager,
	}
	return db
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

	//plans = append(plans, domain.ServicePlan{
	//	ID:          cfdomainbroker.CDNPlanId,
	//	Name:        cfdomainbroker.CDNPlanName,
	//	Description: "This plan provides a custom domain name with CDN services through AWS Cloudfront.",
	//	Metadata: &domain.ServicePlanMetadata{
	//		// todo (mxplusb): make sure these cover the points we care about.
	//		Bullets: []string{
	//			"Each deployment will create an AWS Cloudfront instance on your behalf",
	//			"Creates and maintains a Let's Encrypt SSL certificate for your custom domain.",
	//			"Check your ATO to ensure you can use AWS Cloudfront",
	//		},
	//		DisplayName: cfdomainbroker.CDNPlanName,
	//	},
	//})

	plans = append(plans, domain.ServicePlan{
		ID:          cfdomainbroker.DomainPlanId,
		Name:        cfdomainbroker.DomainPlanName,
		Description: "This plan provides a custom domain name for your application.",
		Metadata: &domain.ServicePlanMetadata{
			// todo (mxplusb): make sure these cover the points we care about.
			Bullets: []string{
				"Creates and maintains a Let's Encrypt TLS certificate for your custom domain.",
				"Does not create a CDN service for you.",
			},
			DisplayName: cfdomainbroker.DomainPlanName,
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
		var domainModels []types.Domain
		for _, domain := range domainstring.Domains {
			var domainModel types.Domain
			domainModel.Value = domain
			domainModels = append(domainModels, domainModel)
		}
		if len(domainModels) > 0 {
			domOpts.Domains = domainModels
		}
	}
	lsession.Info("creating-new-service-instance", lager.Data{
		"plan-id": planId,
	})

	// check for duplicates.
	getInstanceResponse := make(chan managers.GetInstanceResponse, 1)
	d.globalQueueManager.Queue <- managers.ManagerRequest{
		InstanceId: instanceID,
		Type:       managers.WorkerManagerType,
		Payload: managers.GetInstanceRequest{
			Context:    ctx,
			InstanceId: instanceID,
			Response:   getInstanceResponse,
		},
	}
	resp := <-getInstanceResponse

	// todo (mxplusb): check for existing domains that haven't been expired yet.
	if resp.Route.InstanceId == instanceID {
		lsession.Info("preexisting-instance")
		return spec, apiresponses.ErrInstanceAlreadyExists
	}

	// send the request
	d.globalQueueManager.Queue <- managers.ManagerRequest{
		InstanceId: instanceID,
		Type:       managers.WorkerManagerType,
		Payload: managers.ProvisionRequest{
			Context:    ctx,
			InstanceId: instanceID,
			DomainOpts: domOpts,
			CdnOpts:    cdnOpts,
			Tags: map[string]string{
				"Organization": details.OrganizationGUID,
				"Space":        details.SpaceGUID,
				"Service":      details.ServiceID,
				"Plan":         details.PlanID,
			},
		},
	}

	return domain.ProvisionedServiceSpec{IsAsync: true}, nil
}

func (d *DomainBroker) Deprovision(ctx context.Context, instanceID string, details domain.DeprovisionDetails, asyncAllowed bool) (domain.DeprovisionServiceSpec, error) {
	getInstanceResponsec := make(chan managers.GetInstanceResponse, 1)
	d.globalQueueManager.Queue <- managers.ManagerRequest{
		InstanceId: instanceID,
		Type:       managers.WorkerManagerType,
		Payload: managers.GetInstanceRequest{
			Context:    ctx,
			InstanceId: instanceID,
			Response:   getInstanceResponsec,
		},
	}

	getInstanceResponse := <-getInstanceResponsec
	if getInstanceResponse.Error != nil {
		return domain.DeprovisionServiceSpec{}, getInstanceResponse.Error
	}

	deprovisionResponsec := make(chan managers.DeprovisionResponse, 1)
	d.globalQueueManager.Queue <- managers.ManagerRequest{
		InstanceId: instanceID,
		Type:       managers.WorkerManagerType,
		Payload: managers.DeprovisionRequest{
			Context:      ctx,
			InstanceId:   instanceID,
			Details:      details,
			AsyncAllowed: asyncAllowed,
			Response:     deprovisionResponsec,
		},
	}

	return domain.DeprovisionServiceSpec{IsAsync: true}, nil
}

func (d *DomainBroker) GetInstance(ctx context.Context, instanceID string) (domain.GetInstanceDetailsSpec, error) {
	return domain.GetInstanceDetailsSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

// todo (mxplusb): reenable this when CDN support exists.
func (d *DomainBroker) Update(ctx context.Context, instanceID string, details domain.UpdateDetails, asyncAllowed bool) (domain.UpdateServiceSpec, error) {

	//options, err := d.parseUpdateDetails(details)
	//if err != nil {
	//	return domain.UpdateServiceSpec{}, err
	//}
	//
	//emptyCDN := types.CdnPlanOptions{}
	//err = d.Manager.Update(instanceID, options, emptyCDN)
	//if err != nil {
	//	return domain.UpdateServiceSpec{}, err
	//}
	//
	//return domain.UpdateServiceSpec{}, nil
	return domain.UpdateServiceSpec{}, apiresponses.NewFailureResponse(errors.New("this api is unsupported"), http.StatusUnsupportedMediaType, "unsupported request")
}

func (d *DomainBroker) LastOperation(ctx context.Context, instanceID string, details domain.PollDetails) (domain.LastOperation, error) {
	lastOpsRespc := make(chan managers.LastOperationResponse, 1)
	lastOpReq := managers.LastOperationRequest{
		Context:    ctx,
		InstanceId: instanceID,
		Details:    details,
		Response:   lastOpsRespc,
	}
	d.globalQueueManager.Queue <- managers.ManagerRequest{
		InstanceId: instanceID,
		Type:       managers.WorkerManagerType,
		Payload:    lastOpReq,
	}
	lastOpResp := <-lastOpsRespc

	if lastOpResp.Error != nil {
		return domain.LastOperation{}, lastOpResp.Error
	}
	return lastOpResp.LastOperation, nil
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

//func (d *DomainBroker) parseUpdateDetails(details domain.UpdateDetails) (options types.DomainPlanOptions, err error) {
//	options, err = d.createDomainBrokerOptions(details.GetRawParameters())
//	if err != nil {
//		return
//	}
//
//	if len(options.Domains) == 0 {
//		err = errors.New("must pass non-empty `domaions`")
//		return
//	}
//
//	var domains []string
//	for _, domain := range options.Domains {
//		domains = append(domains, domain.Value)
//	}
//
//	err = d.checkDomain(domains, details.PreviousValues.OrgID)
//	return
//}

//func (d *DomainBroker) checkDomain(domains []string, orgGUID string) error {
//	var errorList []string
//	orgName := "<organization>"
//	for _, domain := range domains {
//		if _, err := d.Cf.GetDomainByName(domain); err != nil {
//			d.logger.Error("Error checking domain", err, lager.Data{
//				"domain":  domain,
//				"orgGUID": orgGUID,
//			})
//			if orgName == "<organization>" {
//				org, err := d.Cf.GetOrgByGuid(orgGUID)
//				if err == nil {
//					orgName = org.Name
//				}
//			}
//			errorList = append(errorList, fmt.Sprintf("`cf create-domain %s %s", orgName, domain))
//		}
//	}
//
//	if len(errorList) > 0 {
//		if len(errorList) > 1 {
//			return fmt.Errorf("Multiple domains do not exist; create them with:\n%s", strings.Join(errorList, "\n"))
//		}
//		return fmt.Errorf("Domain does not exist; create it with %s", errorList[0])
//	}
//	return nil
//}
