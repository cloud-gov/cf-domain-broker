package routes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	"code.cloudfoundry.org/lager"
	cf_domain_broker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/interfaces"
	le_providers "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi/domain"
)

type WorkerManagerSettings struct {
	AcmeHttpClient        *http.Client
	AcmeUrl               string
	AcmeEmail             string
	Db                    *gorm.DB
	IamSvc                iamiface.IAMAPI
	CloudFront            interfaces.CloudfrontDistributionIface
	ElbSvc                elbv2iface.ELBV2API
	PersistentDnsProvider bool
	DnsChallengeProvider  challenge.Provider
	Resolvers             map[string]string
	LogLevel              int
}

type WorkerManager struct {
	Settings                    *WorkerManagerSettings
	RequestRouter               chan interface{}
	provisionRequest            chan ProvisionRequest
	deprovisionRequest          chan DeprovisionRequest
	getInstanceRequest          chan GetInstanceRequest
	updateRequest               chan UpdateRequest
	lastOperationRequest        chan LastOperationRequest
	bindRequest                 chan BindRequest
	unbindRequest               chan UnbindRequest
	getBindingRequest           chan GetBindingRequest
	lastBindingOperationRequest chan LastBindingOperationRequest

	logger lager.Logger
}

func NewWorkerManager(logger lager.Logger, settings *WorkerManagerSettings) *WorkerManager {
	p := &WorkerManager{
		RequestRouter:               make(chan interface{}, 150),
		Settings:                    settings,
		logger:                      logger,
		provisionRequest:            make(chan ProvisionRequest, 150),
		deprovisionRequest:          make(chan DeprovisionRequest, 150),
		getInstanceRequest:          make(chan GetInstanceRequest, 150),
		updateRequest:               make(chan UpdateRequest, 150),
		lastOperationRequest:        make(chan LastOperationRequest, 150),
		bindRequest:                 make(chan BindRequest, 150),
		unbindRequest:               make(chan UnbindRequest, 150),
		getBindingRequest:           make(chan GetBindingRequest, 150),
		lastBindingOperationRequest: make(chan LastBindingOperationRequest, 150),
	}

	return p
}

func (p *WorkerManager) Run() {
	// start the background router.
	go func() {
		for {
			msg := <-p.RequestRouter
			switch msg.(type) {
			case ProvisionRequest:
				p.provisionRequest <- msg.(ProvisionRequest)
			}
		}
	}()

	// start the provisioning listener
	go p.RunProvisioner()
}

type ProvisionRequest struct {
	Context      context.Context
	InstanceId   string
	DomainOpts   types.DomainPlanOptions
	CdnOpts      types.CdnPlanOptions
	Tags         map[string]string
	LoadBalancer *elbv2.LoadBalancer
}

func (p *WorkerManager) RunProvisioner() {
	go func() {
		for {
			msg := <-p.provisionRequest
			go p.provision(msg)
		}
	}()
}

func (p *WorkerManager) provision(msg ProvisionRequest) {
	lsession := p.logger.Session("create-route", lager.Data{
		"instance-id": msg.InstanceId,
		"domains":     msg.DomainOpts.Domains,
	})

	defer func(lsession lager.Logger) {
		if r := recover(); r != nil {
			err := errors.New(fmt.Sprintln(r))
			lsession.Error("panic!", err)
		}
	}(lsession)

	// generate a new key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		lsession.Error("rsa-generate-key", err)
	}
	lsession.Debug("rsa-key-generated")

	// build the user with the new key, instantiate a client
	user := models.UserData{
		Email:      p.Settings.AcmeEmail,
		PublicKey:  key.Public(),
		PrivateKey: key,
	}

	conf := lego.NewConfig(&user)
	conf.CADirURL = p.Settings.AcmeUrl

	if p.Settings.AcmeHttpClient == nil {
		p.Settings.AcmeHttpClient = http.DefaultClient
	}

	// if we need to store the challenge for later upstream, create a new provider.
	if p.Settings.PersistentDnsProvider == true {
		p.Settings.DnsChallengeProvider = le_providers.NewServiceBrokerDNSProvider(p.Settings.Db, p.logger, msg.InstanceId)
	}

	acmeClient, err := le_providers.NewAcmeClient(p.Settings.AcmeHttpClient, p.Settings.Resolvers, conf, p.Settings.DnsChallengeProvider, p.logger, msg.InstanceId)
	if err != nil {
		// todo (mxplusb): figure out how to bubble this up
		lsession.Error("acme-new-client", err)
	}
	lsession.Debug("acme-client-instantiated")

	if len(msg.DomainOpts.Domains) > 0 {
		lsession.Debug("acme-dns-provider-assigned")
		// create the route struct and add the user reference.
		localDomainRoute := &models.DomainRoute{
			InstanceId:     msg.InstanceId,
			State:          cf_domain_broker.Provisioning,
			User:           user,
			DomainExternal: msg.DomainOpts.Domains,
		}

		// register our user resource.
		reg, err := acmeClient.Client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		user.Registration = reg
		lsession.Debug("acme-user-registered")

		// store the certificate and elb info the database.
		// check for debug.
		if p.Settings.LogLevel == 1 {
			if err := p.Settings.Db.Debug().Create(&localDomainRoute).Error; err != nil {
				// todo (mxplusb): figure out how to bubble this up
				lsession.Error("db-debug-save-route", err)
			}
		} else {
			if err := p.Settings.Db.Create(&localDomainRoute).Error; err != nil {
				// todo (mxplusb): figure out how to bubble this up
				lsession.Error("db-save-route", err)
			}
		}
		lsession.Info("db-route-saved")

		var domains []string
		for i := 0; i < len(msg.DomainOpts.Domains); i++ {
			domains = append(domains, msg.DomainOpts.Domains[i].Value)
		}

		// make the certificate request.
		request := certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		}

		// get the certificate.
		cert, err := acmeClient.Client.Certificate.Obtain(request)
		if err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("acme-certificate-obtain", err)
		}
		lsession.Info("certificate-obtained")

		localCert := models.Certificate{
			InstanceId: msg.InstanceId,
			Resource:   cert,
		}

		if p.Settings.LogLevel == 1 {
			if err := p.Settings.Db.Debug().Create(&localCert).Error; err != nil {
				// todo (mxplusb): figure out how to bubble this up
				lsession.Error("db-save-certificate", err)
			}
		} else {
			if err := p.Settings.Db.Create(&localCert).Error; err != nil {
				// todo (mxplusb): figure out how to bubble this up
				lsession.Error("db-save-certificate", err)
			}
		}
		lsession.Info("db-certificate-stored")

		// save the ELB arn.
		localDomainRoute.ELBArn = *msg.LoadBalancer.LoadBalancerArn

		// generate the necessary input.
		certUploadInput := &iam.UploadServerCertificateInput{}
		certUploadInput.SetCertificateBody(string(localCert.Resource.Certificate))
		certUploadInput.SetPrivateKey(string(localCert.Resource.PrivateKey))
		certUploadInput.SetServerCertificateName(fmt.Sprintf("cf-domain-%s", msg.InstanceId))

		// upload the certificate.
		certArn, err := p.Settings.IamSvc.UploadServerCertificate(certUploadInput)
		if err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("iam-upload-server-certificate", err)
		}
		lsession.Info("certificate-uploaded-to-iam")

		//save cert ARN
		localCert.ARN = *certArn.ServerCertificateMetadata.Arn

		// grab the listeners.
		listeners, err := p.Settings.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
			LoadBalancerArn: msg.LoadBalancer.LoadBalancerArn,
		})
		if err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("elbsvc-describe-listeners", err)
		}
		lsession.Debug("found-listeners", lager.Data{
			"listeners": listeners.Listeners,
		})

		// find our target listener.
		var targetListenArn *string
		for idx := range listeners.Listeners {
			if *listeners.Listeners[idx].Protocol == "HTTPS" {
				targetListenArn = listeners.Listeners[idx].ListenerArn
			}
		}

		// do a nil reference check and store the listener arn reference.
		if targetListenArn != nil {
			localDomainRoute.ListenerArn = *targetListenArn
		} else {
			err := errors.New("missing listener arn")
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("listener-arn-is-nil", err)
		}

		lsession.Debug("found-https-listener", lager.Data{
			"listener-arn": localDomainRoute.ListenerArn,
		})

		// upload the certificate to the listener.
		if _, err := p.Settings.ElbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
			ListenerArn: targetListenArn,
			Certificates: []*elbv2.Certificate{
				{
					CertificateArn: certArn.ServerCertificateMetadata.Arn,
				},
			},
		}); err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("elbsvc-add-listener-certificates", err)
		}
		lsession.Info("certificate-uploaded-to-elb")

		// since it's been uploaded to the elb, it's done.
		localDomainRoute.State = cf_domain_broker.Provisioned

		// store the certificate and elb info the database.
		if err := p.Settings.Db.Save(localDomainRoute).Error; err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("db-save-route", err)
		}

	} else if len(msg.CdnOpts.Domain) > 0 {
		// create the route struct and add the user reference.
		var domain models.Domain
		domain.Value = msg.CdnOpts.Domain
		var domains []models.Domain
		domains = append(domains, domain)

		localCDNRoute := &models.DomainRoute{
			InstanceId:     msg.InstanceId,
			State:          cf_domain_broker.Provisioning,
			User:           user,
			DomainExternal: domains,
			Origin:         msg.CdnOpts.Origin,
			Path:           msg.CdnOpts.Path,
			InsecureOrigin: msg.CdnOpts.InsecureOrigin,
		}

		dist, err := p.Settings.CloudFront.Create(msg.InstanceId, make([]string, 0), msg.CdnOpts.Origin, msg.CdnOpts.Path, msg.CdnOpts.InsecureOrigin, msg.CdnOpts.Headers, msg.CdnOpts.Cookies, msg.Tags)
		if err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("creating-cloudfront-instance", err)
		}

		localCDNRoute.DomainInternal = *dist.DomainName
		localCDNRoute.DistributionId = *dist.Id

		if err := p.Settings.Db.Create(localCDNRoute).Error; err != nil {
			// todo (mxplusb): figure out how to bubble this up
			lsession.Error("db-creating-route", err)
		}
	}
}

type DeprovisionRequest struct {
	Context    context.Context
	InstanceId string
}

type GetInstanceRequest struct {
	Context    context.Context
	InstanceId string
}

type UpdateRequest struct {
	Context    context.Context
	InstanceId string
}

type LastOperationRequest struct {
	Context    context.Context
	InstanceId string
	Details    domain.PollDetails
}

type LastOperationResponse struct {
	LastOperation domain.LastOperation
	Error         error
}

func (p *WorkerManager) LastOperation(resp <-chan LastOperationResponse) {
	panic("implement me")
}

type BindRequest struct {
	Context    context.Context
	InstanceId string
}

type UnbindRequest struct {
	Context    context.Context
	InstanceId string
}

type GetBindingRequest struct {
	Context    context.Context
	InstanceId string
}

type LastBindingOperationRequest struct {
	Context    context.Context
	InstanceId string
}

func (p WorkerManager) Services(ctx context.Context) ([]domain.Service, error) {
	panic("implement me")
}

func (p WorkerManager) Provision(ctx context.Context, instanceID string, details domain.ProvisionDetails, asyncAllowed bool) (domain.ProvisionedServiceSpec, error) {
	panic("implement me")
}

func (p WorkerManager) Deprovision(ctx context.Context, instanceID string, details domain.DeprovisionDetails, asyncAllowed bool) (domain.DeprovisionServiceSpec, error) {
	panic("implement me")
}

func (p WorkerManager) GetInstance(ctx context.Context, instanceID string) (domain.GetInstanceDetailsSpec, error) {
	panic("implement me")
}

func (p WorkerManager) Update(ctx context.Context, instanceID string, details domain.UpdateDetails, asyncAllowed bool) (domain.UpdateServiceSpec, error) {
	panic("implement me")
}

func (p WorkerManager) Bind(ctx context.Context, instanceID, bindingID string, details domain.BindDetails, asyncAllowed bool) (domain.Binding, error) {
	panic("implement me")
}

func (p WorkerManager) Unbind(ctx context.Context, instanceID, bindingID string, details domain.UnbindDetails, asyncAllowed bool) (domain.UnbindSpec, error) {
	panic("implement me")
}

func (p WorkerManager) GetBinding(ctx context.Context, instanceID, bindingID string) (domain.GetBindingSpec, error) {
	panic("implement me")
}

func (p WorkerManager) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details domain.PollDetails) (domain.LastOperation, error) {
	panic("implement me")
}
