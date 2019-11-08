package routes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	leproviders "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
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
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
)

type WorkerManagerSettings struct {
	AutostartWorkerPool         bool
	AcmeHttpClient              *http.Client
	AcmeUrl                     string
	AcmeEmail                   string
	Db                          *gorm.DB
	IamSvc                      iamiface.IAMAPI
	CloudFront                  cloudfrontiface.CloudFrontAPI
	ElbSvc                      elbv2iface.ELBV2API
	ElbUpdateFrequencyInSeconds time.Duration
	PersistentDnsProvider       bool
	DnsChallengeProvider        challenge.Provider
	Resolvers                   map[string]string
	Logger                      lager.Logger
	LogLevel                    int
}

// The Worker Manager is designed to be a totally asynchronous, message-driven interface on behalf of the Service Broker
// API. It has two interface points: `RequestRouter` and `GetLastError()`. `RequestRouter` is designed to handle any
// type of incoming request. `GetLastError()` will return the most recent unseen error related to the service instance
// requested.
type WorkerManager struct {
	RequestRouter               chan interface{}
	settings                    *WorkerManagerSettings
	provisionRequest            chan ProvisionRequest
	deprovisionRequest          chan DeprovisionRequest
	getInstanceRequest          chan GetInstanceRequest
	updateRequest               chan UpdateRequest
	lastOperationRequest        chan LastOperationRequest
	bindRequest                 chan BindRequest
	unbindRequest               chan UnbindRequest
	getBindingRequest           chan GetBindingRequest
	lastBindingOperationRequest chan LastBindingOperationRequest
	dnsInstructionsRequest      chan DnsInstructionsRequest

	provisioningErrorMap   map[string]error
	deprovisioningErrorMap map[string]error
	elbs                   []*elb
	logger                 lager.Logger
	lock sync.RWMutex
}

type elb struct {
	lb              *elbv2.LoadBalancer
	certsOnListener int
}

func NewWorkerManager(settings *WorkerManagerSettings) *WorkerManager {
	p := &WorkerManager{
		RequestRouter:               make(chan interface{}, 150),
		settings:                    settings,
		logger:                      settings.Logger.Session("worker-manager"),
		provisioningErrorMap:        make(map[string]error),
		deprovisioningErrorMap:      make(map[string]error),
		provisionRequest:            make(chan ProvisionRequest, 150),
		deprovisionRequest:          make(chan DeprovisionRequest, 150),
		getInstanceRequest:          make(chan GetInstanceRequest, 150),
		updateRequest:               make(chan UpdateRequest, 150),
		lastOperationRequest:        make(chan LastOperationRequest, 150),
		bindRequest:                 make(chan BindRequest, 150),
		unbindRequest:               make(chan UnbindRequest, 150),
		getBindingRequest:           make(chan GetBindingRequest, 150),
		lastBindingOperationRequest: make(chan LastBindingOperationRequest, 150),
		dnsInstructionsRequest:      make(chan DnsInstructionsRequest, 150),
	}

	if p.settings.AutostartWorkerPool {
		p.Run()
	}

	return p
}

// Runs the worker pool. Can be automatically invoked via a setting with `NewWorkerManager`.
// todo (mxplusb): leverage the runners to enable and disable SB functionality.
// todo (mxplusb): figure out a `Stop()` story.
func (w *WorkerManager) Run() {
	// start the background router.
	go func() {
		for {
			msg := <-w.RequestRouter
			switch msg.(type) {
			case ProvisionRequest:
				w.provisionRequest <- msg.(ProvisionRequest)
			case GetInstanceRequest:
				w.getInstanceRequest <- msg.(GetInstanceRequest)
			case DnsInstructionsRequest:
				w.dnsInstructionsRequest <- msg.(DnsInstructionsRequest)
			case LastOperationRequest:
				w.lastOperationRequest <- msg.(LastOperationRequest)
			case DeprovisionRequest:
				w.deprovisionRequest <- msg.(DeprovisionRequest)
			}
		}
	}()

	// start our listeners/runners
	go w.elbPopulator()
	w.provisionRunner()
	w.getInstanceRunner()
	w.lastOperationRunner()
	w.dnsInstructionsRunner()
	w.deprovisionRunner()
}

func (w *WorkerManager) elbPopulator() {
	ticker := time.NewTicker(w.settings.ElbUpdateFrequencyInSeconds * time.Second)

	// background function to keep the internal elb certs on listener up to date.
	// runs every so often.
	for ; true; <-ticker.C {
		// get a list of elbs.
		resp, err := w.settings.ElbSvc.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{})
		if err != nil {
			w.logger.Error("describe-load-balancers", err)
		}
		for idx := range resp.LoadBalancers {
			// nil check because you have to every single time you do anything in aws...
			if resp.LoadBalancers[idx] != nil {
				lresp, err := w.settings.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
					LoadBalancerArn: resp.LoadBalancers[idx].LoadBalancerArn,
				})
				if err != nil {
					w.logger.Error("describe-elb-listeners", err, lager.Data{
						"elb-target-arn": resp.LoadBalancers[idx].LoadBalancerArn,
					})
				}

				var certsOnListener int
				for nidx := range lresp.Listeners {
					if lresp.Listeners[nidx] != nil {
						certsOnListener += len(lresp.Listeners[nidx].Certificates)
					}
				}

				w.lock.Lock()
				w.elbs = append(w.elbs, &elb{lb: resp.LoadBalancers[idx], certsOnListener: certsOnListener})
				w.lock.Unlock()
			}
		}
	}
}

type ProvisionRequest struct {
	Context    context.Context
	InstanceId string
	DomainOpts types.DomainPlanOptions
	CdnOpts    types.CdnPlanOptions
	Tags       map[string]string
}

func (w *WorkerManager) provisionRunner() {
	go func() {
		for {
			msg := <-w.provisionRequest
			go w.provision(msg)
		}
	}()
}

func (w *WorkerManager) provision(msg ProvisionRequest) {
	lsession := w.logger.Session("create-route", lager.Data{
		"instance-id": msg.InstanceId,
		"domains":     msg.DomainOpts.Domains,
	})

	// generate a new key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		lsession.Error("rsa-generate-key", err)
		w.provisioningErrorMap[msg.InstanceId] = err
		return
	}
	lsession.Debug("rsa-key-generated")

	// build the user with the new key, instantiate a client
	user := models.UserData{
		Email:      w.settings.AcmeEmail,
		PublicKey:  key.Public(),
		PrivateKey: key,
	}

	conf := lego.NewConfig(&user)
	conf.CADirURL = w.settings.AcmeUrl

	if w.settings.AcmeHttpClient == nil {
		w.settings.AcmeHttpClient = http.DefaultClient
	}

	// if we need to store the challenge for later upstream, create a new provider.
	if w.settings.PersistentDnsProvider == true {
		w.settings.DnsChallengeProvider = leproviders.NewServiceBrokerDNSProvider(w.settings.Db, w.logger, msg.InstanceId)
	}

	acmeClient, err := leproviders.NewAcmeClient(w.settings.AcmeHttpClient, w.settings.Resolvers, conf, w.settings.DnsChallengeProvider, w.logger, msg.InstanceId)
	if err != nil {
		lsession.Error("acme-new-client", err)
		w.provisioningErrorMap[msg.InstanceId] = err
		return
	}
	lsession.Debug("acme-client-instantiated")

	// find the least assigned ELB to assign the route to.
	var targetElb *elbv2.LoadBalancer
	leastAssigned := 0
	for idx := range w.elbs {
		if w.elbs[idx].certsOnListener >= leastAssigned {
			targetElb = w.elbs[idx].lb
			leastAssigned = w.elbs[idx].certsOnListener
		}
	}

	if targetElb == nil {
		lsession.Error("desired-lb-nil-reference", errors.New("nil pointer dereference"))
		w.provisioningErrorMap[msg.InstanceId] = err
		return
	}

	lsession.Info("least-assigned-found", lager.Data{
		"elb-target": &targetElb.LoadBalancerArn,
	})

	if len(msg.DomainOpts.Domains) > 0 {
		lsession.Debug("acme-dns-provider-assigned")
		// create the route struct and add the user reference.
		localDomainRoute := &models.DomainRoute{
			InstanceId:     msg.InstanceId,
			State:          cfdomainbroker.Provisioning,
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
		if w.settings.LogLevel == 1 {
			if err := w.settings.Db.Debug().Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-debug-save-route", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
			}
		} else {
			if err := w.settings.Db.Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-save-route", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
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
			lsession.Error("acme-certificate-obtain", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}
		lsession.Info("certificate-obtained")

		localCert := models.Certificate{
			InstanceId: msg.InstanceId,
			Resource:   cert,
		}

		if w.settings.LogLevel == 1 {
			if err := w.settings.Db.Debug().Create(&localCert).Error; err != nil {
				lsession.Error("db-save-certificate", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
			}
		} else {
			if err := w.settings.Db.Create(&localCert).Error; err != nil {
				lsession.Error("db-save-certificate", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
			}
		}
		lsession.Info("db-certificate-stored")

		// save the ELB arn.
		localDomainRoute.ELBArn = *targetElb.LoadBalancerArn

		// generate the necessary input.
		certUploadInput := &iam.UploadServerCertificateInput{}
		certUploadInput.SetCertificateBody(string(localCert.Resource.Certificate))
		certUploadInput.SetPrivateKey(string(localCert.Resource.PrivateKey))
		certUploadInput.SetServerCertificateName(fmt.Sprintf("cf-domain-%s", msg.InstanceId))

		// upload the certificate.
		certArn, err := w.settings.IamSvc.UploadServerCertificate(certUploadInput)
		if err != nil {
			lsession.Error("iam-upload-server-certificate", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}
		lsession.Info("certificate-uploaded-to-iam")

		if certArn.ServerCertificateMetadata.Arn == nil {
			err := errors.New("nil pointer dereference")
			lsession.Error("iam-server-certificate-arn-empty", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}

		//save cert ARN
		localCert.ARN = *(certArn.ServerCertificateMetadata.Arn)
		if w.settings.LogLevel == 1 {
			if err := w.settings.Db.Debug().Model(&localCert).Where("instance_id = ?", msg.InstanceId).Save(&localCert).Error; err != nil {
				lsession.Error("db-update-certificate-arn", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
			}
		} else {
			if err := w.settings.Db.Model(&localCert).Where("instance_id = ?", msg.InstanceId).Save(&localCert).Error; err != nil {
				lsession.Error("db-update-certificate-arn", err)
				w.provisioningErrorMap[msg.InstanceId] = err
				return
			}
		}

		// grab the listeners.
		listeners, err := w.settings.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
			LoadBalancerArn: targetElb.LoadBalancerArn,
		})
		if err != nil {
			lsession.Error("elbsvc-describe-listeners", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
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
			lsession.Error("listener-arn-is-nil", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}

		lsession.Debug("found-https-listener", lager.Data{
			"listener-arn": localDomainRoute.ListenerArn,
		})

		// upload the certificate to the listener.
		if _, err := w.settings.ElbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
			ListenerArn: targetListenArn,
			Certificates: []*elbv2.Certificate{
				{
					CertificateArn: certArn.ServerCertificateMetadata.Arn,
				},
			},
		}); err != nil {
			lsession.Error("elbsvc-add-listener-certificates", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}
		lsession.Info("certificate-uploaded-to-elb")

		// since it's been uploaded to the elb, it's done.
		localDomainRoute.State = cfdomainbroker.Provisioned

		// store the certificate and elb info the database.
		if err := w.settings.Db.Save(localDomainRoute).Error; err != nil {
			lsession.Error("db-save-route", err)
			w.provisioningErrorMap[msg.InstanceId] = err
			return
		}

	}
	//else if len(msg.CdnOpts.Domain) > 0 {
	//	// create the route struct and add the user reference.
	//	var domain models.Domain
	//	domain.Value = msg.CdnOpts.Domain
	//	var domains []models.Domain
	//	domains = append(domains, domain)
	//
	//	localCDNRoute := &models.DomainRoute{
	//		InstanceId:     msg.InstanceId,
	//		State:          cfdomainbroker.Provisioning,
	//		User:           user,
	//		DomainExternal: domains,
	//		Origin:         msg.CdnOpts.Origin,
	//		Path:           msg.CdnOpts.Path,
	//		InsecureOrigin: msg.CdnOpts.InsecureOrigin,
	//	}
	//
	//	dist, err := w.settings.CloudFront.Create(msg.InstanceId, make([]string, 0), msg.CdnOpts.Origin, msg.CdnOpts.Path, msg.CdnOpts.InsecureOrigin, msg.CdnOpts.Headers, msg.CdnOpts.Cookies, msg.Tags)
	//	if err != nil {
	//		lsession.Error("creating-cloudfront-instance", err)
	//		w.provisioningErrorMap[msg.InstanceId] = err
	//		return
	//	}
	//
	//	localCDNRoute.DomainInternal = *dist.DomainName
	//	localCDNRoute.DistributionId = *dist.Id
	//
	//	if err := w.settings.Db.Create(localCDNRoute).Error; err != nil {
	//		lsession.Error("db-creating-route", err)
	//		w.provisioningErrorMap[msg.InstanceId] = err
	//		return
	//	}
	//}
}

type DeprovisionRequest struct {
	Context      context.Context
	InstanceId   string
	Details      domain.DeprovisionDetails
	AsyncAllowed bool
	Response     chan<- DeprovisionResponse
}

type DeprovisionResponse struct {
	Spec  domain.DeprovisionServiceSpec
	Error error
}

func (w *WorkerManager) deprovisionRunner() {
	go func() {
		for {
			msg := <-w.deprovisionRequest
			go w.deprovision(msg, msg.Response)
		}
	}()
}

func (w *WorkerManager) deprovision(msg DeprovisionRequest, resp chan<- DeprovisionResponse) {

	localResp := DeprovisionResponse{}

	getInstanceRespc := make(chan GetInstanceResponse, 1)
	w.getInstanceRequest <- GetInstanceRequest{
		Context:    msg.Context,
		InstanceId: msg.InstanceId,
		Response:   getInstanceRespc,
	}

	getInstanceResponse := <-getInstanceRespc
	getInstanceResponse.Route.State = cfdomainbroker.Deprovisioning
	if err := w.settings.Db.Where("instance_id = ?", msg.InstanceId).Save(&getInstanceResponse.Route).Error; err != nil {
		w.logger.Error("db-update-deprovisioning-state", err)
		w.deprovisioningErrorMap[msg.InstanceId] = err
		return
	}

	lsession := w.logger.Session("worker-manager-deprovision", lager.Data{
		"instance-id":  msg.InstanceId,
		"listener-arn": getInstanceResponse.Route.ListenerArn,
	})

	var localCert models.Certificate
	result := w.settings.Db.Where("instance_id = ?", msg.InstanceId).Find(&localCert)

	if result.RecordNotFound() {
		lsession.Error("db-certificate-not-found", result.Error)
		w.deprovisioningErrorMap[msg.InstanceId] = result.Error
		return
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		w.deprovisioningErrorMap[msg.InstanceId] = result.Error
		return
	}

	lsession.Info("disabling-route")

	var localRoute models.DomainRoute
	result = w.settings.Db.Where("instance_id = ?", msg.InstanceId).Find(&localRoute)

	if result.RecordNotFound() {
		lsession.Error("db-route-not-found", result.Error)
		w.deprovisioningErrorMap[msg.InstanceId] = result.Error
		return
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		w.deprovisioningErrorMap[msg.InstanceId] = result.Error
		return
	}

	if _, err := w.settings.ElbSvc.RemoveListenerCertificates(&elbv2.RemoveListenerCertificatesInput{
		ListenerArn: aws.String(getInstanceResponse.Route.ListenerArn),
		Certificates: []*elbv2.Certificate{
			{CertificateArn: aws.String(localCert.ARN)},
		},
	}); err != nil {
		w.logger.Error("elb-remove-listener-certificate-failed", err)
		w.deprovisioningErrorMap[msg.InstanceId] = err
		return
	}

	for {
		w.logger.Info("deleting-cert-from-iam")
		if _, err := w.settings.IamSvc.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
			ServerCertificateName: aws.String(msg.InstanceId),
		}); err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == iam.ErrCodeDeleteConflictException {
					time.Sleep(1 * time.Second)
					continue
				}
			}
		}
		break
	}

	lsession.Info("deprovisioning-service-instance")

	// keep the old service instance around, but mark it as deprovisioned.
	// todo (mxplusb): determine if we want to clean up old records or keep them, for now we are keeping them
	localRoute.State = cfdomainbroker.Deprovisioned
	result = w.settings.Db.Where("instance_id = ?", msg.InstanceId).Save(&localRoute)
	if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		w.deprovisioningErrorMap[msg.InstanceId] = result.Error
		return
	}

	lsession.Info("deprovisioned-service-instance")

	// todo (mxplusb): determine whether or not to keep old certs.
	//result = w.settings.Db.Delete(&localCert)
	//
	//if result.RecordNotFound() {
	//	lsession.Error("db-certificate-not-found", result.Error)
	//	w.deprovisioningErrorMap[msg.InstanceId] = result.Error
	//	return
	//} else if result.Error != nil {
	//	lsession.Error("db-generic-error", result.Error)
	//	w.deprovisioningErrorMap[msg.InstanceId] = result.Error
	//	return
	//}

	resp <- localResp
}

// Gets a specific service instance.
type GetInstanceRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan<- GetInstanceResponse
}

type GetInstanceResponse struct {
	Route models.DomainRoute
	Error error
}

func (w *WorkerManager) getInstanceRunner() {
	go func() {
		for {
			msg := <-w.getInstanceRequest
			go w.getInstance(msg, msg.Response)
		}
	}()
}

func (w *WorkerManager) getInstance(msg GetInstanceRequest, resp chan<- GetInstanceResponse) {
	lsession := w.logger.Session("get-instance")

	localResp := GetInstanceResponse{
		Error: nil,
	}

	// if the instance id is in the provisioning error map, then there was a certificate provisioning error and we
	// need to surface it
	if err, ok := w.provisioningErrorMap[msg.InstanceId]; ok {
		localResp.Error = err
		resp <- localResp
		return
	}

	// if the instance id is in the deprovisioning error map, then there was a deprovisioning error and we need to
	// surface it
	if err, ok := w.deprovisioningErrorMap[msg.InstanceId]; ok {
		localResp.Error = err
		resp <- localResp
		return
	}

	var localRoute models.DomainRoute
	result := w.settings.Db.Where("instance_id = ?", msg.InstanceId).Find(&localRoute)
	if result.RecordNotFound() {
		lsession.Error("db-record-not-found", apiresponses.ErrInstanceDoesNotExist)
		localResp.Error = result.Error
		resp <- localResp
		return
	} else if result.Error != nil {
		lsession.Error("db-get-first-route", result.Error)
		localResp.Error = result.Error
		resp <- localResp
		return
	}

	localResp.Route = localRoute

	resp <- localResp
}

type UpdateRequest struct {
	Context    context.Context
	InstanceId string
}

type LastOperationRequest struct {
	Context    context.Context
	InstanceId string
	Details    domain.PollDetails
	Response   chan<- LastOperationResponse
}

type LastOperationResponse struct {
	LastOperation domain.LastOperation
	Error         error
}

func (w *WorkerManager) lastOperationRunner() {
	go func() {
		for {
			msg := <-w.lastOperationRequest
			go w.lastOperation(msg, msg.Response)
		}
	}()
}

func (w *WorkerManager) lastOperation(msg LastOperationRequest, resp chan<- LastOperationResponse) {
	lsession := w.logger.Session("poll", lager.Data{
		"instance-id": msg.InstanceId,
	})

	respc := make(chan GetInstanceResponse, 1)
	w.getInstanceRequest <- GetInstanceRequest{
		Context:    msg.Context,
		InstanceId: msg.InstanceId,
		Response:   respc,
	}

	getInstanceResponse := <-respc
	localResp := LastOperationResponse{
		Error: nil,
	}

	// basically, if there is an asynchronous error, surface it here.
	if getInstanceResponse.Error != nil {
		localResp.Error = getInstanceResponse.Error
		resp <- localResp
		return
	}

	switch getInstanceResponse.Route.State {
	case cfdomainbroker.Provisioning:
		lsession.Info("check-provisioning")

		innerLocalRespc := make(chan DnsInstructionsResponse, 1)
		w.dnsInstructionsRequest <- DnsInstructionsRequest{
			Context:    msg.Context,
			InstanceId: msg.InstanceId,
			Response:   innerLocalRespc,
		}
		innerLocalResp := <-innerLocalRespc

		var sb strings.Builder
		for idx := range innerLocalResp.Messenger {
			if _, err := fmt.Fprint(&sb, innerLocalResp.Messenger[idx].String()); err != nil {
				lsession.Error("string-builder-fprint", err)
			}
		}

		localResp.LastOperation = domain.LastOperation{
			State:       domain.InProgress,
			Description: sb.String(),
		}
		resp <- localResp
	case cfdomainbroker.Deprovisioning:
		lsession.Info("check-deprovisioning")

		localResp.LastOperation = domain.LastOperation{
			State:       domain.InProgress,
			Description: "",
		}
		resp <- localResp
	}
}

type DnsInstructionsRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan<- DnsInstructionsResponse
}

type DnsInstructionsResponse struct {
	Messenger []leproviders.DomainMessenger
	Error     error
}

func (w *WorkerManager) dnsInstructionsRunner() {
	go func() {
		for {
			msg := <-w.dnsInstructionsRequest
			go w.getDnsInstructions(msg, msg.Response)
		}
	}()
}

func (w *WorkerManager) getDnsInstructions(msg DnsInstructionsRequest, resp chan<- DnsInstructionsResponse) {
	lsession := w.logger.Session("get-dns-instructions", lager.Data{
		"instance-id": msg.InstanceId,
	})

	localResp := DnsInstructionsResponse{
		Error: nil,
	}

	var domainMessage []leproviders.DomainMessenger
	if err := w.settings.Db.Where("instance_id = ?", msg.InstanceId).Find(&domainMessage).Error; err != nil {
		lsession.Error("db-find-dns-instructions", err)
		localResp.Error = err
		resp <- localResp
		return
	}
	lsession.Info("found-domain-auth-instructions")

	localResp.Messenger = domainMessage
	resp <- localResp
}

// Not Implemented
type BindRequest struct {
	Context      context.Context
	InstanceId   string
	BindingId    string
	Details      domain.BindDetails
	AsyncAllowed bool
}

// Not Implemented
type UnbindRequest struct {
	Context    context.Context
	InstanceId string
}

// Not Implemented
type GetBindingRequest struct {
	Context    context.Context
	InstanceId string
}

// Not Implemented
type LastBindingOperationRequest struct {
	Context    context.Context
	InstanceId string
}
