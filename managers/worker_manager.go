package managers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi/domain"
)

type WorkerManagerSettings struct {
	AutoStartWorkerPool         bool
	Db                          *gorm.DB
	IamSvc                      iamiface.IAMAPI
	CloudFront                  cloudfrontiface.CloudFrontAPI
	ElbNames                    []*string
	ElbRequest                  chan ElbRequest
	ElbSvc                      elbv2iface.ELBV2API
	ElbUpdateFrequencyInSeconds time.Duration
	Logger                      lager.Logger
	LogLevel                    int
	ObtainmentManagerSettings   *ObtainmentManagerSettings
}

// The Worker Manager is designed to be a totally asynchronous, message-driven interface on behalf of the Service Broker
// API. It has two interface points: `RequestRouter` and `GetLastError()`. `RequestRouter` is designed to handle any
// type of incoming request. `GetLastError()` will return the most recent unseen error related to the service instance
// requested.
type WorkerManager struct {
	RequestRouter               chan interface{}
	Running                     bool
	settings                    *WorkerManagerSettings
	db                          *gorm.DB
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
	iamUploadRequest            chan IamUploadRequest
	elbUploadRequest            chan ElbUploadRequest

	provisioningErrorMap   map[string]error
	deprovisioningErrorMap map[string]error
	elbs                   []*elb
	elbRequest             chan ElbRequest
	globalQueueManagerChan chan ManagerRequest
	logger                 lager.Logger
	lock                   sync.RWMutex
}

type elb struct {
	lb              *elbv2.LoadBalancer
	certsOnListener int
}

func NewWorkerManager(settings *WorkerManagerSettings) (*WorkerManager, error) {
	p := &WorkerManager{
		RequestRouter:               make(chan interface{}, 150),
		settings:                    settings,
		db:                          settings.Db,
		logger:                      settings.Logger.Session("worker-manager"),
		elbRequest:                  settings.ElbRequest,
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
		iamUploadRequest:            make(chan IamUploadRequest, 150),
		elbUploadRequest:            make(chan ElbUploadRequest, 150),
	}

	if p.settings.AutoStartWorkerPool {
		p.Run()
		p.Running = true
	}
	p.Running = false

	return p, nil
}

// Runs the worker pool. Can be automatically invoked via a setting with `NewWorkerManager`.
// todo (mxplusb): leverage the runners to enable and disable SB functionality.
// todo (mxplusb): figure out a `Stop()` story.
// todo (mxplusb): figure out how to pass a context object all the way down.
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
			case IamUploadRequest:
				w.iamUploadRequest <- msg.(IamUploadRequest)
			}
		}
	}()

	// start our listeners/runners
	w.elbPopulator()
	w.provisionRunner()
	w.getInstanceRunner()
	w.lastOperationRunner()
	w.dnsInstructionsRunner()
	w.deprovisionRunner()
	w.iamUploadRunner()
	w.elbUploadRunner()
}

// background function to keep the internal elb certs on listener up to date.
// runs every so often.
func (w *WorkerManager) elbPopulator() {
	go func() {
		ticker := time.NewTicker(w.settings.ElbUpdateFrequencyInSeconds * time.Second)
		for ; true; <-ticker.C {
			// get a list of elbs.
			resp, err := w.settings.ElbSvc.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{
				Names: w.settings.ElbNames,
			})
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
	}()
}

func (w *WorkerManager) elbRunner() {
	go func() {
		for {
			msg := <-w.elbRequest
			go w.elbFinder(msg)
		}
	}()
}

func (w *WorkerManager) elbFinder(request ElbRequest) {
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
		err := errors.New("nil pointer dereference")
		w.logger.Error("desired-lb-nil-reference", err)
		w.provisioningErrorMap[request.InstanceId] = err
		request.Response <- ElbResponse{
			InstanceId: request.InstanceId,
			Error:      err,
		}
		return
	}

	w.logger.Info("least-assigned-found", lager.Data{
		"elb-target": &targetElb.LoadBalancerArn,
	})

	request.Response <- ElbResponse{
		InstanceId: request.InstanceId,
		Error:      nil,
		Elb:        targetElb,
	}
}

type ElbUploadRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan ElbUploadResponse
}

type ElbUploadResponse struct {
	InstanceId string
	Ok         bool
	Error      error
}

func (w *WorkerManager) elbUploadRunner() {
	go func() {
		for {
			msg := <-w.elbUploadRequest
			go w.elbUpload(msg)
		}
	}()
}

func (w *WorkerManager) elbUpload(request ElbUploadRequest) {

	lsession := w.logger.Session("elb-upload", lager.Data{
		"instance-id": request.InstanceId,
	})

	var localDomainRoute DomainRouteModel
	results := w.db.Where("instance_id = ?", request.InstanceId).Find(&localDomainRoute)
	if results.Error != nil {
		lsession.Error("cannot-find-domain-route-reference", results.Error)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: IamCertificateUploaded,
				DesiredState: Error,
				ErrorMessage: results.Error.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ElbUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}

	var localCert Certificate
	results = w.db.Where("instance_id = ?", request.InstanceId).Find(&localCert)
	if results.Error != nil {
		lsession.Error("cannot-find-certificate-reference", results.Error)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: IamCertificateUploaded,
				DesiredState: Error,
				ErrorMessage: results.Error.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ElbUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}

	// grab the listeners.
	listeners, err := w.settings.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(localDomainRoute.ElbArn),
	})
	if err != nil {
		lsession.Error("elbsvc-describe-listeners", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: IamCertificateUploaded,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ElbUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      err,
			}
		}
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
		localDomainRoute.ElbListenerArn = *(targetListenArn)
	} else {
		err := errors.New("missing listener arn")
		lsession.Error("listener-arn-is-nil", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: IamCertificateUploaded,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ElbUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      err,
			}
		}
		return
	}

	lsession.Debug("found-https-listener", lager.Data{
		"listener-arn": localDomainRoute.ElbListenerArn,
	})

	// upload the certificate to the listener.
	if _, err := w.settings.ElbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
		ListenerArn: targetListenArn,
		Certificates: []*elbv2.Certificate{
			{
				CertificateArn: aws.String(localDomainRoute.IamCertificateArn),
			},
		},
	}); err != nil {
		lsession.Error("elbsvc-add-listener-certificates", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: IamCertificateUploaded,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ElbUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      err,
			}
		}
		return
	}
	lsession.Info("certificate-uploaded-to-elb")

	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			InstanceId:   request.InstanceId,
			CurrentState: IamCertificateUploaded,
			DesiredState: ElbAssigned,
			ErrorMessage: "",
			Response:     nil,
		},
	}
	if request.Response != nil {
		request.Response <- ElbUploadResponse{
			InstanceId: request.InstanceId,
			Ok:         true,
			Error:      nil,
		}
	}
}

type IamUploadRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan IamUploadResponse
}

type IamUploadResponse struct {
	InstanceId string
	Ok         bool
	Error      error
}

func (w *WorkerManager) iamUploadRunner() {
	go func() {
		for {
			msg := <-w.iamUploadRequest
			go w.iamUpload(msg)
		}
	}()
}

func (w *WorkerManager) iamUpload(request IamUploadRequest) {

	lsession := w.logger.Session("iam-upload", lager.Data{
		"instance-id": request.InstanceId,
	})

	var localCert Certificate
	results := w.db.Where("instance_id = ?").Find(&localCert)
	if results.Error != nil {
		lsession.Error("cannot-get-certificate-reference", results.Error)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: results.Error.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- IamUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}

	// generate the necessary input.
	certUploadInput := &iam.UploadServerCertificateInput{}
	certUploadInput.SetCertificateBody(string(localCert.Certificate))
	certUploadInput.SetPrivateKey(string(localCert.PrivateKey))
	certUploadInput.SetServerCertificateName(fmt.Sprintf("cf-domain-%s", request.InstanceId))

	// upload the certificate.
	certArn, err := w.settings.IamSvc.UploadServerCertificate(certUploadInput)
	if err != nil {
		lsession.Error("iam-upload-server-certificate", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- IamUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}
	lsession.Info("certificate-uploaded-to-iam")

	if certArn.ServerCertificateMetadata.Arn == nil {
		err := errors.New("nil pointer dereference")
		lsession.Error("iam-server-certificate-arn-empty", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- IamUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}

	var localRoute DomainRouteModel
	results = w.db.Where("instance_id = ?", request.InstanceId).Find(&localRoute)
	if results.Error != nil {
		lsession.Error("error-finding-domain-route", err)
		if request.Response != nil {
		}
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- IamUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		return
	}

	localRoute.IamCertificateArn = *(certArn.ServerCertificateMetadata.Arn)

	tx := w.db.Begin()
	results = tx.Update(localCert)
	if results.Error != nil {
		lsession.Error("db-update-certificate-arn", err)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- IamUploadResponse{
				InstanceId: request.InstanceId,
				Ok:         false,
				Error:      results.Error,
			}
		}
		tx.Rollback()
		return
	}
	tx.Commit()

	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			InstanceId:   request.InstanceId,
			CurrentState: CertificateReady,
			DesiredState: IamCertificateUploaded,
			ErrorMessage: "",
			Response:     nil,
		},
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

func (w *WorkerManager) provision(request ProvisionRequest) {
	lsession := w.logger.Session("create-route", lager.Data{
		"instance-id": request.InstanceId,
		"domains":     request.DomainOpts.Domains,
	})

	if len(request.DomainOpts.Domains) > 0 {
		lsession.Debug("acme-dns-provider-assigned")

		// tell the system we're changing state to provisioning.
		provisionStateReqRespc := make(chan StateTransitionResponse, 1)
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: New,
				Response:     provisionStateReqRespc,
			},
		}
		resp := <-provisionStateReqRespc
		close(provisionStateReqRespc)

		if !resp.Ok {
			lsession.Error("cannot-create-state", resp.Error)
		}

		// create the route struct and add the user reference.
		localDomainRoute := &DomainRouteModel{
			InstanceId:     request.InstanceId,
			DomainExternal: request.DomainOpts.Domains,
		}

		// store the certificate and elb info the database.
		// check for debug.
		if w.settings.LogLevel == 1 {
			if err := w.settings.Db.Debug().Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-debug-save-route", err)
				w.provisioningErrorMap[request.InstanceId] = err
				return
			}
		} else {
			if err := w.settings.Db.Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-save-route", err)
				w.provisioningErrorMap[request.InstanceId] = err
				return
			}
		}
		lsession.Info("db-route-saved")

		var domains []string
		for i := 0; i < len(request.DomainOpts.Domains); i++ {
			domains = append(domains, request.DomainOpts.Domains[i].Value)
		}

		// request the certificate to be obtained
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       ObtainmentManagerType,
			Payload: certificate.ObtainRequest{
				Domains: domains,
				Bundle:  true,
			},
		}
		return

		// this point the provisioning is done, we just need to wait on the certificate.

		// todo (mxplusb): delete domain message data - i.e. keyAuth.

	}
	//else if len(request.CdnOpts.Domain) > 0 {
	//	// create the route struct and add the user reference.
	//	var domain models.Domain
	//	domain.Value = request.CdnOpts.Domain
	//	var domains []models.Domain
	//	domains = append(domains, domain)
	//
	//	localCDNRoute := &models.DomainRouteModel{
	//		InstanceId:     request.InstanceId,
	//		ObtainState:          cfdomainbroker.Provisioning,
	//		User:           user,
	//		DomainExternal: domains,
	//		Origin:         request.CdnOpts.Origin,
	//		Path:           request.CdnOpts.Path,
	//		InsecureOrigin: request.CdnOpts.InsecureOrigin,
	//	}
	//
	//	dist, err := w.settings.CloudFront.Create(request.InstanceId, make([]string, 0), request.CdnOpts.Origin, request.CdnOpts.Path, request.CdnOpts.InsecureOrigin, request.CdnOpts.Headers, request.CdnOpts.Cookies, request.Tags)
	//	if err != nil {
	//		lsession.Error("creating-cloudfront-instance", err)
	//		w.provisioningErrorMap[request.InstanceId] = err
	//		return
	//	}
	//
	//	localCDNRoute.DomainInternal = *dist.DomainName
	//	localCDNRoute.DistributionId = *dist.Id
	//
	//	if err := w.settings.Db.Create(localCDNRoute).Error; err != nil {
	//		lsession.Error("db-creating-route", err)
	//		w.provisioningErrorMap[request.InstanceId] = err
	//		return
	//	}
	//}
}

// internal error checker to see if we need to panic on networking-related errors.
// real talk: this mostly exists because macos is flaky af on networking when it comes to opening and closing ports in
// random succession.
func (w *WorkerManager) checkNetworkError(err error) {
	if err == nil {
		return // we're okay so skip it.
	} else if netError, ok := err.(net.Error); ok && netError.Timeout() {
		w.logger.Error("network-timeout", err)
		return
	}

	// we're just checking to see if we need to panic.
	// if we don't need to panic, this will pass and
	// whatever logic called this will keep going.
	switch t := err.(type) {
	case *net.OpError:
		if t.Op == "dial" {
			w.logger.Fatal("unknown-host", err)
		} else if t.Op == "read" {
			w.logger.Fatal("connection-refused", err)
		}
	case syscall.Errno:
		if t == syscall.ECONNREFUSED {
			w.logger.Fatal("connection-refused", err)
		}
	}
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
			go w.deprovision(msg)
		}
	}()
}

// todo (mxplusb): break this apart at some point.
func (w *WorkerManager) deprovision(request DeprovisionRequest) {

	// get the current state.
	currentStateRespc := make(chan StateResponse, 1)
	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateRequest{
			Context:    request.Context,
			InstanceId: request.InstanceId,
			Response:   currentStateRespc,
		},
	}
	currentState := <-currentStateRespc

	// get the service instance.
	getInstanceRespc := make(chan GetInstanceResponse, 1)
	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       WorkerManagerType,
		Payload: GetInstanceRequest{
			Context:    request.Context,
			InstanceId: request.InstanceId,
			Response:   getInstanceRespc,
		},
	}
	serviceInstance := <-getInstanceRespc

	if serviceInstance.ErrorNotFound {
		request.Response <- DeprovisionResponse{
			Spec: domain.DeprovisionServiceSpec{
				IsAsync: true,
			},
			Error: errors.New("service instance not found"),
		}
		return
	} else if serviceInstance.Error != nil {
		request.Response <- DeprovisionResponse{Error: serviceInstance.Error}
		return
	}

	// request a state change
	stateTransitionRespc := make(chan StateTransitionResponse, 1)
	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			Context:      request.Context,
			InstanceId:   request.InstanceId,
			CurrentState: currentState.CurrentState,
			DesiredState: Deprovisioning,
			Response:     stateTransitionRespc,
		},
	}
	stateTransitionResp := <-stateTransitionRespc
	if stateTransitionResp.Error != nil {
		request.Response <- DeprovisionResponse{Error: serviceInstance.Error}
		return
	}

	lsession := w.logger.Session("begin-deprovision", lager.Data{
		"instance-id":  request.InstanceId,
		"listener-arn": serviceInstance.Route.ElbListenerArn,
	})

	// get the certificate.
	var localCert Certificate
	result := w.settings.Db.Where("instance_id = ?", request.InstanceId).Find(&localCert)
	if result.RecordNotFound() {
		lsession.Error("certificate-not-found", result.Error)
		request.Response <- DeprovisionResponse{Error: result.Error}
		return
	} else if result.Error != nil {
		lsession.Error("generic-certificate-db-error", result.Error)
		request.Response <- DeprovisionResponse{Error: result.Error}
		return
	}

	// get the domain reference.
	var localRoute DomainRouteModel
	result = w.settings.Db.Where("instance_id = ?", request.InstanceId).Find(&localRoute)
	if result.RecordNotFound() {
		lsession.Error("route-not-found", result.Error)
		request.Response <- DeprovisionResponse{Error: result.Error}
		return
	} else if result.Error != nil {
		lsession.Error("generic-domain-route-db-error", result.Error)
		request.Response <- DeprovisionResponse{Error: result.Error}
		return
	}

	lsession.Info("disabling-elb-certificate")

	if _, err := w.settings.ElbSvc.RemoveListenerCertificates(&elbv2.RemoveListenerCertificatesInput{
		ListenerArn: aws.String(serviceInstance.Route.ElbListenerArn),
		Certificates: []*elbv2.Certificate{
			{CertificateArn: aws.String(localCert.ARN)},
		},
	}); err != nil {
		w.logger.Error("elb-remove-listener-certificate-failed", err)
		request.Response <- DeprovisionResponse{Error: result.Error}
		return
	}

	for {
		w.logger.Info("deleting-cert-from-iam")
		if _, err := w.settings.IamSvc.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
			ServerCertificateName: aws.String(request.InstanceId),
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

	// request a state change.
	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			Context:    request.Context,
			InstanceId: request.InstanceId,
			Response:   stateTransitionRespc,
		},
	}
	stateTransitionResp = <-stateTransitionRespc
	if stateTransitionResp.Error != nil {
		request.Response <- DeprovisionResponse{Error: serviceInstance.Error}
		return
	}

	lsession.Info("deprovisioned-service-instance")

	// todo (mxplusb): determine whether or not to keep old certs.

	request.Response <- DeprovisionResponse{
		Spec: domain.DeprovisionServiceSpec{
			IsAsync: true,
		},
		Error: nil,
	}
}

// Gets a specific service instance.
type GetInstanceRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan<- GetInstanceResponse
}

type GetInstanceResponse struct {
	InstanceId    string
	Route         DomainRouteModel
	Error         error
	ErrorNotFound bool
}

func (w *WorkerManager) getInstanceRunner() {
	go func() {
		for {
			msg := <-w.getInstanceRequest
			go w.getInstance(msg)
		}
	}()
}

// This function just polls for the last operation so the workflow will continue to move state.
func (w *WorkerManager) pollRunner() {

	lsession := w.logger.Session("poll-runner")

	tick := time.Millisecond * 3000
	failTime := tick - 100

	ticker := time.NewTicker(tick)
	for ; true; <-ticker.C {

		// todo (mxplusb): figure out how to implement canceling.
		ctx := context.TODO()

		var localDomainRoutes []StateModel
		results := w.db.Where("current_state < ?", Provisioned).Find(&localDomainRoutes)
		if results.RecordNotFound() {
			continue
		} else if results.Error != nil {
			lsession.Error("error-finding-currently-provisioning-records", results.Error)
			continue
		}

		respc := make(chan LastOperationResponse, len(localDomainRoutes))

		for idx := range localDomainRoutes {
			if localDomainRoutes[idx].ErrorMessage == "" {
				w.globalQueueManagerChan <- ManagerRequest{
					InstanceId: localDomainRoutes[idx].InstanceId,
					Type:       WorkerManagerType,
					Payload: LastOperationRequest{
						Context:    ctx,
						InstanceId: localDomainRoutes[idx].InstanceId,
						Details:    domain.PollDetails{},
						Response:   respc,
					},
				}
			}
		}

		// sleep for a bit, then close.
		time.Sleep(failTime)
		close(respc)
	}
}

func (w *WorkerManager) getInstance(request GetInstanceRequest) {
	lsession := w.logger.Session("get-instance", lager.Data{
		"instance-id": request.InstanceId,
	})

	var localDomainRoute DomainRouteModel
	results := w.db.Where("instance_id = ?", request.InstanceId).Find(&localDomainRoute)
	if results.Error != nil {
		w.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Unknown,
				DesiredState: Error,
				ErrorMessage: results.Error.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			lresp := GetInstanceResponse{
				InstanceId: request.InstanceId,
				Route:      DomainRouteModel{},
				Error:      results.Error,
			}
			if results.RecordNotFound() {
				lresp.ErrorNotFound = true
			} else {
				lresp.ErrorNotFound = false
			}
			request.Response <- lresp
		}
		lsession.Error("cannot-find-domain-route-reference", results.Error)
		return
	}
	lsession.Info("found-service-instance")

	request.Response <- GetInstanceResponse{
		InstanceId:    request.InstanceId,
		Route:         localDomainRoute,
		Error:         nil,
		ErrorNotFound: false,
	}
}

type UpdateRequest struct {
	Context    context.Context
	InstanceId string
}

type LastOperationRequest struct {
	Context    context.Context
	InstanceId string
	Details    domain.PollDetails
	Response   chan LastOperationResponse
}

type LastOperationResponse struct {
	LastOperation domain.LastOperation
	Error         error
}

func (w *WorkerManager) lastOperationRunner() {
	go func() {
		for {
			msg := <-w.lastOperationRequest
			go w.lastOperation(msg)
		}
	}()
}

// lastOperation is really the state promoter, in addition to getting the actual state.
func (w *WorkerManager) lastOperation(request LastOperationRequest) {
	lsession := w.logger.Session("last-operation", lager.Data{
		"instance-id": request.InstanceId,
	})

	// get the state of things.
	stateRespc := make(chan StateResponse, 1)
	w.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateRequest{
			InstanceId: request.InstanceId,
			Response:   stateRespc,
		},
	}
	stateResp := <-stateRespc
	close(stateRespc)

	// basically, if there is an asynchronous error, surface it here.
	if stateResp.Error != nil {
		request.Response <- LastOperationResponse{
			LastOperation: domain.LastOperation{
				State: domain.Failed,
			},
			Error: stateResp.Error,
		}
		return
	}

	switch {
	// check for errors.
	case stateResp.CurrentState == Error:
		request.Response <- LastOperationResponse{
			LastOperation: domain.LastOperation{
				State:       domain.Failed,
				Description: stateResp.Error.Error(),
			},
			Error: stateResp.Error,
		}
	// check to see if it's somewhere in provisioning
	case stateResp.CurrentState < Provisioned:
		lsession.Info("check-provisioning")

		// if the state is less than Provisioned but more than PostSolve,
		// we likely need to get the dns instructions.
		if stateResp.CurrentState < PostSolve && stateResp.CurrentState > PreOrder {
			dnsInstructionsRespc := make(chan DnsInstructionsResponse, 1)
			w.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       WorkerManagerType,
				Payload: DnsInstructionsRequest{
					Context:    request.Context,
					InstanceId: request.InstanceId,
					Response:   dnsInstructionsRespc,
				},
			}
			innerLocalResp := <-dnsInstructionsRespc
			close(dnsInstructionsRespc)

			val, err := json.Marshal(innerLocalResp.Messenger)
			if err != nil {
				innerLocalResp.Error = err
				request.Response <- LastOperationResponse{
					LastOperation: domain.LastOperation{
						State:       domain.Failed,
						Description: err.Error(),
					},
					Error: err,
				}
				return
			}

			request.Response <- LastOperationResponse{
				LastOperation: domain.LastOperation{
					State:       domain.InProgress,
					Description: string(val),
				},
				Error: nil,
			}
		}

		// the certificate has been solved but is not yet ready.
		if stateResp.CurrentState == PostSolve || stateResp.CurrentState == Finalized {
			val, _ := json.Marshal(&struct {
				State string `json:"state"`
			}{
				State: "certificate challenge has been solved, waiting on let's encrypt to provision certificate",
			})
			request.Response <- LastOperationResponse{
				LastOperation: domain.LastOperation{
					State:       domain.InProgress,
					Description: string(val),
				},
				Error: nil,
			}
		}

		if stateResp.CurrentState == CertificateReady {
			respc := make(chan IamUploadResponse, 1)
			w.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       WorkerManagerType,
				Payload: IamUploadRequest{
					Context:    request.Context,
					InstanceId: request.InstanceId,
					Response:   respc,
				},
			}
			resp := <-respc
			close(respc)

			val, _ := json.Marshal(&struct {
				State string `json:"state"`
			}{
				State: "certificate is ready and is being uploaded to iam",
			})
			if resp.Error != nil {
				request.Response <- LastOperationResponse{
					LastOperation: domain.LastOperation{
						State:       domain.Failed,
						Description: "",
					},
					Error: resp.Error,
				}
				return
			}

			request.Response <- LastOperationResponse{
				LastOperation: domain.LastOperation{
					State:       domain.InProgress,
					Description: string(val),
				},
				Error: nil,
			}
		}

		if stateResp.CurrentState == IamCertificateUploaded {
			val, _ := json.Marshal(&struct {
				State string `json:"state"`
			}{
				State: "certificate is available in iam and is being uploaded to the elb",
			})

			respc := make(chan ElbUploadResponse, 1)
			w.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       WorkerManagerType,
				Payload: ElbUploadRequest{
					Context:    request.Context,
					InstanceId: request.InstanceId,
					Response:   respc,
				},
			}
			resp := <-respc
			close(respc)

			if resp.Error != nil {
				request.Response <- LastOperationResponse{
					LastOperation: domain.LastOperation{
						State:       domain.Failed,
						Description: "",
					},
					Error: resp.Error,
				}
				return
			}

			request.Response <- LastOperationResponse{
				LastOperation: domain.LastOperation{
					State:       domain.InProgress,
					Description: string(val),
				},
				Error: nil,
			}
		}

		if stateResp.CurrentState == ElbAssigned {
			val, _ := json.Marshal(&struct {
				State string `json:"state"`
			}{
				State: "certificate is provisioned to ec2, marking as provisioned",
			})

			respc := make(chan StateTransitionResponse, 1)
			w.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       WorkerManagerType,
				Payload: StateTransitionRequest{
					Context:      request.Context,
					InstanceId:   request.InstanceId,
					CurrentState: ElbAssigned,
					DesiredState: Provisioned,
					Response:     respc,
				},
			}
			resp := <-respc
			close(respc)

			if resp.Error != nil {
				request.Response <- LastOperationResponse{
					LastOperation: domain.LastOperation{
						State:       domain.Failed,
						Description: "",
					},
					Error: resp.Error,
				}
				return
			}

			request.Response <- LastOperationResponse{
				LastOperation: domain.LastOperation{
					State:       domain.Succeeded,
					Description: string(val),
				},
				Error: nil,
			}
		}

	case stateResp.CurrentState == Deprovisioning:
		lsession.Info("check-deprovisioning")
		request.Response <- LastOperationResponse{
			LastOperation: domain.LastOperation{
				State:       domain.InProgress,
				Description: "",
			},
			Error: nil,
		}

	case stateResp.CurrentState == Deprovisioned:
		request.Response <- LastOperationResponse{
			LastOperation: domain.LastOperation{
				State:       domain.Succeeded,
				Description: "instance was deprovisioned and is no longer available",
			},
			Error: nil,
		}
	}
}

type DnsInstructionsRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan DnsInstructionsResponse
}

type DnsInstructionsResponse struct {
	Messenger []DomainMessenger
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

	var domainMessage []DomainMessenger
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
