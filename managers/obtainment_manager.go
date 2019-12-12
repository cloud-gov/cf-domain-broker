// Chunks of this file are using MIT licensed code.
// It is being relicensed as public domain as part of this work but credit and copyright is due to the original author.
// The original code can be found here: https://github.com/go-acme/lego

package managers

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/acme/api"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/challenge/resolver"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/go-pg/pg/v9"
	"github.com/go-pg/pg/v9/orm"
	"github.com/jinzhu/gorm"
	"github.com/miekg/dns"
	"go.uber.org/ratelimit"
	"golang.org/x/net/idna"
)

// Configuration options for the Obtainment Manager.
type ObtainmentManagerSettings struct {
	// Automatically start all the runners.
	Autostart bool
	// ACME server.
	ACMEConfig *lego.Config
	// Database connection we can use to store the checkpointed steps.
	Db *pg.DB
	// A channel must be opened so the reference to an ELB can be sent.
	ElbRequest chan ElbRequest
	// Logger to inherit.
	Logger lager.Logger
	// Used to sign the JSON Web Signature used by ACME.
	// See: https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3
	PrivateKey            crypto.PrivateKey
	PersistentDnsProvider bool
	Resolvers             map[string]string
}

// todo (mxplusb): ensure this gets assigned.
// todo (mxplusb): ensure this gets removed.
type ObtainmentManagerState struct {
	gorm.Model
	AcmeUserInfo *UserData
}

type ObtainmentManager struct {
	RequestRouter                 chan interface{}
	Running                       bool
	obtainRequest                 chan ObtainRequest
	authRequest                   chan AuthorizationRequest
	solveRequest                  chan SolveRequest
	getCertificateForOrderRequest chan GetCertificateForOrderRequest
	checkACMEResponseRequest      chan CheckACMEResponseRequest
	certificateReadyRequest       chan CertificateReadyRequest
	elbRequest                    chan ElbRequest
	acmeConfig                    *lego.Config
	core                          *api.Core
	client                        *ACMEClient
	restarted                     bool
	db                            *pg.DB
	globalQueueManagerChan        chan ManagerRequest
	goodResolutionMap             map[string]int
	logger                        lager.Logger
	limiter                       ratelimit.Limiter
	resolvers                     map[string]string
	settings                      *ObtainmentManagerSettings
}

// Generate a new Obtainment Manager, a checkpointed way for obtaining certificates.
// todo (mxplusb): make sure to deactivate all failed authorizations.
// todo (mxplusb): implement restart logic for unsolved records.
func NewObtainmentManager(settings *ObtainmentManagerSettings) (*ObtainmentManager, error) {

	o := &ObtainmentManager{
		RequestRouter:                 make(chan interface{}, 150),
		obtainRequest:                 make(chan ObtainRequest, 150),
		authRequest:                   make(chan AuthorizationRequest, 150),
		solveRequest:                  make(chan SolveRequest, 150),
		getCertificateForOrderRequest: make(chan GetCertificateForOrderRequest, 150),
		checkACMEResponseRequest:      make(chan CheckACMEResponseRequest, 150),
		certificateReadyRequest:       make(chan CertificateReadyRequest, 150),
		elbRequest:                    settings.ElbRequest,
		acmeConfig:                    settings.ACMEConfig,
		db:                            settings.Db,
		goodResolutionMap:             make(map[string]int),
		logger:                        settings.Logger.Session("obtainment-manager"),
		limiter:                       ratelimit.New(AcmeRateLimit, ratelimit.WithoutSlack),
		resolvers:                     settings.Resolvers,
		settings:                      settings,
	}

	// prep our acme client.
	if o.acmeConfig == nil {
		return &ObtainmentManager{}, errors.New("acme configuration cannot be nil")
	}
	if err := o.newClient(); err != nil {
		return &ObtainmentManager{}, err
	}

	// generate the DB models.
	tableOpts := &orm.CreateTableOptions{
		Varchar:       4096,
		Temp:          false,
		IfNotExists:   true,
		FKConstraints: false,
	}

	tableLiteral := []interface{}{
		&ObtainCheckpointModel{},
		&Certificate{},
		&ObtainmentManagerState{},
		&ProcInfo{},
	}

	for idx := range tableLiteral {
		if err := o.db.CreateTable(tableLiteral[idx], tableOpts); err != nil {
			return &ObtainmentManager{}, err
		}
	}

	// autostart the things if needed!
	if o.settings.Autostart {
		o.Run()
		o.Running = true
		return o, nil
	}
	o.Running = false
	return o, nil
}

// Runs the worker pool. Can be automatically invoked via a setting with `NewObtainmentManager`.
// todo (mxplusb): figure out a `Stop()` story.
// todo (mxplusb): figure out how to pass a context down
func (o *ObtainmentManager) Run() {

	o.logger.Debug("starting-request-router")

	// start the background router.
	go func() {
		for {
			msg := <-o.RequestRouter
			switch msg.(type) {
			case ObtainRequest:
				o.obtainRequest <- msg.(ObtainRequest)
			case AuthorizationRequest:
				o.authRequest <- msg.(AuthorizationRequest)
			case SolveRequest:
				o.solveRequest <- msg.(SolveRequest)
			case GetCertificateForOrderRequest:
				o.getCertificateForOrderRequest <- msg.(GetCertificateForOrderRequest)
			case CheckACMEResponseRequest:
				o.checkACMEResponseRequest <- msg.(CheckACMEResponseRequest)
			case CertificateReadyRequest:
				o.certificateReadyRequest <- msg.(CertificateReadyRequest)
			}
		}
	}()

	o.logger.Debug("starting-runners")

	// start our listeners/runners
	o.obtainRunner()
	o.authRunner()
	o.solveRunner()
	o.getCertificateForOrderRunner()
	o.checkResponseRunner()
	o.certificateReadyRunner()
	o.continuityRunner()
}

type ObtainmentResovler interface {
	Solve(authorizations []acme.Authorization) error
}

// The checkpoint state of a provisioning certificate
type ObtainCheckpointModel struct {
	ObtainRequest  ObtainRequest
	Order          acme.ExtendedOrder
	State          State
	Authorizations []acme.Authorization
	CSR            []byte
	InstanceId     string `pg:",pk"`
}

type ElbRequest struct {
	Context    context.Context
	InstanceId string
	Error      error
	Response   chan ElbResponse
}

type ElbResponse struct {
	InstanceId string
	Ok         bool
	Error      error
	Elb        *elbv2.LoadBalancer
}

// This client is designed to be the same as go-acme/lego.Client, except the
// certifier is extracted from being a private implementation.
type ACMEClient struct {
	Challenge    *resolver.SolverManager
	Registration *registration.Registrar
	core         *api.Core
	resolver     ObtainmentResovler
}

func (o *ObtainmentManager) newClient() error {

	lsession := o.logger.Session("new-acme-client-builder")

	lsession.Debug("building-client")

	if o.acmeConfig == nil {
		err := errors.New("a configuration must be provided")
		lsession.Error("nil-client-configuration", err)
		return err
	}

	_, err := url.Parse(o.acmeConfig.CADirURL)
	if err != nil {
		lsession.Error("acme-url-parse", err)
		return err
	}

	if o.acmeConfig.HTTPClient == nil {
		err := errors.New("the HTTP client cannot be nil")
		lsession.Error("nil-http-client", err)
		return err
	}

	privateKey := o.acmeConfig.User.GetPrivateKey()
	if privateKey == nil {
		err := errors.New("private key was nil")
		lsession.Error("nil-private-key", err)
		return err
	}

	var kid string
	if reg := o.acmeConfig.User.GetRegistration(); reg != nil {
		kid = reg.URI
	}

	// create our let's encrypt API client.
	core, err := api.New(o.acmeConfig.HTTPClient, "18f/domain-broker-v2", o.acmeConfig.CADirURL, kid, privateKey)
	if err != nil {
		lsession.Error("new-acme-api-failure", err)
		return err
	}
	o.core = core

	solversManager := resolver.NewSolversManager(o.core)
	prober := resolver.NewProber(solversManager)

	o.client = &ACMEClient{
		Challenge:    solversManager,
		Registration: registration.NewRegistrar(o.core, o.acmeConfig.User),
		core:         o.core,
		resolver:     prober,
	}

	o.logger.Info("acme-client-built")

	return nil
}

// ref: https://community.letsencrypt.org/t/le-staging-dns-servers/107282
// re: why we check 3 times per configured provider for validation.
func (o *ObtainmentManager) preCheck(domain, fqdn, value string, check dns01.PreCheckFunc) (b bool, e error) {
	lsession := o.logger.Session("dns-pre-check", lager.Data{
		"domain": domain,
		"fqdn":   fqdn,
		"value":  value,
	})

	// if we haven't resolved this record before, set to 0
	_, ok := o.goodResolutionMap[fqdn]
	if !ok {
		o.goodResolutionMap[fqdn] = 0
	}

	var resolverStates []bool
	for localProvider, localAddress := range o.resolvers {
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
		"global-resolver-state": fmt.Sprintf("%d/%d", goodResolvers, len(o.resolvers)),
	})

	switch {
	// we've waited awhile and all the records are resolving multiple times, so things are good.
	case o.goodResolutionMap[fqdn] == cfdomainbroker.GoodResolutionCount:
		lsession.Info("stable-dns-resolution")
		return true, nil
	case goodResolvers < len(o.resolvers): // not everything is resolving properly.
		lsession.Info("not-all-resolvers-found-record")
		return false, nil
	case goodResolvers == len(o.resolvers): // not waited long enough but resolution is good.
		lsession.Info("testing-dns-resolution-stability")
		o.goodResolutionMap[fqdn] += 1
		return false, nil
	default: // required by law
		return false, nil
	}
}

// This runs once on startup to see if there are any leftover records which need to resolve.
func (o *ObtainmentManager) continuityRunner() {
	var rebootList []*ProcInfo
	var checkpoints []*ObtainCheckpointModel

	lsession := o.logger.Session("continuity-runner")

	// find the reboots, sort by ascending so we know the most recent one.
	if err := o.db.Model(&rebootList).Order("start asc").Select(); err != nil {
		lsession.Error("db-query-no-reboots", err)
	}

	// if there are no reboots, I guess we're okay?
	if len(rebootList) == 0 {
		o.logger.Info("db-no-known-reboots")
		return
	}

	// find any unsolved challenges from before the reboot.
	if err := o.db.Model(&checkpoints).Where("last_updated < ?", rebootList[0]).Where("state < ?", PostSolve).Select(); err != nil {
		if notFound(err) {
			o.logger.Info("db-no-pre-restart-records-found")
			return
		}
		lsession.Error("db-query-pre-restart-records", err)
		return
	}

	// for each challenge we need to solve, verify the state and then send it to the right place.
	// todo (mxplusb): this needs to be fixed with a real state machine.
	for idx := range checkpoints {
		switch checkpoints[idx].State {
		case State(PreOrder):
			err := fmt.Errorf("service instance cannot be rehydrated, please recreate the service")
			lsession.Error("cannot-rehydrate-service-instance", err)
			return
		// the certificate is on order, go get it's auth.
		case State(Ordered):
			o.RequestRouter <- GetCertificateForOrderRequest{InstanceId: checkpoints[idx].InstanceId}
			return
		// ready for it's first attempt at solving.
		case State(Authorized):
			o.RequestRouter <- SolveRequest{InstanceId: checkpoints[idx].InstanceId}
			return
		// started the solver last time, didn't finish.
		case State(PreSolve):
			o.RequestRouter <- SolveRequest{InstanceId: checkpoints[idx].InstanceId}
			return
		}
	}
}

// Request a certificate be obtained from ACME.
type ObtainRequest struct {
	certificate.ObtainRequest
	Context    context.Context
	InstanceId string
	Response   chan ObtainResponse
}

// The response object.
// todo (mxplusb): update with response object.
type ObtainResponse struct {
	InstanceId string
	Error      error
	Ok         bool
}

func (o *ObtainmentManager) obtainRunner() {
	go func() {
		for {
			msg := <-o.obtainRequest
			go o.obtain(msg)
		}
	}()
}

func (o *ObtainmentManager) obtain(request ObtainRequest) {
	lsession := o.logger.Session("obtain", lager.Data{
		"instance-id": request.InstanceId,
	})

	if len(request.Domains) == 0 {
		err := errors.New("domains are empty")
		lsession.Error("check-empty-domain-value", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				Context:      request.Context,
				InstanceId:   request.InstanceId,
				CurrentState: Provisioning,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
	}

	_, err := o.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		lsession.Error("registration-failure", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				Context:      request.Context,
				InstanceId:   request.InstanceId,
				CurrentState: Provisioning,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ObtainResponse{
				Error:      err,
				Ok:         false,
				InstanceId: request.InstanceId,
			}
		}
		return
	}

	// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.4
	// todo (mxplusb): pop and push this instead of reassignment.
	var sanitizedDomains []string
	for _, domain := range request.Domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			lerr := fmt.Errorf("skip domain %q: unable to sanitize (punnycode): %v", domain, err)
			lsession.Error("sanitization-failure", lerr)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					Context:      request.Context,
					InstanceId:   request.InstanceId,
					CurrentState: Provisioning,
					DesiredState: Error,
					ErrorMessage: lerr.Error(),
					Response:     nil,
				},
			}
			if request.Response != nil {
				request.Response <- ObtainResponse{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				}
			}
			return
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	request.Domains = sanitizedDomains

	if request.Bundle {
		lsession.Info("obtaining-bundled-san-certificate", lager.Data{
			"domains": strings.Join(sanitizedDomains, ","),
		})
	} else {
		lsession.Info("obtaining-san-certificate", lager.Data{
			"domains": strings.Join(sanitizedDomains, ","),
		})
	}

	// make our first checkpoint.
	obtainRequestCheckpoint := ObtainCheckpointModel{
		ObtainRequest: request,
		State:         PreOrder,
		InstanceId:    request.InstanceId,
	}

	// start a transaction
	tx, err := o.db.Begin()
	if err != nil {
		lsession.Error("error-beginning-transaction", err)
		if request.Response != nil {
			request.Response <- ObtainResponse{
				Error:      err,
				Ok:         false,
				InstanceId: request.InstanceId,
			}
		}
		return
	}

	if err := tx.Update(&obtainRequestCheckpoint); err != nil {
		lsession.Error("create-obtain-request-checkpoint-failure", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				Context:      request.Context,
				InstanceId:   request.InstanceId,
				CurrentState: Provisioning,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- ObtainResponse{
				Error:      err,
				Ok:         false,
				InstanceId: request.InstanceId,
			}
		}
		tx.Rollback()
		return
	}

	// request a state change.
	o.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			Context:      request.Context,
			InstanceId:   request.InstanceId,
			CurrentState: Provisioning,
			DesiredState: PreOrder,
			ErrorMessage: "",
			Response:     nil,
		},
	}

	order, err := o.core.Orders.New(request.Domains)
	if err != nil {
		lsession.Error("new-order-error", err)

		if request.Response != nil {
			request.Response <- ObtainResponse{
				Error:      err,
				Ok:         false,
				InstanceId: request.InstanceId,
			}
		}

		tx.Rollback()
		return
	}

	// make our second checkpoint.
	orderCheckpoint := ObtainCheckpointModel{
		Order:      order,
		InstanceId: request.InstanceId,
		State:      Ordered,
	}
	if err := tx.Update(&orderCheckpoint); err != nil {
		lsession.Error("db-update-order-checkpoint", err)

		if request.Response != nil {
			request.Response <- ObtainResponse{
				Error:      err,
				Ok:         false,
				InstanceId: request.InstanceId,
			}
		}

		tx.Rollback()
		return
	}

	// request a state change.
	o.globalQueueManagerChan <- ManagerRequest{
		InstanceId: request.InstanceId,
		Type:       StateManagerType,
		Payload: StateTransitionRequest{
			Context:      request.Context,
			InstanceId:   request.InstanceId,
			CurrentState: PreOrder,
			DesiredState: Ordered,
			ErrorMessage: "",
			Response:     nil,
		},
	}

	// now that we're done, commit the difference.
	tx.Commit()

	lsession.Info("order-complete")

	o.RequestRouter <- AuthorizationRequest{
		InstanceId: request.InstanceId,
		Order:      order,
	}
	if request.Response != nil {
		request.Response <- ObtainResponse{
			Error:      nil,
			Ok:         true,
			InstanceId: request.InstanceId,
		}
	}

	lsession.Debug("authorization-requested-and-response-sent")
}

type AuthorizationRequest struct {
	Context    context.Context
	Order      acme.ExtendedOrder
	InstanceId string
	Response   chan AuthorizationResponse
}

type AuthorizationResponse struct{ Response }

type authError struct {
	Domain string
	Error  error
}

func (o *ObtainmentManager) authRunner() {
	go func() {
		for {
			msg := <-o.authRequest
			go o.getAuthorizations(msg)
		}
	}()
}

func (o *ObtainmentManager) getAuthorizations(request AuthorizationRequest) {

	lsession := o.logger.Session("get-authorizations", lager.Data{
		"instance-id": request.InstanceId,
	})

	respc, errc := make(chan acme.Authorization, 150), make(chan authError, 150)

	// in the case there are some nil values.
	// theoretically this should never kick off, but you never know.
	// inspections are disabled because of the recovery functionality.
	//defer func(l lager.Logger, request AuthorizationRequest) {
	//	if r := recover(); r != nil {
	//		//noinspection GoErrorStringFormat
	//		l.Error("fatality!", errors.New("fatality when trying to get an auth request, is there a nil value?"), lager.Data{
	//			"payload": request,
	//		})
	//	}
	//}(lsession, request)

	// this most likely means the request came in after a reboot, so we need to rehydrate state
	if request.Order.Authorizations == nil {
		if err := o.db.Model(&acme.Order{}).Where("instance_id = ?", request.InstanceId).First(); err != nil {
			if notFound(err) {
				lsession.Error("authorization-not-found", err)
				if request.Response != nil {
					request.Response <- AuthorizationResponse{
						Response{
							InstanceId: request.InstanceId,
							Error:      err,
							Ok:         false,
							NotFound:   true,
						},
					}
				}

				o.globalQueueManagerChan <- ManagerRequest{
					InstanceId: request.InstanceId,
					Type:       StateManagerType,
					Payload: StateTransitionRequest{
						Context:      request.Context,
						InstanceId:   request.InstanceId,
						CurrentState: Unknown,
						DesiredState: Error,
						ErrorMessage: err.Error(),
						Response:     nil,
					},
				}

				return
			}

			lsession.Error("db-authorization-query-error", err)

			if request.Response != nil {
				request.Response <- AuthorizationResponse{
					Response{
						Error:      err,
						Ok:         false,
						InstanceId: request.InstanceId,
					},
				}
			}

			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					Context:      request.Context,
					InstanceId:   request.InstanceId,
					CurrentState: Unknown,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}

			return
		}
	}

	for idx := range request.Order.Authorizations {
		go func(authzUrl string) {
			o.limiter.Take()
			authz, err := o.core.Authorizations.Get(authzUrl)
			if err != nil {
				lsession.Error("get-authorization-failure", err, lager.Data{
					"response": authz,
				})
				errc <- authError{
					Domain: authz.Identifier.Value,
					Error:  err,
				}
				return
			}
			respc <- authz
		}(request.Order.Authorizations[idx])
	}

	var responses []acme.Authorization
	for i := 0; i < len(request.Order.Authorizations); i++ {
		select {
		case err := <-errc: // it doesn't matter how many errors there are, die on the first one.

			lsession.Error("authorization-request", err.Error)

			if request.Response != nil {
				request.Response <- AuthorizationResponse{
					Response{
						Error:      err.Error,
						Ok:         false,
						InstanceId: request.InstanceId,
					},
				}
			}
			return
		case resp := <-respc:
			responses = append(responses, resp)
		}
	}

	// being a transaction
	tx, err := o.db.Begin()
	if err != nil {
		if request.Response != nil {
			request.Response <- AuthorizationResponse{
				Response{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				},
			}
		}
		return
	}

	// todo (mxplusb): fix state manager integration here
	var obtainCheckpoint ObtainCheckpointModel
	if err := o.db.Model(&obtainCheckpoint).Where("instance_id = ?", request.InstanceId).Select(); err != nil {
		lsession.Error("find-pre-authorization-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Authorized,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- AuthorizationResponse{
				Response{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				},
			}
		}

		tx.Rollback()
		return
	}

	obtainCheckpoint.State = Authorized
	obtainCheckpoint.Order = request.Order
	obtainCheckpoint.Authorizations = responses

	if err := tx.Update(&obtainCheckpoint); err != nil {
		lsession.Error("save-authorizations", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Authorized,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- AuthorizationResponse{
				Response{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				},
			}
		}
		tx.Rollback()
		return
	}

	// todo (mxplusb): add state manager integration
	if err := tx.Update(&obtainCheckpoint); err != nil {
		lsession.Error("save-post-authorization-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Authorized,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- AuthorizationResponse{
				Response{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				},
			}
		}
		tx.Rollback()
		return
	}

	// save our state.
	if err := tx.Commit(); err != nil {
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Authorized,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		if request.Response != nil {
			request.Response <- AuthorizationResponse{
				Response{
					Error:      err,
					Ok:         false,
					InstanceId: request.InstanceId,
				},
			}
		}
		tx.Rollback()
		return
	}

	// todo (mxplusb): pass this through the state manager.

	o.RequestRouter <- SolveRequest{InstanceId: request.InstanceId}
}

// Try and solve an ACME challenge.
// No response is needed since it's just a verification step, no data is added or lost because of this.
type SolveRequest struct {
	Context    context.Context
	InstanceId string
}

func (o *ObtainmentManager) solveRunner() {
	go func() {
		for {
			msg := <-o.solveRequest
			go o.solve(msg)
		}
	}()
}

// this is our fundamentally blocking section.
func (o *ObtainmentManager) solve(request SolveRequest) {

	lsession := o.logger.Session("solve", lager.Data{
		"instance-id": request.InstanceId,
	})

	// begin our transaction
	tx, err := o.db.Begin()
	if err != nil {
		lsession.Error("error-beginning-transaction", err)
		return
	}

	var obtainCheckpoint ObtainCheckpointModel
	if err := tx.Model(&obtainCheckpoint).Where("instance_id = ?", request.InstanceId).Select(); err != nil {
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Authorized,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// update our state.
	obtainCheckpoint.State = PreSolve

	// todo (mxplusb): add state manager integration.
	if err := tx.Update(&obtainCheckpoint); err != nil {
		lsession.Error("cannot-update-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PreSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// add the nameserver resolvers to the dns provider.
	var nameservers []string
	for k := range o.resolvers {
		nameservers = append(nameservers, o.resolvers[k])
	}
	o.logger.Debug("using-nameservers", lager.Data{
		"nameservers": nameservers,
	})

	if o.settings.PersistentDnsProvider == true {
		respc := make(chan ElbResponse, 1)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       WorkerManagerType,
			Payload: ElbRequest{
				InstanceId: request.InstanceId,
				Response:   respc,
			},
		}

		resp := <-respc // wait for the ELb response to block.
		sbdnspSettings := &ServiceBrokerDnsProviderSettings{
			Db:         o.settings.Db,
			Logger:     o.logger,
			InstanceId: request.InstanceId,
			ELBTarget:  *(resp.Elb.DNSName),
		}

		// we store the elb reference here and now so it can be referenced at upload time, after the certificate has
		// been created. we have to do this now instead of after the certificate was provisioned because we need to give
		// customers the target CNAME value.
		var localDomainRoute DomainRouteModel
		if err := o.db.Model(&localDomainRoute).Where("instance_id = ?", request.InstanceId).Select(); err != nil {
			lsession.Error("cannot-find-domain-route-reference", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PreSolve,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			return
		}

		localDomainRoute.ElbArn = *(resp.Elb.LoadBalancerArn)
		if err := o.db.Update(localDomainRoute); err != nil {
			lsession.Error("cannot-update-domain-route-reference", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PreSolve,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			return
		}

		if err := o.client.Challenge.SetDNS01Provider(
			NewServiceBrokerDNSProvider(sbdnspSettings),
			dns01.AddRecursiveNameservers(nameservers),
			dns01.WrapPreCheck(o.preCheck),
		); err != nil {
			lsession.Error("acme-client-set-dns-provider", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PreSolve,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}
	}

	// commit now because we are starting the solving process.
	tx.Commit()
	tx, err = o.db.Begin()
	if err != nil {
		lsession.Error("cannot-begin-transaction", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PreSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// this will start the blocking resolve.
	// there is no rollback because it has not been solved.
	// todo (mxplusb): don't forget to implement the deactivations.
	if err := o.client.resolver.Solve(obtainCheckpoint.Authorizations); err != nil {
		lsession.Error("solve", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PreSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// we've solved, past the hard blockers!
	obtainCheckpoint.State = PostSolve

	// we don't rollback a failed save, because the worst case scenario in all of this
	// we have to solve the challenge again, which is totally fine.
	if err := tx.Update(&obtainCheckpoint); err != nil {
		lsession.Error("save-post-solve-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PreSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		return
	}

	// we've verified it's solved.
	tx.Commit()

	// todo (mxplusb): ensure the solved challenges are passed along.
	o.RequestRouter <- GetCertificateForOrderRequest{
		Domains:    obtainCheckpoint.ObtainRequest.Domains,
		Order:      obtainCheckpoint.Order,
		Bundle:     obtainCheckpoint.ObtainRequest.Bundle,
		PrivateKey: obtainCheckpoint.ObtainRequest.PrivateKey,
		MustStaple: false,
		InstanceId: request.InstanceId,
	}
}

// todo (mxplusb): figure out if we need a request
type GetCertificateForOrderRequest struct {
	Domains    []string
	Order      acme.ExtendedOrder
	Bundle     bool
	PrivateKey crypto.PrivateKey
	MustStaple bool
	InstanceId string
}

func (o *ObtainmentManager) getCertificateForOrderRunner() {
	go func() {
		for {
			msg := <-o.solveRequest
			go o.solve(msg)
		}
	}()
}

func (o *ObtainmentManager) getCertificateForOrder(request GetCertificateForOrderRequest) {

	lsession := o.logger.Session("get-certificate-for-order", lager.Data{
		"instance-id": request.InstanceId,
	})

	if request.PrivateKey == nil {
		var err error
		request.PrivateKey, err = certcrypto.GeneratePrivateKey(o.acmeConfig.Certificate.KeyType)
		if err != nil {
			lsession.Error("generate-private-key", err)
			return
		}
	}

	tx, err := o.db.Begin()
	if err != nil {
		lsession.Error("cannot-begin-transaction", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PostSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	var obtainCheckpoint ObtainCheckpointModel
	if err := tx.Model(&obtainCheckpoint).Where("instance_id = ?", request.InstanceId).Select(); err != nil {
		lsession.Error("find-post-solve-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PostSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// Determine certificate name(s) based on the authorization resources
	// todo (mxplusb): figure out how to document this.
	commonName := request.Domains[0]

	// ACME draft Section 7.4 "Applying for CertificateResource Issuance"
	// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
	// says:
	//   Clients SHOULD NOT make any assumptions about the sort order of
	//   "identifiers" or "authorizations" elements in the returned order
	//   object.
	// todo (mxplusb): research this because it's weird.
	san := []string{commonName}
	for _, auth := range request.Order.Identifiers {
		if auth.Value != commonName {
			san = append(san, auth.Value)
		}
	}

	// todo (mxplusb): should the CSR be customizable?
	csr, err := certcrypto.GenerateCSR(request.PrivateKey, commonName, san, request.MustStaple)
	if err != nil {
		lsession.Error("generate-csr", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PostSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		tx.Rollback()
		return
	}

	// update our state
	obtainCheckpoint.State = Finalized
	obtainCheckpoint.CSR = csr
	if err := tx.Update(&obtainCheckpoint); err != nil {
		lsession.Error("db-save-pre-csr-checkpoint", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PostSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		return
	}

	orderResp, err := o.client.core.Orders.UpdateForCSR(request.Order.Finalize, csr)
	if err != nil {
		lsession.Error("finalize-order", err)
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: PostSolve,
				DesiredState: Error,
				ErrorMessage: err.Error(),
				Response:     nil,
			},
		}
		return
	}

	certResource := &certificate.Resource{
		Domain:     commonName,
		CertURL:    orderResp.Certificate,
		PrivateKey: certcrypto.PEMEncode(request.PrivateKey),
	}

	// if we don't have to wait, why not?
	if orderResp.Status == acme.StatusValid {
		checkRespc := make(chan CheckACMEResponseResult, 1)
		o.checkACMEResponseRequest <- CheckACMEResponseRequest{
			Order:      orderResp,
			Bundle:     request.Bundle,
			InstanceId: request.InstanceId,
			Response:   checkRespc,
		}
		resp := <-checkRespc
		if resp.Error != nil {
			lsession.Error("acme-order-status", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PostSolve,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			return
		}
		if resp.Ok {
			o.certificateReadyRequest <- CertificateReadyRequest{
				Op:                  Store,
				InstanceId:          request.InstanceId,
				CertificateResource: certResource,
			}
		}
	}

	ticker := time.NewTicker(time.Second * 1)
	timeout := time.NewTimer(time.Second * 60)

	for {
		select {
		case <-timeout.C:
			err := errors.New("acme took too long to issue certificate")
			lsession.Error("acme-order-status", err)
			return // "I want to break free" -Freddie Mercury
		case <-ticker.C:
			checkRespc := make(chan CheckACMEResponseResult, 1)
			o.checkACMEResponseRequest <- CheckACMEResponseRequest{
				Order:      orderResp,
				Bundle:     request.Bundle,
				InstanceId: request.InstanceId,
				Response:   checkRespc,
			}
			resp := <-checkRespc
			if resp.Error != nil {
				lsession.Error("acme-order-status", err)
				return
			}
			if resp.Ok {
				o.certificateReadyRequest <- CertificateReadyRequest{
					Op:                  Store,
					InstanceId:          request.InstanceId,
					CertificateResource: certResource,
				}
				return
			}
		}
	}
}

// Check with the ACME server to ensure the thing?
type CheckACMEResponseRequest struct {
	Order      acme.Order
	Bundle     bool
	InstanceId string
	Response   chan CheckACMEResponseResult
}

type CheckACMEResponseResult struct {
	Ok                  bool
	CertificateResource *certificate.Resource
	Error               error
}

func (o *ObtainmentManager) checkResponseRunner() {
	go func() {
		for {
			msg := <-o.checkACMEResponseRequest
			go o.checkResponse(msg)
		}
	}()
}

func (o *ObtainmentManager) checkResponse(request CheckACMEResponseRequest) {

	lsession := o.logger.Session("check-response")

	_, err := o.checkOrderStatus(request.Order)
	if err != nil {
		lsession.Error("acme-invalid-status", err)
		request.Response <- CheckACMEResponseResult{
			Ok:    false,
			Error: err,
		}
		return
	}

	cert, issuer, err := o.client.core.Certificates.Get(request.Order.Certificate, request.Bundle)
	if err != nil {
		lsession.Error("acme-get-certificate", err)
		request.Response <- CheckACMEResponseResult{
			Ok:    false,
			Error: err,
		}
		return
	}

	lsession.Info("acme-responded-with-certificate", lager.Data{
		"certificate": request.Order.Certificate,
	})

	request.Response <- CheckACMEResponseResult{
		Ok: true,
		CertificateResource: &certificate.Resource{
			CertURL:           request.Order.Certificate,
			CertStableURL:     request.Order.Certificate,
			Certificate:       cert,
			IssuerCertificate: issuer,
		},
		Error: nil,
	}
}

func (o *ObtainmentManager) checkOrderStatus(order acme.Order) (bool, error) {
	switch order.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusInvalid:
		return false, order.Error
	default:
		return false, nil
	}
}

type CertificateReadyRequest struct {
	Context             context.Context
	CertificateResource *certificate.Resource
	Op                  Op
	InstanceId          string
	Response            chan CertificateReadyResponse
}

type CertificateReadyResponse struct {
	InstanceId  string
	Ready       bool
	Error       error
	Certificate *certificate.Resource
}

func (o *ObtainmentManager) certificateReadyRunner() {
	go func() {
		for {
			msg := <-o.certificateReadyRequest
			go o.certificateReady(msg)
		}
	}()
}

// Handle the certificate operations.
func (o *ObtainmentManager) certificateReady(request CertificateReadyRequest) {

	lsession := o.logger.Session("certificate-ready", lager.Data{
		"instance-id": request.InstanceId,
	})

	switch request.Op {
	case Load:
		var cert certificate.Resource
		if err := o.db.Model(&cert).Where("instance_id = ?", request.InstanceId).First(); err != nil {
			lsession.Error("fetch-certificate", err)
			if request.Response != nil {
				request.Response <- CertificateReadyResponse{
					Error:       err,
					Certificate: &certificate.Resource{},
				}
			}
			return
		}
		if request.Response != nil {
			request.Response <- CertificateReadyResponse{
				InstanceId:  request.InstanceId,
				Certificate: &cert,
				Error:       nil,
				Ready:       true,
			}
		}
	case Store: // todo (mxplusb): add state manager integration.
		tx, err := o.db.Begin()
		if err != nil {
			lsession.Error("cannot-begin-transaction", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: Finalized,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}

		var obtainCheckpoint ObtainCheckpointModel
		if err := tx.Model(&obtainCheckpoint).Where("instance_id = ?", request.InstanceId).First(); err != nil {
			lsession.Error("db-find-post-solve-checkpoint", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: Finalized,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}

		localCert := Certificate{
			InstanceId: request.InstanceId,
			Resource:   request.CertificateResource,
		}
		if err := tx.Update(&localCert); err != nil {
			lsession.Error("db-save-certificate", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: Finalized,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}
		obtainCheckpoint.State = CertificateReady
		if err := tx.Update(&obtainCheckpoint); err != nil {
			lsession.Error("db-save-certificate-ready", err)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: Finalized,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}

		if err := tx.Commit(); err != nil {
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: Finalized,
					DesiredState: Error,
					ErrorMessage: err.Error(),
					Response:     nil,
				},
			}
			tx.Rollback()
			return
		}
		o.globalQueueManagerChan <- ManagerRequest{
			InstanceId: request.InstanceId,
			Type:       StateManagerType,
			Payload: StateTransitionRequest{
				InstanceId:   request.InstanceId,
				CurrentState: Finalized,
				DesiredState: CertificateReady,
				ErrorMessage: "",
				Response:     nil,
			},
		}
	}
}
