// Chunks of this file are using MIT licensed code.
// It is being relicensed as public domain as part of this work but credit and copyright is due to the original author.
// The original code can be found here: https://github.com/go-acme/lego

package managers

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/jinzhu/gorm"
	"github.com/miekg/dns"
	"go.uber.org/ratelimit"
	"golang.org/x/net/idna"
)

type ObtainmentResovler interface {
	Solve(authorizations []acme.Authorization) error
}

// The checkpoint state of a provisioning certificate
type ObtainCheckpoint struct {
	gorm.Model
	ObtainRequest  ObtainRequest
	Order          acme.ExtendedOrder
	State          State
	Authorizations []acme.Authorization
	CSR            []byte
	InstanceId     string `gorm:"primary_key"`
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

// Configuration options for the Obtainment Manager.
type ObtainmentManagerSettings struct {
	// Automatically start all the runners.
	Autostart bool
	// ACME server.
	ACMEConfig *lego.Config
	// Database connection we can use to store the checkpointed steps.
	Db *gorm.DB
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
	obtainErrors                  map[string]error
	acmeConfig                    *lego.Config
	core                          *api.Core
	client                        *ACMEClient
	restarted                     bool
	db                            *gorm.DB
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
		obtainErrors:                  make(map[string]error),
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
	if err := o.db.AutoMigrate(&ObtainCheckpoint{}, &Certificate{}, &ObtainmentManagerState{}).Error; err != nil {
		return &ObtainmentManager{}, err
	}

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

	// start our listeners/runners
	o.obtainRunner()
	o.authRunner()
	o.solveRunner()
	o.getCertificateForOrderRunner()
	o.checkResponseRunner()
	o.certificateReadyRunner()
	o.continuityRunner()
}

func (o *ObtainmentManager) newClient() error {
	if o.acmeConfig == nil {
		err := errors.New("a configuration must be provided")
		o.logger.Error("nil-client-configuration", err)
		return err
	}

	_, err := url.Parse(o.acmeConfig.CADirURL)
	if err != nil {
		o.logger.Error("acme-url-parse", err)
		return err
	}

	if o.acmeConfig.HTTPClient == nil {
		err := errors.New("the HTTP client cannot be nil")
		o.logger.Error("nil-http-client", err)
		return err
	}

	privateKey := o.acmeConfig.User.GetPrivateKey()
	if privateKey == nil {
		err := errors.New("private key was nil")
		o.logger.Error("nil-private-key", err)
		return err
	}

	var kid string
	if reg := o.acmeConfig.User.GetRegistration(); reg != nil {
		kid = reg.URI
	}

	// create our let's encrypt API client.
	core, err := api.New(http.DefaultClient, "18f/domain-broker-v2", o.acmeConfig.CADirURL, kid, privateKey)
	if err != nil {
		o.logger.Error("new-acme-api-failure", err)
		return err
	}

	solversManager := resolver.NewSolversManager(core)
	prober := resolver.NewProber(solversManager)

	o.client = &ACMEClient{
		Challenge:    solversManager,
		Registration: registration.NewRegistrar(core, o.acmeConfig.User),
		core:         core,
		resolver:     prober,
	}

	return nil
}

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
	var rebootList []ProcInfo
	var checkpoints []ObtainCheckpoint

	// find the reboots, sort by ascending so we know the most recent one.
	results := o.db.Order("start asc").Find(&rebootList)
	if results.Error != nil {
		o.logger.Error("db-query-no-reboots", results.Error)
	}

	// if there are no reboots, I guess we're okay?
	if len(rebootList) == 0 {
		o.logger.Info("db-no-known-reboots")
		return
	}

	// find any unsolved challenges from before the reboot.
	results = o.db.Where("last_updated < ?", rebootList[0]).Where("state < ?", PostSolve).Find(&checkpoints)
	if results.RecordNotFound() {
		o.logger.Info("db-no-pre-restart-records-found")
		return
	}
	if results.Error != nil {
		o.logger.Error("db-query-pre-restart-records", results.Error)
		return
	}

	// for each challenge we need to solve, verify the state and then send it to the right place.
	// todo (mxplusb): this needs to be fixed.
	for idx := range checkpoints {
		switch checkpoints[idx].State {
		case State(PreOrder):
			err := fmt.Errorf("service instance cannot be rehydrated, please recreate the service")
			o.logger.Error("cannot-rehydrate-service-instance", err)
			o.obtainErrors[checkpoints[idx].InstanceId] = err
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

type ObtainRequest struct {
	certificate.ObtainRequest
	Context    context.Context
	InstanceId string
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
	if len(request.Domains) == 0 {
		o.obtainErrors[request.InstanceId] = errors.New("domains are empty")
	}

	_, err := o.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		o.obtainErrors[request.InstanceId] = err
	}

	// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.4
	// todo (mxplusb): pop and push this instead of reassignment.
	var sanitizedDomains []string
	for _, domain := range request.Domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			lerr := fmt.Errorf("skip domain %q: unable to sanitize (punnycode): %v", domain, err)
			o.logger.Error("cannot-sanitize-domain", lerr)
			o.obtainErrors[request.InstanceId] = lerr
			return
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	request.Domains = sanitizedDomains

	if request.Bundle {
		o.logger.Info("obtaining-bundled-san-certificate", lager.Data{
			"domains": strings.Join(sanitizedDomains, ","),
		})
	} else {
		o.logger.Info("obtaining-san-certificate", lager.Data{
			"domains": strings.Join(sanitizedDomains, ","),
		})
	}

	// make our first checkpoint.
	obtainRequestCheckpoint := ObtainCheckpoint{
		ObtainRequest: request,
		State:         PreOrder,
		InstanceId:    request.InstanceId,
	}

	// start a transaction
	tx := o.db.Begin()

	if err := tx.Create(&obtainRequestCheckpoint).Error; err != nil {
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("db-create-obtain-request-checkpoint", err)
		tx.Rollback()
		return
	}

	order, err := o.core.Orders.New(request.Domains)
	if err != nil {
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("new-order-error", err)
		tx.Rollback()
		return
	}

	// make our second checkpoint.
	orderCheckpoint := ObtainCheckpoint{
		Order:      order,
		InstanceId: request.InstanceId,
		State:      Ordered,
	}
	if err := tx.Save(&orderCheckpoint).Error; err != nil {
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("db-update-order-checkpoint", err)
		tx.Rollback()
		return
	}

	// now that we're done, commit the difference.
	tx.Commit()

	o.RequestRouter <- AuthorizationRequest{
		InstanceId: request.InstanceId,
		Order:      order,
	}
}

type AuthorizationRequest struct {
	Context    context.Context
	Order      acme.ExtendedOrder
	InstanceId string
}

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
	respc, errc := make(chan acme.Authorization, 150), make(chan authError, 150)

	// in the case there are some nil values.
	// theoretically this should never kick off, but you never know.
	// inspections are disabled because of the recovery functionality.
	defer func(o *ObtainmentManager, request AuthorizationRequest) {
		if r := recover(); r != nil {
			//noinspection ALL
			o.logger.Error("fatality!", errors.New("fatality when trying to get an auth request, is there a nil value?"), lager.Data{
				"payload": request,
			})
		}
	}(o, request)

	// this most likely means the request came in after a reboot, so we need to rehydrate state
	if request.Order.Authorizations == nil {
		results := o.db.Where("instance_id = ?", request.InstanceId).Find(&request.Order)
		if results.Error != nil {
			if results.RecordNotFound() {
				o.obtainErrors[request.InstanceId] = results.Error
				o.logger.Error("db-authorization-not-found", results.Error)
				return
			}
			o.obtainErrors[request.InstanceId] = results.Error
			o.logger.Error("db-authorization-query-error", results.Error)
			return
		}
	}

	for idx := range request.Order.Authorizations {
		o.limiter.Take()
		go func(authzUrl string) {
			authz, err := o.core.Authorizations.Get(authzUrl)
			if err != nil {
				// parts of this section can be nil
				//noinspection ALL
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
			o.obtainErrors[request.InstanceId] = err.Error
			o.logger.Error("authorization-request", err.Error)
			return
		case resp := <-respc:
			responses = append(responses, resp)
		}
	}

	var ldata lager.Data
	for idx, auth := range request.Order.Authorizations {
		//noinspection ALL
		ldata[request.Order.Identifiers[idx].Value] = auth
	}
	o.logger.Info("auth-urls", ldata)

	// being a transaction
	tx := o.db.Begin()

	var obtainCheckpoint ObtainCheckpoint
	result := tx.Where("instance_id = ?", request.InstanceId).Find(&obtainCheckpoint)
	if result.RecordNotFound() {
		err := errors.New("cannot find existing checkpoint")
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("db-find-pre-authorization-checkpoint", err)
		tx.Rollback()
		return
	} else if result.Error != nil {
		o.obtainErrors[request.InstanceId] = result.Error
		o.logger.Error("db-find-pre-authorization-checkpoint", result.Error)
		tx.Rollback()
		return
	}

	obtainCheckpoint.Authorizations = responses
	obtainCheckpoint.State = Authorized

	if err := tx.Save(obtainCheckpoint); err.Error != nil {
		o.obtainErrors[request.InstanceId] = err.Error
		o.logger.Error("db-save-post-authorization-checkpoint", err.Error)
		tx.Rollback()
		return
	}

	// save our state.
	tx.Commit()

	o.RequestRouter <- SolveRequest{InstanceId: request.InstanceId}
}

// Try and solve an ACME challenge.
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
	tx := o.db.Begin()

	var obtainCheckpoint ObtainCheckpoint
	result := tx.Where("instance_id = ?", request.InstanceId).Find(&obtainCheckpoint)
	if result.RecordNotFound() {
		err := errors.New("cannot find existing checkpoint")
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("db-find-pre-solve-checkpoint", err)
		tx.Rollback()
		return
	} else if result.Error != nil {
		o.obtainErrors[request.InstanceId] = result.Error
		o.logger.Error("db-find-pre-solve-checkpoint", result.Error)
		tx.Rollback()
		return
	}

	obtainCheckpoint.State = PreSolve

	if err := tx.Save(obtainCheckpoint); err.Error != nil {
		o.obtainErrors[request.InstanceId] = err.Error
		o.logger.Error("db-save-pre-solve-checkpoint", err.Error)
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

		resp := <-respc
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
		results := o.db.Where("instance_id = ?", request.InstanceId).Find(&localDomainRoute)
		if results.Error != nil {
			lsession.Error("cannot-find-domain-route-reference", results.Error)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PreSolve,
					DesiredState: Error,
					ErrorMessage: results.Error.Error(),
					Response:     nil,
				},
			}
			return
		}

		localDomainRoute.ElbArn = *(resp.Elb.LoadBalancerArn)
		results = o.db.Update(localDomainRoute)
		if results.Error != nil {
			lsession.Error("cannot-update-domain-route-reference", results.Error)
			o.globalQueueManagerChan <- ManagerRequest{
				InstanceId: request.InstanceId,
				Type:       StateManagerType,
				Payload: StateTransitionRequest{
					InstanceId:   request.InstanceId,
					CurrentState: PreSolve,
					DesiredState: Error,
					ErrorMessage: results.Error.Error(),
					Response:     nil,
				},
			}
			return
		}

		if err := o.client.Challenge.SetDNS01Provider(NewServiceBrokerDNSProvider(sbdnspSettings), dns01.AddRecursiveNameservers(nameservers), dns01.WrapPreCheck(o.preCheck)); err != nil {
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("acme-client-set-dns-provider", err)
			tx.Rollback()
			return
		}
	}

	// commit now because we are starting the solving process.
	tx.Commit()

	// this will start the blocking resolve.
	// there is no rollback because it has not been solved.
	// todo (mxplusb): don't forget to implement the deactivations.
	if err := o.client.resolver.Solve(obtainCheckpoint.Authorizations); err != nil {
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("solve", err)
		return
	}

	obtainCheckpoint.State = PostSolve

	// we don't rollback a failed save, because the worst case scenario in all of this
	// we have to solve the challenge again, which is totally fine.
	if err := tx.Save(obtainCheckpoint); err.Error != nil {
		o.obtainErrors[request.InstanceId] = err.Error
		o.logger.Error("db-save-post-solve-checkpoint", err.Error)
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
	if request.PrivateKey == nil {
		var err error
		request.PrivateKey, err = certcrypto.GeneratePrivateKey(o.acmeConfig.Certificate.KeyType)
		if err != nil {
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("generate-private-key", err)
			return
		}
	}

	tx := o.db.Begin()

	var obtainCheckpoint ObtainCheckpoint
	result := tx.Where("instance_id = ?", request.InstanceId).Find(&obtainCheckpoint)
	if result.RecordNotFound() {
		err := errors.New("cannot find existing checkpoint")
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("db-find-post-solve-checkpoint", err)
		tx.Rollback()
		return
	} else if result.Error != nil {
		o.obtainErrors[request.InstanceId] = result.Error
		o.logger.Error("db-find-post-solve-checkpoint", result.Error)
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
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("generate-csr", err)
		return
	}

	obtainCheckpoint.State = Finalized
	obtainCheckpoint.CSR = csr
	if err := tx.Save(obtainCheckpoint); err.Error != nil {
		o.obtainErrors[request.InstanceId] = err.Error
		o.logger.Error("db-save-pre-csr-checkpoint", err.Error)
		return
	}

	orderResp, err := o.client.core.Orders.UpdateForCSR(request.Order.Finalize, csr)
	if err != nil {
		o.obtainErrors[request.InstanceId] = err
		o.logger.Error("finalize-order", err)
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
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("acme-order-status", err)
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
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("acme-order-status", err)
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
				o.obtainErrors[request.InstanceId] = err
				o.logger.Error("acme-order-status", err)
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
		o.obtainErrors[request.InstanceId] = err
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
	switch request.Op {
	case Load:
		var cert certificate.Resource
		result := o.db.Where("instance_id = ?", request.InstanceId).Find(&cert)
		if result.RecordNotFound() {
			err := errors.New("cannot find certificate")
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("db-fetch-certificate", err)
			request.Response <- CertificateReadyResponse{
				Error:       nil,
				Ready:       false,
				Certificate: &certificate.Resource{},
			}
			return
		} else if result.Error != nil {
			o.obtainErrors[request.InstanceId] = result.Error
			o.logger.Error("db-fetch-certificate", result.Error)
			request.Response <- CertificateReadyResponse{
				Error:       result.Error,
				Certificate: &certificate.Resource{},
			}
			return
		}
		request.Response <- CertificateReadyResponse{
			InstanceId:  request.InstanceId,
			Certificate: &cert,
			Error:       nil,
			Ready:       true,
		}
	case Store:
		tx := o.db.Begin()
		var obtainCheckpoint ObtainCheckpoint
		result := tx.Where("instance_id = ?", request.InstanceId).Find(&obtainCheckpoint)
		if result.RecordNotFound() {
			err := errors.New("cannot find existing checkpoint")
			o.obtainErrors[request.InstanceId] = err
			o.logger.Error("db-find-post-solve-checkpoint", err)
			tx.Rollback()
			return
		} else if result.Error != nil {
			o.obtainErrors[request.InstanceId] = result.Error
			o.logger.Error("db-find-post-solve-checkpoint", result.Error)
			tx.Rollback()
			return
		}
		localCert := Certificate{
			InstanceId: request.InstanceId,
			Resource:   request.CertificateResource,
		}
		result = tx.Update(&localCert)
		if result.Error != nil {
			o.obtainErrors[request.InstanceId] = result.Error
			o.logger.Error("db-save-certificate", result.Error)
			tx.Rollback()
			return
		}
		obtainCheckpoint.State = CertificateReady
		result = tx.Update(&obtainCheckpoint)
		if result.Error != nil {
			o.obtainErrors[request.InstanceId] = result.Error
			o.logger.Error("db-save-certificate-ready", result.Error)
			tx.Rollback()
			return
		}

		tx.Commit()
	}
}
