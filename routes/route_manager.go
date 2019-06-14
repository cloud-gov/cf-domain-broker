package routes

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"code.cloudfoundry.org/lager"
	cf_domain_broker "github.com/18f/cf-domain-broker"
	le_providers "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/jinzhu/gorm"
)

// RouteManager is the worker for managing custom domains.
// todo (mxplusb): add rate limiter to prevent rate limiting issues with ACME.
type RouteManager struct {
	// Internal database.
	Db *gorm.DB

	// Inherited from main.
	Logger lager.Logger

	// Global settings from the environment.
	Settings types.Settings

	// AWS IAM.
	IamSvc iamiface.IAMAPI

	// AWS CloudFront.
	CloudFrontSvc cloudfrontiface.CloudFrontAPI

	// AWS ELBv2
	ElbSvc elbv2iface.ELBV2API

	// dns challenger
	Dns le_providers.ServiceBrokerDNSProvider

	// ACME Client, used mostly for testing.
	AcmeHttpClient *http.Client

	// DNS Resolvers
	Resolvers map[string]string

	// list of available ELBs
	elbs []*elb

	// locker
	locker sync.RWMutex
}

// internal holder for needed information about an elb to prevent nested round trips.
type elb struct {
	lb              *elbv2.LoadBalancer
	certsOnListener int
}

// todo (mxplusb): prolly test this before the broker code.
func NewManager(logger lager.Logger, iam iamiface.IAMAPI, cloudFront cloudfrontiface.CloudFrontAPI, elbSvc elbv2iface.ELBV2API, settings types.Settings, db *gorm.DB) RouteManager {
	return RouteManager{
		Logger:        logger,
		IamSvc:        iam,
		CloudFrontSvc: cloudFront,
		Settings:      settings,
		Db:            db,
		ElbSvc:        elbSvc,
		Dns: le_providers.ServiceBrokerDNSProvider{
			Handler: make(chan le_providers.DomainMessenger, 10),
			Db:      db,
		},
	}
}

// Create a new custom domain.
// todo (mxplusb): add hook for creating a CDN instance.
func (r *RouteManager) Create(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions, tags map[string]string) (*models.DomainRoute, error) {
	lsession := r.Logger.Session("create-route", lager.Data{
		"instance-id": instanceId,
		"domains":     domainOpts.Domains,
	})

	// generate a new key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		lsession.Error("rsa-generate-key", err)
		return &models.DomainRoute{}, err
	}
	lsession.Debug("rsa-key-generated")

	// build the user with the new key, instantiate a client
	user := models.UserData{
		Email:      r.Settings.Email,
		PublicKey:  key.Public(),
		PrivateKey: key,
	}

	conf := lego.NewConfig(&user)
	conf.CADirURL = r.Settings.AcmeUrl

	acmeClient, err := le_providers.NewAcmeClient(nil, r.Resolvers, conf, r.Dns, r.Logger)
	if err != nil {
		lsession.Error("acme-new-client", err)
		return &models.DomainRoute{}, err
	}
	lsession.Debug("acme-client-instantiated")

	lsession.Debug("acme-dns-provider-assigned")

	// create the route struct and add the user reference.
	localRoute := &models.DomainRoute{
		InstanceId: instanceId,
		State:      cf_domain_broker.Provisioning,
		User:       user,
	}

	// register our user resource.
	reg, err := acmeClient.Client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	user.Registration = reg
	lsession.Debug("acme-user-registered")

	// store the certificate and elb info the database.
	if err := r.Db.Save(localRoute).Error; err != nil {
		lsession.Error("db-save-route", err)
		return &models.DomainRoute{}, err
	}

	// make the certificate request.
	request := certificate.ObtainRequest{
		Domains: domainOpts.Domains,
		Bundle:  true,
	}

	// get the certificate.
	cert, err := acmeClient.Client.Certificate.Obtain(request)
	if err != nil {
		lsession.Error("acme-certificate-obtain", err)
		return &models.DomainRoute{}, err
	}
	localRoute.Certificate = cert
	lsession.Info("certificate-obtained")

	// find the least assigned ELB to assign the route to.
	var targetElb *elbv2.LoadBalancer
	var leastAssigned = 0
	for idx := range r.elbs {
		if r.elbs[idx].certsOnListener <= leastAssigned {
			targetElb = r.elbs[idx].lb
		}
	}
	lsession.Debug("least-assigned-found", lager.Data{
		"elb-target": *targetElb.LoadBalancerArn,
	})

	// save the ELB arn.
	localRoute.ELBArn = *targetElb.LoadBalancerArn

	// generate the necessary input.
	certUploadInput := &iam.UploadServerCertificateInput{}
	certUploadInput.SetCertificateBody(string(localRoute.Certificate.Certificate))
	certUploadInput.SetPrivateKey(string(localRoute.Certificate.PrivateKey))
	certUploadInput.SetServerCertificateName(fmt.Sprintf("cf-domain-%s", instanceId))

	// upload the certificate.
	certArn, err := r.IamSvc.UploadServerCertificate(certUploadInput)
	if err != nil {
		lsession.Error("iam-upload-server-certificate", err)
		return &models.DomainRoute{}, err
	}
	lsession.Info("certificate-uploaded-to-iam")

	// grab the listeners.
	listeners, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
		LoadBalancerArn: targetElb.LoadBalancerArn,
	})
	if err != nil {
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
	lsession.Debug("found-https-listener", lager.Data{
		"listener-arn": *targetListenArn,
	})

	// store the listener arn reference.
	localRoute.ListenerArn = *targetListenArn

	// upload the certificate to the listener.
	if _, err := r.ElbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
		ListenerArn: targetListenArn,
		Certificates: []*elbv2.Certificate{
			{
				// I really hate the AWS string dereferencing to create a reference.
				CertificateArn: aws.String(*certArn.ServerCertificateMetadata.Arn),
			},
		},
	}); err != nil {
		lsession.Error("elbsvc-add-listener-certificates", err)
		return &models.DomainRoute{}, err
	}
	lsession.Info("certificate-uploaded-to-elb")

	// since it's been uploaded to the elb, it's done.
	localRoute.State = cf_domain_broker.Provisioned

	// store the certificate and elb info the database.
	if err := r.Db.Save(localRoute).Error; err != nil {
		lsession.Error("db-save-route", err)
		return &models.DomainRoute{}, err
	}

	return localRoute, nil
}

// Update is not supported yet.
func (*RouteManager) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
	return nil
}

// Get the instance by it's instance ID.
func (r *RouteManager) Get(instanceId string) (models.DomainRoute, error) {
	lsession := r.Logger.Session("get-instance", lager.Data{
		"instance-id": instanceId,
	})

	var localRoute models.DomainRoute
	if err := r.Db.Find(&localRoute, &models.DomainRoute{InstanceId: instanceId}).Error; err != nil {
		switch {
		case gorm.IsRecordNotFoundError(err):
			lsession.Error("db-record-not-found", err)
			return models.DomainRoute{}, nil
		}
		lsession.Error("db-find-instance-id", err)
		return models.DomainRoute{}, err
	}
	lsession.Info("found-instance")

	return localRoute, nil
}

func (*RouteManager) Poll(route *models.DomainRoute) error {
	panic("implement me")
}

func (*RouteManager) Disable(route *models.DomainRoute) error {
	panic("implement me")
}

func (*RouteManager) Renew(route *models.DomainRoute) error {
	panic("implement me")
}

func (r *RouteManager) RenewAll() {
	lsession := r.Logger.Session("renew-all")

	rows, err := r.scanner(models.DomainRoute{})
	if err != nil {
		lsession.Error("scanner-error", err)
	}

	// for every row
	for rows.Next() {

		// search for the certificate or skip from errors.
		var localRoute models.DomainRoute
		if err := r.Db.ScanRows(rows, &localRoute); err != nil {
			lsession.Error("db-scan-rows", err)
			continue
		}

		// generate a client or skip from errors.
		acmeClient, err := lego.NewClient(lego.NewConfig(localRoute.User))
		if err != nil {
			lsession.Error("acme-new-client", err)
			continue
		}

		// renew the cert or skip from errors.
		newCert, err := acmeClient.Certificate.Renew(*localRoute.Certificate, true, false)
		if err != nil {
			lsession.Error("acme-renew-certificate", err)
			continue
		}
		localRoute.Certificate = newCert

		if err := r.Db.Save(localRoute).Error; err != nil {
			lsession.Error("db-save", err)
		}
	}
}

func (*RouteManager) DeleteOrphanedCerts() {
	panic("implement me")
}

// GetDNSInstructions gets the stored DNS instructions from a given
func (r *RouteManager) GetDNSInstructions(route *models.DomainRoute) (le_providers.DomainMessenger, error) {
	lsession := r.Logger.Session("get-dns-instructions", lager.Data{
		"instance-id": route.InstanceId,
	})

	var domainMessage le_providers.DomainMessenger
	if errs := r.Db.Where("domain like ?", route.DomainExternal).First(&domainMessage).GetErrors(); len(errs) > 0 {
		var errStrs []string
		for idx := range errs {
			errStrs = append(errStrs, errs[idx].Error())
		}
		err := errors.New(strings.Join(errStrs, ","))
		lsession.Error("db-like-domain", err, lager.Data{
			"external-domain": route.DomainExternal,
			"internal-domain": route.DomainInternal,
		})
	}
	lsession.Info("found-domain-token")

	return domainMessage, nil
}

func (*RouteManager) Populate() error {
	panic("implement me")
}

// UpdateElbs is a cron job designed to keep the internal ELB references up-to-date so we don't need to store the info
// in a database and we can just reference it as needed. This should be run at least once a minute.
func (r *RouteManager) UpdateElbs() {
	lsession := r.Logger.Session("update-elbs")

	if err := r.ElbSvc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancers {
				if *lb.Scheme != elbv2.LoadBalancerSchemeEnumInternetFacing {
					continue
				}
				if strings.HasPrefix(*lb.LoadBalancerName, r.Settings.ALBPrefix) {
					// populate the internal struct
					localElb := new(elb)
					localElb.lb = lb

					// grab the listeners.
					listeners, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
						LoadBalancerArn: localElb.lb.LoadBalancerArn,
					})
					if err != nil {
						lsession.Error("describe-listeners", err)
					}
					localElb.certsOnListener = len(listeners.Listeners)

					// lock to prevent updates elsewhere and make it threadsafe.
					r.locker.Lock()
					r.elbs = append(r.elbs, localElb)
					r.locker.Unlock()
				}
			}
			return true
		},
	); err != nil {
		lsession.Error("describe-load-balancers-pages", err)
	}
}

// Grabs all rows from a given model.
func (r *RouteManager) scanner(model interface{}) (*sql.Rows, error) {
	rows, err := r.Db.Model(&model).Where("instance_id = *").Select("*").Rows()
	if err != nil {
		return nil, nil
	}
	return rows, nil
}
