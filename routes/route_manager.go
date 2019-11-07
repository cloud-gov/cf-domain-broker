package routes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/interfaces"
	leproviders "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
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
	CloudFront interfaces.CloudfrontDistributionIface

	// AWS ELBv2
	ElbSvc elbv2iface.ELBV2API

	// dns challenger
	PersistentDnsProvider bool
	DnsChallengeProvider  challenge.Provider

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
func NewManager(logger lager.Logger, iam iamiface.IAMAPI, cloudFront interfaces.CloudfrontDistributionIface, elbSvc elbv2iface.ELBV2API, settings types.Settings, db *gorm.DB, persistentDnsProvider bool) (RouteManager, error) {
	r := RouteManager{
		Logger:                logger,
		IamSvc:                iam,
		CloudFront:            cloudFront,
		Settings:              settings,
		Db:                    db,
		ElbSvc:                elbSvc,
		elbs:                  make([]*elb, 0),
		PersistentDnsProvider: persistentDnsProvider,
	}

	// get a list of elbs.
	resp, err := r.ElbSvc.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		logger.Error("describe-load-balancers", err)
		return RouteManager{}, err
	}

	for idx, _ := range resp.LoadBalancers {
		// nil check because you have to every single time you do anything in aws...
		if resp.LoadBalancers[idx] != nil {
			lresp, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
				LoadBalancerArn: resp.LoadBalancers[idx].LoadBalancerArn,
			})
			if err != nil {
				logger.Error("describe-elb-listeners", err, lager.Data{
					"elb-target-arn": resp.LoadBalancers[idx].LoadBalancerArn,
				})
				return RouteManager{}, err
			}

			var certsOnListener int
			for nidx, _ := range lresp.Listeners {
				if lresp.Listeners[nidx] != nil {
					certsOnListener += len(lresp.Listeners[nidx].Certificates)
				}
			}

			r.elbs = append(r.elbs, &elb{lb: resp.LoadBalancers[idx], certsOnListener: certsOnListener})
		}
	}

	return r, nil
}

// Create a new custom domain.
func (r *RouteManager) Create(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions, tags map[string]string) (*models.DomainRoute, error) {
	lsession := r.Logger.Session("create-route", lager.Data{
		"instance-id": instanceId,
		"domains":     domainOpts.Domains,
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

	if r.AcmeHttpClient == nil {
		r.AcmeHttpClient = http.DefaultClient
	}

	// if we need to store the challenge for later upstream, create a new provider.
	if r.PersistentDnsProvider == true {
		r.DnsChallengeProvider = leproviders.NewServiceBrokerDNSProvider(r.Db, r.Logger, instanceId)
	}

	acmeClient, err := leproviders.NewAcmeClient(r.AcmeHttpClient, r.Resolvers, conf, r.DnsChallengeProvider, r.Logger, instanceId)
	if err != nil {
		lsession.Error("acme-new-client", err)
		return &models.DomainRoute{}, err
	}
	lsession.Debug("acme-client-instantiated")

	r.AcmeHttpClient = acmeClient.AcmeConfig.HTTPClient

	if len(domainOpts.Domains) > 0 {
		lsession.Debug("acme-dns-provider-assigned")
		// create the route struct and add the user reference.
		localDomainRoute := &models.DomainRoute{
			InstanceId:     instanceId,
			State:          cfdomainbroker.Provisioning,
			User:           user,
			DomainExternal: domainOpts.Domains,
		}

		// register our user resource.
		reg, err := acmeClient.Client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		user.Registration = reg
		lsession.Debug("acme-user-registered")

		// store the certificate and elb info the database.
		// check for debug.
		if r.Settings.LogLevel == 1 {
			if err := r.Db.Debug().Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-debug-save-route", err)
				return &models.DomainRoute{}, err
			}
		} else {
			if err := r.Db.Create(&localDomainRoute).Error; err != nil {
				lsession.Error("db-save-route", err)
				return &models.DomainRoute{}, err
			}
		}
		lsession.Info("db-route-saved")

		var domains []string
		for i := 0; i < len(domainOpts.Domains); i++ {
			domains = append(domains, domainOpts.Domains[i].Value)
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
			return &models.DomainRoute{}, err
		}
		lsession.Info("certificate-obtained")

		localCert := models.Certificate{
			InstanceId: instanceId,
			Resource:   cert,
		}

		if r.Settings.LogLevel == 1 {
			if err := r.Db.Debug().Create(&localCert).Error; err != nil {
				lsession.Error("db-save-certificate", err)
				return &models.DomainRoute{}, nil
			}
		} else {
			if err := r.Db.Create(&localCert).Error; err != nil {
				lsession.Error("db-save-certificate", err)
				return &models.DomainRoute{}, nil
			}
		}
		lsession.Info("db-certificate-stored")

		// find the least assigned ELB to assign the route to.
		var targetElb *elbv2.LoadBalancer
		leastAssigned := 0
		for idx := range r.elbs {
			if r.elbs[idx].certsOnListener >= leastAssigned {
				targetElb = r.elbs[idx].lb
				leastAssigned = r.elbs[idx].certsOnListener
			}
		}
		lsession.Debug("least-assigned-found", lager.Data{
			"elb-target": &targetElb.LoadBalancerArn,
		})

		// save the ELB arn.
		localDomainRoute.ELBArn = *targetElb.LoadBalancerArn

		// generate the necessary input.
		certUploadInput := &iam.UploadServerCertificateInput{}
		certUploadInput.SetCertificateBody(string(localCert.Resource.Certificate))
		certUploadInput.SetPrivateKey(string(localCert.Resource.PrivateKey))
		certUploadInput.SetServerCertificateName(fmt.Sprintf("cf-domain-%s", instanceId))

		// upload the certificate.
		certArn, err := r.IamSvc.UploadServerCertificate(certUploadInput)
		if err != nil {
			lsession.Error("iam-upload-server-certificate", err)
			return &models.DomainRoute{}, err
		}
		lsession.Info("certificate-uploaded-to-iam")

		//save cert ARN
		localCert.ARN = *certArn.ServerCertificateMetadata.Arn

		// grab the listeners.
		listeners, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
			LoadBalancerArn: targetElb.LoadBalancerArn,
		})
		if err != nil {
			lsession.Error("elbsvc-describe-listeners", err)
			return &models.DomainRoute{}, err
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
			return &models.DomainRoute{}, err
		}

		lsession.Debug("found-https-listener", lager.Data{
			"listener-arn": localDomainRoute.ListenerArn,
		})

		// upload the certificate to the listener.
		if _, err := r.ElbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
			ListenerArn: targetListenArn,
			Certificates: []*elbv2.Certificate{
				{
					CertificateArn: certArn.ServerCertificateMetadata.Arn,
				},
			},
		}); err != nil {
			lsession.Error("elbsvc-add-listener-certificates", err)
			return &models.DomainRoute{}, err
		}
		lsession.Info("certificate-uploaded-to-elb")

		// since it's been uploaded to the elb, it's done.
		localDomainRoute.State = cfdomainbroker.Provisioned

		// store the certificate and elb info the database.
		if err := r.Db.Save(localDomainRoute).Error; err != nil {
			lsession.Error("db-save-route", err)
			return &models.DomainRoute{}, err
		}
		return localDomainRoute, nil

	} else if len(cdnOpts.Domain) > 0 {
		// create the route struct and add the user reference.
		var domain models.Domain
		domain.Value = cdnOpts.Domain
		var domains []models.Domain
		domains = append(domains, domain)

		localCDNRoute := &models.DomainRoute{
			InstanceId:     instanceId,
			State:          cfdomainbroker.Provisioning,
			User:           user,
			DomainExternal: domains,
			Origin:         cdnOpts.Origin,
			Path:           cdnOpts.Path,
			InsecureOrigin: cdnOpts.InsecureOrigin,
		}

		dist, err := r.CloudFront.Create(instanceId, make([]string, 0), cdnOpts.Origin, cdnOpts.Path, cdnOpts.InsecureOrigin, cdnOpts.Headers, cdnOpts.Cookies, tags)
		if err != nil {
			lsession.Error("creating-cloudfront-instance", err)
			return nil, err
		}

		localCDNRoute.DomainInternal = *dist.DomainName
		localCDNRoute.DistributionId = *dist.Id

		if err := r.Db.Create(localCDNRoute).Error; err != nil {
			lsession.Error("db-creating-route", err)
			return nil, err
		}
		return localCDNRoute, nil
	}

	return nil, nil //nothing
}

// Update is not supported yet.
func (r *RouteManager) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
	/*lsession := r.Logger.Session("get-instance", lager.Data{
		"instance-id": instanceId,
	})

	route, err := r.Get(instanceId)
	if err != nil {
		return err
	}

	if domainOpts.Domains[0].Value != "" {
		route.DomainExternal = domainOpts.Domains
	}

	route.State = cfdomainbroker.Provisioning

	if domainOpts.Domains[0].Value != "" {
		user := route.User

		conf := lego.NewConfig(&user)
		conf.CADirURL = r.Settings.AcmeUrl
		conf.HTTPClient = r.AcmeHttpClient

		/*acmeClient, err := leproviders.NewAcmeClient(r.AcmeHttpClient, r.Resolvers, conf, r.DnsChallengeProvider, r.Logger)
		if err != nil {
			lsession.Error("acme-new-client", err)
			return err
		}
		lsession.Debug("acme-client-started")

		route.DNSChallenge = leproviders.DomainMessenger{}

	}*/

	return nil
}

// Get the instance by it's instance ID.
func (r *RouteManager) Get(instanceId string) (*models.DomainRoute, error) {
	lsession := r.Logger.Session("get-instance")

	var localRoute models.DomainRoute
	result := r.Db.First(&localRoute, &models.DomainRoute{InstanceId: instanceId})
	if result.RecordNotFound() {
		lsession.Error("db-record-not-found", apiresponses.ErrInstanceDoesNotExist)
		return &models.DomainRoute{}, apiresponses.ErrInstanceDoesNotExist
	} else if result.Error != nil {
		lsession.Error("db-get-first-route", result.Error)
		return &models.DomainRoute{}, result.Error
	}

	return &localRoute, nil
}

func (r *RouteManager) stillActive(route *models.DomainRoute) error {
	lsession := r.Logger.Session("still-active", lager.Data{
		"instance-id": route.InstanceId,
	})

	lsession.Info("starting-canary-check", lager.Data{
		"route":       route,
		"settings":    r.Settings,
		"instance-id": route.InstanceId,
	})

	session := session.New(aws.NewConfig().WithRegion(r.Settings.AwsDefaultRegion))

	s3client := s3.New(session)

	target := path.Join(".well-known", "acme-challenge", "canary", route.InstanceId)

	input := s3.PutObjectInput{
		Bucket: aws.String(r.Settings.Bucket),
		Key:    aws.String(target),
		Body:   strings.NewReader(route.InstanceId),
	}

	if r.Settings.ServerSideEncryption != "" {
		input.ServerSideEncryption = aws.String(r.Settings.ServerSideEncryption)
	}

	if _, err := s3client.PutObject(&input); err != nil {
		lsession.Error("s3-put-object", err)
		return err
	}

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, domain := range route.GetDomains() {
		resp, err := insecureClient.Get("https://" + path.Join(domain, target))
		if err != nil {
			lsession.Error("insecure-client-get", err)
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lsession.Error("read-response-body", err)
			return err
		}

		if string(body) != route.InstanceId {
			err := fmt.Errorf("Canary check failed for %s: expected %s, got %s", domain, route.InstanceId, string(body))
			lsession.Error("", err)
			return err
		}
	}

	return nil
}

func (r *RouteManager) Poll(route *models.DomainRoute) error {
	lsession := r.Logger.Session("poll", lager.Data{
		"instance-id": route.InstanceId,
	})
	switch route.State {
	case cfdomainbroker.Provisioning:
		lsession.Info("check-provisioning")
		// todo (mxplusb): return the domain messenger value here.
		return nil
	case cfdomainbroker.Deprovisioning:
		lsession.Info("check-deprovisioning")
		// todo (mxplusb): figure out what to do here.
		return nil
	default:
		return nil
	}
}

func (r *RouteManager) updateDeprovisioning(route *models.DomainRoute) error {
	if len(route.DistributionId) > 0 {
		deleted, err := r.CloudFront.Delete(route.DistributionId)
		if err != nil {
			r.Logger.Error("cloudfront-delete", err)
			return err
		}

		if deleted {
			route.State = cfdomainbroker.Deprovisioned
			if err := r.Db.Save(route).Error; err != nil {
				r.Logger.Error("db-saving-delete-state", err)
			}
		}
	}

	return nil
}

func (r *RouteManager) checkDistribution(route *models.DomainRoute) bool {
	dist, err := r.CloudFront.Get(route.DistributionId)
	if err != nil {
		r.Logger.Session("checking-distribution").Error("cloudfront-get", err)
		return false
	}

	return *dist.Status == "Deployed" && *dist.DistributionConfig.Enabled
}

func (r *RouteManager) purgeCertificate(route *models.DomainRoute, cert *models.Certificate) error {
	r.Logger.Info("remove-listener-cert", lager.Data{
		"guid":        route.ID,
		"domains":     route.GetDomains,
		"listenerARN": route.ListenerArn,
		"certARN":     cert.ARN,
	})

	if _, err := r.ElbSvc.RemoveListenerCertificates(&elbv2.RemoveListenerCertificatesInput{
		ListenerArn: aws.String(route.ListenerArn),
		Certificates: []*elbv2.Certificate{
			{CertificateArn: aws.String(cert.ARN)},
		},
	}); err != nil {
		return err
	}

	for {
		r.Logger.Info("deleting-cert", lager.Data{
			"guid":    route.ID,
			"domains": route.GetDomains,
			"name":    route.InstanceId})
		if _, err := r.IamSvc.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
			ServerCertificateName: aws.String(route.InstanceId),
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

	return nil
}

func (r *RouteManager) Disable(route *models.DomainRoute) error {
	lsession := r.Logger.Session("route-manager-disable", lager.Data{
		"instance-id": route.InstanceId,
	})

	lsession.Info("disable-route")

	var localRoute models.DomainRoute
	result := r.Db.First(&localRoute, &models.DomainRoute{InstanceId: route.InstanceId})

	if result.RecordNotFound() {
		lsession.Error("db-route-not-found", result.Error)
		return result.Error
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		return result.Error
	}

	result = r.Db.Delete(&localRoute)

	if result.RecordNotFound() {
		lsession.Error("db-route-not-found", result.Error)
		return result.Error
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		return result.Error
	}

	var localCert models.Certificate
	result = r.Db.First(&localCert, &models.Certificate{InstanceId: route.InstanceId})

	if result.RecordNotFound() {
		lsession.Error("db-certificate-not-found", result.Error)
		return result.Error
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		return result.Error
	}

	if err := r.purgeCertificate(route, &localCert); err != nil {
		lsession.Error("purging-certificate", err)
	}

	result = r.Db.Delete(&localCert)

	if result.RecordNotFound() {
		lsession.Error("db-certificate-not-found", result.Error)
		return result.Error
	} else if result.Error != nil {
		lsession.Error("db-generic-error", result.Error)
		return result.Error
	}

	return nil
}

func (r *RouteManager) Renew(route *models.DomainRoute) error {
	lsession := r.Logger.Session("renew", lager.Data{
		"instance-id": route.InstanceId,
	})

	//checking if active
	err := r.stillActive(route)
	if err != nil {
		err := fmt.Errorf("Route is not active, skipping renewal: %v", err)
		lsession.Error("still-active", err)
		return err
	}

	var certRow models.Certificate
	err = r.Db.Model(route).Related(&certRow).Error
	if err != nil {
		lsession.Error("db-find-related-cert", err)
		return err
	}

	user := route.User

	conf := lego.NewConfig(&user)
	conf.CADirURL = r.Settings.AcmeUrl
	//conf.HTTPClient = r.AcmeHttpClient

	acmeClient, err := leproviders.NewAcmeClient(r.AcmeHttpClient, r.Resolvers, conf, r.DnsChallengeProvider, r.Logger, "")
	if err != nil {
		lsession.Error("acme-new-client", err)
		return err
	}
	lsession.Debug("acme-client-started")

	// renew the certificate.

	localCert := models.Certificate{InstanceId: route.InstanceId}

	cert, err := acmeClient.Client.Certificate.Renew(*localCert.Resource, true, false)
	if err != nil {
		lsession.Error("acme-certificate-renew", err)
		return err
	}
	localCert.Resource = cert
	lsession.Info("certificate-obtained")

	if err := r.Db.Save(route).Error; err != nil {
		lsession.Error("db-save-renew", err)
	}

	return nil
}

// todo (mxplusb): make sure this actually does the thing
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

		localCert := models.Certificate{InstanceId: localRoute.InstanceId}

		newCert, err := acmeClient.Certificate.Renew(*localCert.Resource, true, false)
		if err != nil {
			lsession.Error("acme-renew-certificate", err)
			continue
		}
		localCert.Resource = newCert

		if err := r.Db.Save(localRoute).Error; err != nil {
			lsession.Error("db-save", err)
		}
	}
}

func (r *RouteManager) DeleteOrphanedCerts() {
	//Finish wehn adding CDN
	/*activeCerts := make(map[string]string)

	r.CloudFrontSvc.ListDistributions(func(distro cloudfront.DistributionSummary) bool {
		if distro.ViewerCertificate.IAMCertificateId != nil {
			activeCerts[*distro.ViewerCertificate.IAMCertificateId] = *distro.ARN
		}
		return true
	})

	/*interfaces.IamCertificateManager.ListCertificates(func(cert iam.ServerCertificateMetadata) bool {

		_, active := activeCerts[*cert.ServerCertificateId]
		if !active && time.Since(*cert.UploadDate).Hours() > 24 {
			r.Logger.Info("cleaning-orphaned-certs", lager.Data{
				"cert": cert,
			})

			if err := interfaces.IamCertificateManager.DeleteCertificate(cert.ServerCertificateName); err != nil {
				r.Logger.Error("iam-delete-cert", err, lager.Data{
					"cert": cert,
				})
			}

		}
		return true
	})*/
	panic("finish me :)")
}

// GetDNSInstructions gets the stored DNS instructions from a given
func (r *RouteManager) GetDNSInstructions(route *models.DomainRoute) (leproviders.DomainMessenger, error) {
	lsession := r.Logger.Session("get-dns-instructions", lager.Data{
		"instance-id": route.InstanceId,
	})

	var domainMessage leproviders.DomainMessenger
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

func (r *RouteManager) Populate() error {
	proxies := []types.ALBProxy{}

	var paginationError error
	err := r.ElbSvc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancers {
				if *lb.Scheme != elbv2.LoadBalancerSchemeEnumInternetFacing {
					continue
				}

				if strings.HasPrefix(*lb.LoadBalancerName, r.Settings.ALBPrefix) {
					proxy := types.ALBProxy{
						ALBARN:     *lb.LoadBalancerArn,
						ALBDNSName: *lb.DNSName,
					}

					listeners, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
						LoadBalancerArn: lb.LoadBalancerArn,
					})

					if err != nil {
						paginationError = err
						return false
					}

					for _, listener := range listeners.Listeners {
						if *listener.Protocol == "HTTPS" {
							proxy.ListenerARN = *listener.ListenerArn
						}
					}
					proxies = append(proxies, proxy)
				}
			}
			return true
		},
	)
	if err != nil {
		return paginationError
	}

	for _, proxy := range proxies {
		if err := r.Db.Set("gorm:insert_option", "ON CONFLICT (alb_arn) DO UPDATE SET alb_dns_name = EXCLUDED.alb_dns_name, listener_arn = EXCLUDED.listener_arn").Create(&proxy).Error; err != nil {
			return err
		}
	}

	return nil

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
