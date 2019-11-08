package routes

import (
	"context"
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
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi/domain/apiresponses"
)

// RouteManagerSettings is the worker for managing custom domains.
// todo (mxplusb): add rate limiter to prevent rate limiting issues with ACME.
type RouteManagerSettings struct {
	WorkerManager WorkerManager
	// Internal database.
	Db *gorm.DB

	// Inherited from main.
	Logger lager.Logger

	// Global settings from the environment.
	Settings types.RuntimeSettings

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
func NewManager(logger lager.Logger, iam iamiface.IAMAPI, cloudFront interfaces.CloudfrontDistributionIface, elbSvc elbv2iface.ELBV2API, settings types.RuntimeSettings, db *gorm.DB, persistentDnsProvider bool) (RouteManagerSettings, error) {
	r := RouteManagerSettings{
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
		return RouteManagerSettings{}, err
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
				return RouteManagerSettings{}, err
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
func (r *RouteManagerSettings) Create(ctx context.Context, instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions, tags map[string]string) {

	lsession := r.Logger.Session("create-route", lager.Data{
		"instance-id": instanceId,
		"domains":     domainOpts.Domains,
	})

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

	// build the request
	req := ProvisionRequest{
		Context:      ctx,
		InstanceId:   instanceId,
		DomainOpts:   domainOpts,
		CdnOpts:      cdnOpts,
		Tags:         tags,
		LoadBalancer: targetElb,
	}

	// send the request
	r.WorkerManager.RequestRouter <- req
}

// Update is not supported yet.
func (r *RouteManagerSettings) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
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
		conf.CADirURL = r.RuntimeSettings.AcmeUrl
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
func (r *RouteManagerSettings) Get(instanceId string) (*models.DomainRoute, error) {
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

func (r *RouteManagerSettings) stillActive(route *models.DomainRoute) error {
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

func (r *RouteManagerSettings) Poll(route *models.DomainRoute) error {
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

func (r *RouteManagerSettings) updateDeprovisioning(route *models.DomainRoute) error {
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

func (r *RouteManagerSettings) checkDistribution(route *models.DomainRoute) bool {
	dist, err := r.CloudFront.Get(route.DistributionId)
	if err != nil {
		r.Logger.Session("checking-distribution").Error("cloudfront-get", err)
		return false
	}

	return *dist.Status == "Deployed" && *dist.DistributionConfig.Enabled
}

func (r *RouteManagerSettings) purgeCertificate(route *models.DomainRoute, cert *models.Certificate) error {
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

func (r *RouteManagerSettings) Disable(route *models.DomainRoute) error {
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

func (r *RouteManagerSettings) Renew(route *models.DomainRoute) error {
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
func (r *RouteManagerSettings) RenewAll() {
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

func (r *RouteManagerSettings) DeleteOrphanedCerts() {
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
func (r *RouteManagerSettings) GetDNSInstructions(route *models.DomainRoute) (leproviders.DomainMessenger, error) {
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

func (r *RouteManagerSettings) Populate() error {
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
func (r *RouteManagerSettings) UpdateElbs() {
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
func (r *RouteManagerSettings) scanner(model interface{}) (*sql.Rows, error) {
	rows, err := r.Db.Model(&model).Where("instance_id = *").Select("*").Rows()
	if err != nil {
		return nil, nil
	}
	return rows, nil
}
