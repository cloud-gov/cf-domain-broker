package routes

import (
	"context"
	"sync"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/jinzhu/gorm"
)

// RouteManagerSettings is the worker for managing custom domains.
// todo (mxplusb): add rate limiter to prevent rate limiting issues with ACME.
type RouteManagerSettings struct {
	WorkerManager               WorkerManager
	Db                          *gorm.DB
	Logger                      lager.Logger
	IamSvc                      iamiface.IAMAPI
	CloudFront                  cloudfrontiface.CloudFrontAPI
	ElbSvc                      elbv2iface.ELBV2API
	ElbUpdateFrequencyInSeconds time.Duration

	elbs   []*elb
	locker sync.RWMutex
}

type RouteManager struct {
	Settings *RouteManagerSettings
	logger   lager.Logger
	elbs     []*elb
}

// todo (mxplusb): prolly test this before the broker code.
func NewManager(rms *RouteManagerSettings) (*RouteManager, error) {

	rm := &RouteManager{
		Settings: rms,
		logger:   rms.Logger.Session("route-manager"),
		elbs:     make([]*elb, 0),
	}

	return rm, nil
}

// Create a new custom domain.
func (r *RouteManager) Create(ctx context.Context,
	instanceId string,
	domainOpts types.DomainPlanOptions,
	cdnOpts types.CdnPlanOptions,
	tags map[string]string) {

	lsession := r.logger.Session("create-route", lager.Data{
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
		Context:    ctx,
		InstanceId: instanceId,
		DomainOpts: domainOpts,
		CdnOpts:    cdnOpts,
		Tags:       tags,
	}

	// send the request
	r.Settings.WorkerManager.RequestRouter <- req
}

// Update is not supported yet.
func (r *RouteManager) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
	//lsession := r.Logger.Session("get-instance", lager.Data{
	//	"instance-id": instanceId,
	//})
	//
	//route, err := r.Get(instanceId)
	//if err != nil {
	//	return err
	//}
	//
	//if domainOpts.Domains[0].Value != "" {
	//	route.DomainExternal = domainOpts.Domains
	//}
	//
	//route.State = cfdomainbroker.Provisioning
	//
	//if domainOpts.Domains[0].Value != "" {
	//	user := route.User
	//
	//	conf := lego.NewConfig(&user)
	//	conf.CADirURL = r.RuntimeSettings.AcmeUrl
	//	conf.HTTPClient = r.AcmeHttpClient
	//
	//	acmeClient, err := leproviders.NewAcmeClient(r.AcmeHttpClient, r.Resolvers, conf, r.DnsChallengeProvider, r.Logger)
	//	if err != nil {
	//		lsession.Error("acme-new-client", err)
	//		return err
	//	}
	//	lsession.Debug("acme-client-started")
	//
	//	route.DNSChallenge = leproviders.DomainMessenger{}
	//
	//}
	//
	return nil
}

// todo (mxplusb): figure this function out.
//func (r *RouteManager) stillActive(route *models.DomainRoute) error {
//	lsession := r.logger.Session("still-active", lager.Data{
//		"instance-id": route.InstanceId,
//	})
//
//	lsession.Info("starting-canary-check", lager.Data{
//		"route":       route,
//		"instance-id": route.InstanceId,
//	})
//
//	session := session.New(aws.NewConfig().WithRegion(r.settings.AwsDefaultRegion))
//
//	s3client := s3.New(session)
//
//	target := path.Join(".well-known", "acme-challenge", "canary", route.InstanceId)
//
//	input := s3.PutObjectInput{
//		Bucket: aws.String(r.settings.Bucket),
//		Key:    aws.String(target),
//		Body:   strings.NewReader(route.InstanceId),
//	}
//
//	if r.settings.ServerSideEncryption != "" {
//		input.ServerSideEncryption = aws.String(r.settings.ServerSideEncryption)
//	}
//
//	if _, err := s3client.PutObject(&input); err != nil {
//		lsession.Error("s3-put-object", err)
//		return err
//	}
//
//	insecureClient := &http.Client{
//		Transport: &http.Transport{
//			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
//		},
//	}
//
//	for _, domain := range route.GetDomains() {
//		resp, err := insecureClient.Get("https://" + path.Join(domain, target))
//		if err != nil {
//			lsession.Error("insecure-client-get", err)
//			return err
//		}
//
//		defer resp.Body.Close()
//		body, err := ioutil.ReadAll(resp.Body)
//		if err != nil {
//			lsession.Error("read-response-body", err)
//			return err
//		}
//
//		if string(body) != route.InstanceId {
//			err := fmt.Errorf("Canary check failed for %s: expected %s, got %s", domain, route.InstanceId, string(body))
//			lsession.Error("", err)
//			return err
//		}
//	}
//
//	return nil
//}

func (r *RouteManagerSettings) updateDeprovisioning(route *models.DomainRoute) error {
	//if len(route.DistributionId) > 0 {
	//	deleted, err := r.CloudFront.Delete(route.DistributionId)
	//	if err != nil {
	//		r.Logger.Error("cloudfront-delete", err)
	//		return err
	//	}
	//
	//	if deleted {
	//		route.State = cfdomainbroker.Deprovisioned
	//		if err := r.Db.Save(route).Error; err != nil {
	//			r.Logger.Error("db-saving-delete-state", err)
	//		}
	//	}
	//}

	return nil
}

//func (r *RouteManagerSettings) checkDistribution(route *models.DomainRoute) bool {
//	dist, err := r.CloudFront.Get(route.DistributionId)
//	if err != nil {
//		r.Logger.Session("checking-distribution").Error("cloudfront-get", err)
//		return false
//	}
//
//	return *dist.Status == "Deployed" && *dist.DistributionConfig.Enabled
//}

// todo (mxplusb): this needs to do the renewal thing
//func (r *RouteManagerSettings) Renew(route *models.DomainRoute) error {
//	lsession := r.Logger.Session("renew", lager.Data{
//		"instance-id": route.InstanceId,
//	})
//
//	//checking if active
//	err := r.stillActive(route)
//	if err != nil {
//		err := fmt.Errorf("Route is not active, skipping renewal: %v", err)
//		lsession.Error("still-active", err)
//		return err
//	}
//
//	var certRow models.Certificate
//	err = r.Db.Model(route).Related(&certRow).Error
//	if err != nil {
//		lsession.Error("db-find-related-cert", err)
//		return err
//	}
//
//	user := route.User
//
//	conf := lego.NewConfig(&user)
//	conf.CADirURL = r.settings.AcmeUrl
//	//conf.HTTPClient = r.AcmeHttpClient
//
//	acmeClient, err := leproviders.NewAcmeClient(r.AcmeHttpClient, r.Resolvers, conf, r.DnsChallengeProvider, r.Logger, "")
//	if err != nil {
//		lsession.Error("acme-new-client", err)
//		return err
//	}
//	lsession.Debug("acme-client-started")
//
//	// renew the certificate.
//
//	localCert := models.Certificate{InstanceId: route.InstanceId}
//
//	cert, err := acmeClient.Client.Certificate.Renew(*localCert.Resource, true, false)
//	if err != nil {
//		lsession.Error("acme-certificate-renew", err)
//		return err
//	}
//	localCert.Resource = cert
//	lsession.Info("certificate-obtained")
//
//	if err := r.Db.Save(route).Error; err != nil {
//		lsession.Error("db-save-renew", err)
//	}
//
//	return nil
//}

// todo (mxplusb): make sure this actually does the renewal things
//func (r *RouteManager) RenewAll() {
//	lsession := r.Logger.Session("renew-all")
//
//	rows, err := r.scanner(models.DomainRoute{})
//	if err != nil {
//		lsession.Error("scanner-error", err)
//	}
//
//	// for every row
//	for rows.Next() {
//
//		// search for the certificate or skip from errors.
//		var localRoute models.DomainRoute
//		if err := r.Db.ScanRows(rows, &localRoute); err != nil {
//			lsession.Error("db-scan-rows", err)
//			continue
//		}
//
//		// generate a client or skip from errors.
//		acmeClient, err := lego.NewClient(lego.NewConfig(localRoute.User))
//		if err != nil {
//			lsession.Error("acme-new-client", err)
//			continue
//		}
//
//		// renew the cert or skip from errors.
//
//		localCert := models.Certificate{InstanceId: localRoute.InstanceId}
//
//		newCert, err := acmeClient.Certificate.Renew(*localCert.Resource, true, false)
//		if err != nil {
//			lsession.Error("acme-renew-certificate", err)
//			continue
//		}
//		localCert.Resource = newCert
//
//		if err := r.Db.Save(localRoute).Error; err != nil {
//			lsession.Error("db-save", err)
//		}
//	}
//}

//func (r *RouteManager) DeleteOrphanedCerts() {
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
//panic("finish me :)")
//}

// UpdateElbs is a cron job designed to keep the internal ELB references up-to-date so we don't need to store the info
// in a database and we can just reference it as needed. This should be run at least once a minute.
// todo (mxplusb): this might be better ELB update code
//func (r *RouteManagerSettings) UpdateElbs() {
//	lsession := r.Logger.Session("update-elbs")
//
//	if err := r.ElbSvc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{},
//		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
//			for _, lb := range page.LoadBalancers {
//				if *lb.Scheme != elbv2.LoadBalancerSchemeEnumInternetFacing {
//					continue
//				}
//				if strings.HasPrefix(*lb.LoadBalancerName, r.settings.ALBPrefix) {
//					// populate the internal struct
//					localElb := new(elb)
//					localElb.lb = lb
//
//					// grab the listeners.
//					listeners, err := r.ElbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
//						LoadBalancerArn: localElb.lb.LoadBalancerArn,
//					})
//					if err != nil {
//						lsession.Error("describe-listeners", err)
//					}
//					localElb.certsOnListener = len(listeners.Listeners)
//
//					// lock to prevent updates elsewhere and make it threadsafe.
//					r.locker.Lock()
//					r.elbs = append(r.elbs, localElb)
//					r.locker.Unlock()
//				}
//			}
//			return true
//		},
//	); err != nil {
//		lsession.Error("describe-load-balancers-pages", err)
//	}
//}

// Grabs all rows from a given model.
//func (r *RouteManagerSettings) scanner(model interface{}) (*sql.Rows, error) {
//	rows, err := r.Db.Model(&model).Where("instance_id = *").Select("*").Rows()
//	if err != nil {
//		return nil, nil
//	}
//	return rows, nil
//}
