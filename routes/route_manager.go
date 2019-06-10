package routes

import (
	"code.cloudfoundry.org/lager"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/jinzhu/gorm"
	"net"
	"strings"
	"sync"
)

// RouteManager is the worker for managing custom domains.
type RouteManager struct {
	// Internal database.
	Db *gorm.DB

	// Inherited from main.
	Logger lager.Logger

	// Global settings from the environemnt.
	Settings types.Settings

	// AWS IAM.
	IamSvc iamiface.IAMAPI

	// AWS CloudFront.
	CloudFrontSvc cloudfrontiface.CloudFrontAPI

	// AWS ELBv2
	ElbSvc elbv2iface.ELBV2API

	// list of available ELBs
	elbs []*elb

	// locker
	locker sync.RWMutex

	// dns challenger
	dns le_providers.ServiceBrokerDNSProvider
}

// internal holder for needed information about an elb to prevent nested round trips.
type elb struct {
	lb              *elbv2.LoadBalancer
	certsOnListener int
}

// Create a new custom domain.
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
	acmeClient, err := lego.NewClient(lego.NewConfig(&user))
	if err != nil {
		lsession.Error("acme-new-client", err)
		return &models.DomainRoute{}, nil
	}
	lsession.Debug("acme-client-instantiated")

	// set the DNS challenger, and create our resolvers.
	// todo (mxplusb): move this into it's own package.
	if err := acmeClient.Challenge.SetDNS01Provider(r.dns, dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (b bool, e error) {
		ctx := context.Background()

		// if either dns servers resolves the record, it will be set to true.
		var googleValidated = false
		var cloudflareValdiated = false

		// create a DNS resolver which pokes google's public DNS address.
		googleResolver := net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		}
		gval, err := googleResolver.LookupTXT(ctx, fqdn)
		if err != nil {
			return false, err
		}
		for idx := range gval {
			if gval[idx] == value {
				googleValidated = true
			}
		}

		// create a DNS resolver which pokes cloudflare's public DNS address.
		cloudflareResolver := net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (conn net.Conn, e error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", "1.1.1.1:53")
			},
		}
		cval, err := cloudflareResolver.LookupTXT(ctx, fqdn)
		if err != nil {
			return false, err
		}
		for idx := range gval {
			if cval[idx] == value {
				cloudflareValdiated = true
			}
		}

		// true == 1 and false == 0 as helper functions because go doesn't support bitwise xor on booleans.
		// we need these so we can return `true | false`, depending on whichever resolves first.
		ifn := func(b bool) int {
			if b {
				return 1
			} else {
				return 0
			}
		}
		bfn := func(i int) bool {
			if i == 0 {
				return false
			} else {
				return true
			}
		}

		// return whichever one resolves.
		return bfn(ifn(googleValidated) | ifn(cloudflareValdiated)), nil
	})); err != nil {
		return &models.DomainRoute{}, nil
	}
	lsession.Debug("acme-dns-provider-assigned")

	// register our user resource.
	reg, err := acmeClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	user.Registration = reg
	lsession.Debug("acme-user-registered")

	// create the route struct and add the user reference.
	localRoute := &models.DomainRoute{
		User: user,
	}

	// make the certificate request.
	request := certificate.ObtainRequest{
		Domains: domainOpts.Domains,
		Bundle:  true,
	}

	// get the certificate.
	cert, err := acmeClient.Certificate.Obtain(request)
	if err != nil {
		lsession.Error("acme-certificate-obtain", err)
		return &models.DomainRoute{}, nil
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
		return &models.DomainRoute{}, nil
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
		return &models.DomainRoute{}, nil
	}
	lsession.Info("certificate-uploaded-to-elb")

	// store the certificate and elb info the database.
	if err := r.Db.Save(localRoute).Error; err != nil {
		lsession.Error("db-save-route", err)
		return &models.DomainRoute{}, err
	}

	return localRoute, nil
}

func (*RouteManager) Update(instanceId string, domainOpts types.DomainPlanOptions, cdnOpts types.CdnPlanOptions) error {
	panic("implement me")
}

func (*RouteManager) Get(instanceId string) (*models.DomainRoute, error) {
	panic("implement me")
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

func (*RouteManager) RenewAll() {
	panic("implement me")
}

func (*RouteManager) DeleteOrphanedCerts() {
	panic("implement me")
}

func (*RouteManager) GetDNSInstructions(route *models.DomainRoute) ([]string, error) {
	panic("implement me")
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

func NewManager(logger lager.Logger, iam iamiface.IAMAPI, cloudFront cloudfrontiface.CloudFrontAPI, elbSvc elbv2iface.ELBV2API, settings types.Settings, db *gorm.DB) RouteManager {
	return RouteManager{
		Logger:        logger,
		IamSvc:        iam,
		CloudFrontSvc: cloudFront,
		Settings:      settings,
		Db:            db,
		ElbSvc:        elbSvc,
		dns: le_providers.ServiceBrokerDNSProvider{
			Handler: make(chan le_providers.DomainMessenger, 1),
		},
	}
}
