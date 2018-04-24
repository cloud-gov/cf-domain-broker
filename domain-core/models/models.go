package models

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
	"github.com/pivotal-cf/brokerapi"
	"github.com/xenolf/lego/acme"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/18F/cf-domain-broker-alb/utils"
)

type State string

const (
	Provisioning  State = "provisioning"
	Provisioned         = "provisioned"
	Deprovisioned       = "deprovisioned"
)

// Marshal a `State` to a `string` when saving to the database
func (s State) Value() (driver.Value, error) {
	return string(s), nil
}

// Unmarshal an `interface{}` to a `State` when reading from the database
func (s *State) Scan(value interface{}) error {
	switch value.(type) {
	case string:
		*s = State(value.(string))
	case []byte:
		*s = State(value.([]byte))
	default:
		return fmt.Errorf("Incompatible type for %s", value)
	}
	return nil
}

type UserData struct {
	gorm.Model
	Email string `gorm:"not null"`
	Reg   []byte
	Key   []byte
}

func CreateUser(email string) (utils.User, error) {
	user := utils.User{Email: email}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return user, err
	}
	user.SetPrivateKey(key)

	return user, nil
}

func SaveUser(db *gorm.DB, user utils.User) (UserData, error) {
	var err error
	userData := UserData{Email: user.GetEmail()}

	userData.Key, err = savePrivateKey(user.GetPrivateKey())
	if err != nil {
		return userData, err
	}
	userData.Reg, err = json.Marshal(user)
	if err != nil {
		return userData, err
	}

	if err := db.Save(&userData).Error; err != nil {
		return userData, err
	}

	return userData, nil
}

func LoadUser(userData UserData) (utils.User, error) {
	var user utils.User
	if err := json.Unmarshal(userData.Reg, &user); err != nil {
		return user, err
	}
	key, err := loadPrivateKey(userData.Key)
	if err != nil {
		return user, err
	}
	user.SetPrivateKey(key)
	return user, nil
}

// loadPrivateKey loads a PEM-encoded ECC/RSA private key from an array of bytes.
func loadPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

// savePrivateKey saves a PEM-encoded ECC/RSA private key to an array of bytes.
func savePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}

	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(&pemKey), nil
}

type ALBProxy struct {
	ALBARN      string `gorm:"primary_key;column:alb_arn"`
	ALBDNSName  string `gorm:"column:alb_dns_name"`
	ListenerARN string
}

type Route struct {
	GUID          string         `gorm:"primary_key"`
	State         State          `gorm:"not null;index"`
	Domains       pq.StringArray `gorm:"type:text[]"`
	ChallengeJSON []byte

	UserData   UserData
	UserDataID int

	ALBProxy    ALBProxy
	ALBProxyARN string

	Certificate Certificate
}

func (r *Route) loadUser(db *gorm.DB) (utils.User, error) {
	var userData UserData
	if err := db.Model(r).Related(&userData).Error; err != nil {
		return utils.User{}, err
	}
	return LoadUser(userData)
}

type Certificate struct {
	RouteId     uint
	Domain      string
	CertURL     string
	Certificate []byte
	Expires     time.Time `gorm:"index"`
}

type RouteManagerIface interface {
	Create(instanceId string, domains []string) (*Route, error)
	Update(instanceId string, domains []string) error
	Destroy(instanceId string) error
	Get(instanceId string) (*Route, error)
	Poll(route *Route) error
	Renew(route *Route) error
	RenewAll()
	DeleteOrphanedCerts()
	GetDNSInstructions(route *Route) (string, error)
	Populate() error
}

type RouteManager struct {
	logger   lager.Logger
	iam      utils.IamIface
	elbSvc   elbv2iface.ELBV2API
	settings config.Settings
	db       *gorm.DB
}

func NewManager(
	logger lager.Logger,
	iam utils.IamIface,
	elbSvc elbv2iface.ELBV2API,
	settings config.Settings,
	db *gorm.DB,
) RouteManager {
	return RouteManager{
		logger:   logger,
		iam:      iam,
		elbSvc:   elbSvc,
		settings: settings,
		db:       db,
	}
}

func (m *RouteManager) Create(instanceId string, domains []string) (*Route, error) {
	m.logger.Info("create-user", lager.Data{"guid": instanceId, "domains": domains})
	user, err := CreateUser(m.settings.Email)
	if err != nil {
		return nil, err
	}

	clients, err := m.getClients(&user, m.settings)
	if err != nil {
		return nil, err
	}

	userData, err := SaveUser(m.db, user)
	if err != nil {
		return nil, err
	}

	m.logger.Info("assign-alb", lager.Data{"guid": instanceId, "domains": domains})
	route, err := m.assignALB(instanceId)
	if err != nil {
		return nil, err
	}
	m.logger.Info("assigned-alb", lager.Data{"route": route})

	route.Domains = pq.StringArray(domains)
	route.UserData = userData

	challenges, errs := clients[acme.HTTP01].GetChallenges(route.Domains)
	if len(errs) > 0 {
		return nil, fmt.Errorf("Error(s) getting challenges: %v", errs)
	}

	challengeJSON, err := json.Marshal(challenges)
	if err != nil {
		return nil, err
	}
	route.ChallengeJSON = challengeJSON

	if err := m.db.Save(route).Error; err != nil {
		return nil, err
	}

	return route, nil
}

func (m *RouteManager) assignALB(guid string) (*Route, error) {
	var route Route
	if err := m.db.Raw(`
		WITH counts AS (
			SELECT alb_arn, count(guid)
				FROM alb_proxies
				LEFT JOIN routes ON (alb_proxies.alb_arn = routes.alb_proxy_arn)
				GROUP BY alb_arn
				HAVING count(*) < $1
				ORDER BY count
				LIMIT 1
		)
		INSERT INTO routes (guid, state, alb_proxy_arn) SELECT $2 AS guid, $3 AS state, alb_arn AS alb_proxy_arn FROM counts
		RETURNING guid, state, alb_proxy_arn;
	`, m.settings.MaxRoutes, guid, Provisioning).Scan(&route).Error; err != nil {
		return nil, err
	}
	return &route, nil
}

func (m *RouteManager) Get(guid string) (*Route, error) {
	route := Route{}
	result := m.db.First(&route, Route{GUID: guid})
	if result.Error == nil {
		return &route, nil
	} else if result.RecordNotFound() {
		return nil, brokerapi.ErrInstanceDoesNotExist
	} else {
		return nil, result.Error
	}
}

func (m *RouteManager) Update(instanceId string, domain []string) error {
	return nil
	// // Get current route
	// route, err := m.Get(instanceId)
	// if err != nil {
	// 	return err
	// }

	// // Override any settings that are new or different.
	// if domain != "" {
	// 	route.DomainExternal = domain
	// }

	// route.State = Provisioning

	// if domain != "" {
	// 	user, err := route.loadUser(m.db)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	clients, err := m.getClients(&user, m.settings)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	route.ChallengeJSON = []byte("")
	// 	if err := m.ensureChallenges(route, clients[acme.HTTP01], false); err != nil {
	// 		return err
	// 	}
	// }

	// // Save the database.
	// result := m.db.Save(route)
	// if result.Error != nil {
	// 	return result.Error
	// }
	// return nil
}

func (m *RouteManager) Poll(r *Route) error {
	switch r.State {
	case Provisioning:
		return m.updateProvisioning(r)
	default:
		return nil
	}
}

func (m *RouteManager) stillActive(r *Route) error {
	m.logger.Info("Starting canary check", lager.Data{
		"route":    r,
		"settings": m.settings,
	})

	session := session.New(aws.NewConfig().WithRegion(m.settings.AwsDefaultRegion))

	s3client := s3.New(session)

	target := path.Join(".well-known", "acme-challenge", "canary", r.GUID)

	input := s3.PutObjectInput{
		Bucket: aws.String(m.settings.Bucket),
		Key:    aws.String(target),
		Body:   strings.NewReader(r.GUID),
	}

	if m.settings.ServerSideEncryption != "" {
		input.ServerSideEncryption = aws.String(m.settings.ServerSideEncryption)
	}

	if _, err := s3client.PutObject(&input); err != nil {
		return err
	}

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, domain := range r.Domains {
		resp, err := insecureClient.Get("https://" + path.Join(domain, target))
		if err != nil {
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if string(body) != r.GUID {
			return fmt.Errorf("Canary check failed for %s; expected %s, got %s", domain, r.GUID, string(body))
		}
	}

	return nil
}

func (m *RouteManager) Renew(r *Route) error {
	err := m.stillActive(r)
	if err != nil {
		return fmt.Errorf("Route is not active, skipping renewal: %v", err)
	}

	var certRow Certificate
	err = m.db.Model(r).Related(&certRow, "Certificate").Error
	if err != nil {
		return err
	}

	user, err := r.loadUser(m.db)
	if err != nil {
		return err
	}

	clients, err := m.getClients(&user, m.settings)
	if err != nil {
		return err
	}

	certResource, errs := clients[acme.HTTP01].ObtainCertificate(r.Domains, true, nil, false)
	if len(errs) > 0 {
		return fmt.Errorf("Error(s) obtaining certificate: %v", errs)
	}
	expires, err := acme.GetPEMCertExpiration(certResource.Certificate)
	if err != nil {
		return err
	}

	if err := m.deployCertificate(r, certResource); err != nil {
		return err
	}

	certRow.Domain = certResource.Domain
	certRow.CertURL = certResource.CertURL
	certRow.Certificate = certResource.Certificate
	certRow.Expires = expires
	return m.db.Save(&certRow).Error
}

func (m *RouteManager) DeleteOrphanedCerts() {
	// // iterate over all distributions and record all certificates in-use by these distributions
	// activeCerts := make(map[string]string)

	// m.cloudFront.ListDistributions(func(distro cloudfront.DistributionSummary) bool {
	// 	if distro.ViewerCertificate.IAMCertificateId != nil {
	// 		activeCerts[*distro.ViewerCertificate.IAMCertificateId] = *distro.ARN
	// 	}
	// 	return true
	// })

	// // iterate over all certificates
	// m.iam.ListCertificates(m.settings.IamPathPrefix, func(cert iam.ServerCertificateMetadata) bool {

	// 	// delete any certs not attached to a distribution that are older than 24 hours
	// 	_, active := activeCerts[*cert.ServerCertificateId]
	// 	if !active && time.Since(*cert.UploadDate).Hours() > 24 {
	// 		m.logger.Info("Deleting orphaned certificate", lager.Data{
	// 			"cert": cert,
	// 		})

	// 		err := m.iam.DeleteCertificate(*cert.ServerCertificateName)
	// 		if err != nil {
	// 			m.logger.Error("Error deleting certificate", err, lager.Data{
	// 				"cert": cert,
	// 			})
	// 		}
	// 	}

	// 	return true
	// })
}

func (m *RouteManager) RenewAll() {
	routes := []Route{}

	m.logger.Info("Looking for routes that are expiring soon")

	m.db.Having(
		"max(expires) < now() + interval '30 days'",
	).Group(
		"routes.id",
	).Where(
		"state = ?", string(Provisioned),
	).Joins(
		"join certificates on routes.id = certificates.route_id",
	).Find(&routes)

	m.logger.Info("Found routes that need renewal", lager.Data{
		"num-routes": len(routes),
	})

	for _, route := range routes {
		err := m.Renew(&route)
		if err != nil {
			m.logger.Error("Error renewing certificate", err, lager.Data{
				"domains": route.Domains,
			})
		} else {
			m.logger.Info("Successfully renewed certificate", lager.Data{
				"domains": route.Domains,
			})
		}
	}
}

func (m *RouteManager) getClients(user *utils.User, settings config.Settings) (map[acme.Challenge]*acme.Client, error) {
	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))

	var err error

	clients := map[acme.Challenge]*acme.Client{}
	clients[acme.HTTP01], err = utils.NewClient(settings, user, s3.New(session), []acme.Challenge{acme.TLSSNI01, acme.DNS01})
	if err != nil {
		return clients, err
	}
	clients[acme.DNS01], err = utils.NewClient(settings, user, s3.New(session), []acme.Challenge{acme.TLSSNI01, acme.HTTP01})
	if err != nil {
		return clients, err
	}

	return clients, nil
}

func (m *RouteManager) updateProvisioning(r *Route) error {
	m.logger.Info("load-user", lager.Data{"guid": r.GUID, "domains": r.Domains})
	user, err := r.loadUser(m.db)
	if err != nil {
		return err
	}
	m.logger.Info("loaded-user", lager.Data{"guid": r.GUID, "domains": r.Domains, "user": user})

	clients, err := m.getClients(&user, m.settings)
	if err != nil {
		return err
	}

	m.logger.Info("solve-challenges", lager.Data{"guid": r.GUID, "domains": r.Domains})
	var challenges []acme.AuthorizationResource
	if err := json.Unmarshal(r.ChallengeJSON, &challenges); err != nil {
		return err
	}
	if errs := m.solveChallenges(clients, challenges); len(errs) > 0 {
		return fmt.Errorf("Error(s) solving challenges: %v", errs)
	}

	m.logger.Info("request-certificate", lager.Data{"guid": r.GUID, "domains": r.Domains})
	cert, err := clients[acme.HTTP01].RequestCertificate(challenges, true, nil, false)
	if err != nil {
		return err
	}

	expires, err := acme.GetPEMCertExpiration(cert.Certificate)
	if err != nil {
		return err
	}
	if err := m.deployCertificate(r, cert); err != nil {
		return err
	}

	certRow := Certificate{
		Domain:      cert.Domain,
		CertURL:     cert.CertURL,
		Certificate: cert.Certificate,
		Expires:     expires,
	}
	if err := m.db.Create(&certRow).Error; err != nil {
		return err
	}

	r.State = Provisioned
	r.Certificate = certRow
	return m.db.Save(r).Error

	m.logger.Info("distribution-provisioning", lager.Data{"guid": r.GUID})
	return nil
}

func (m *RouteManager) Destroy(guid string) error {
	route, err := m.Get(guid)
	if err != nil {
		return err
	}
	// TODO: Delete certificate from listener and iam
	return m.db.Delete(route).Error
}

func (m *RouteManager) solveChallenges(clients map[acme.Challenge]*acme.Client, challenges []acme.AuthorizationResource) map[string]error {
	errs := make(chan map[string]error)

	for _, client := range clients {
		go func(client *acme.Client) {
			errs <- client.SolveChallenges(challenges)
		}(client)
	}

	var failures map[string]error
	for challenge, _ := range clients {
		failures = <-errs
		m.logger.Info("solve-challenges", lager.Data{
			"challenge": challenge,
			"failures":  failures,
		})
		if len(failures) == 0 {
			return failures
		}
	}

	return failures
}

func (m *RouteManager) deployCertificate(route *Route, cert acme.CertificateResource) error {
	expires, err := acme.GetPEMCertExpiration(cert.Certificate)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("cf-domains-%s-%s", route.GUID, expires.Format("2006-01-02_15-04-05"))
	m.logger.Info("upload-cert", lager.Data{"guid": route.GUID, "domains": route.Domains, "name": name})
	certARN, err := m.iam.UploadCertificate(name, m.settings.IamPathPrefix, cert)
	if err != nil {
		return err
	}

	var albProxy ALBProxy
	if err := m.db.First(&albProxy, ALBProxy{ALBARN: route.ALBProxyARN}).Error; err != nil {
		return err
	}

	for {
		m.logger.Info("add-listener-cert", lager.Data{
			"listenerARN": albProxy.ListenerARN,
			"certARN":     certARN,
		})
		if _, err := m.elbSvc.AddListenerCertificates(&elbv2.AddListenerCertificatesInput{
			ListenerArn: aws.String(albProxy.ListenerARN),
			Certificates: []*elbv2.Certificate{
				{CertificateArn: aws.String(certARN)},
			},
		}); err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == elbv2.ErrCodeCertificateNotFoundException {
					continue
				}
			}
			return err
		}
		break
	}

	return nil
}

func (m *RouteManager) GetDNSInstructions(route *Route) (string, error) {
	var instructions []string
	var challenges []acme.AuthorizationResource

	var albProxy ALBProxy
	if err := m.db.First(&albProxy, ALBProxy{ALBARN: route.ALBProxyARN}).Error; err != nil {
		return "", err
	}

	user, err := route.loadUser(m.db)
	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(route.ChallengeJSON, &challenges); err != nil {
		return "", err
	}
	for _, auth := range challenges {
		for _, challenge := range auth.Body.Challenges {
			if challenge.Type == acme.DNS01 {
				keyAuth, err := acme.GetKeyAuthorization(challenge.Token, user.GetPrivateKey())
				if err != nil {
					return "", err
				}
				fqdn, value, ttl := acme.DNS01Record(auth.Domain, keyAuth)
				instructions = append(instructions, fmt.Sprintf("name: %s, value: %s, ttl: %d", fqdn, value, ttl))
			}
		}
	}

	return fmt.Sprintf(
		"Provisioning in progress; CNAME or ALIAS domain(s) %s to %s or create TXT record(s): \n%s",
		strings.Join(route.Domains, ", "), albProxy.ALBDNSName,
		strings.Join(instructions, "\n"),
	), nil
}

func (m *RouteManager) Populate() error {
	proxies := []ALBProxy{}
	var paginationError error
	if err := m.elbSvc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancers {
				if strings.HasPrefix(*lb.LoadBalancerName, m.settings.ALBPrefix) {
					proxy := ALBProxy{
						ALBARN:     *lb.LoadBalancerArn,
						ALBDNSName: *lb.DNSName,
					}
					listeners, err := m.elbSvc.DescribeListeners(&elbv2.DescribeListenersInput{
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
	); err != nil {
		return err
	}
	if paginationError != nil {
		return paginationError
	}
	// TODO: Bulk insert
	for _, proxy := range proxies {
		if err := m.db.Set("gorm:insert_option", "ON CONFLICT (alb_arn) DO UPDATE SET alb_dns_name = EXCLUDED.alb_dns_name, listener_arn = EXCLUDED.listener_arn").Create(&proxy).Error; err != nil {
			return err
		}
	}
	return nil
}
