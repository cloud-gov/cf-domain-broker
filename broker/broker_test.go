package broker

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/fakes"
	leproviders "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/18f/gravel"
	"github.com/18f/gravel/dns"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/pborman/uuid"
	"github.com/pivotal-cf/brokerapi/domain"
	"github.com/stretchr/testify/suite"
)

// todo (mxplusb): implement fuzzing for better coverage.

// DomainBroker test entry point.
func TestBrokerSuite(t *testing.T) {
	suite.Run(t, new(BrokerSuite))
}

// Mocks and such.
type BrokerSuite struct {
	suite.Suite
	DomainBrokerSettings  *DomainBrokerSettings
	DomainBroker          *DomainBroker
	WorkerManagerSettings *routes.WorkerManagerSettings
	WorkerManager         *routes.WorkerManager
	RuntimeSettings       *types.RuntimeSettings

	DB     *gorm.DB
	Gravel *gravel.Gravel

	Logger lager.Logger
}

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupTest() {

	var err error
	s.DB, err = gorm.Open("sqlite3", ":memory:")
	s.Require().NoError(err)

	// migrate our DB to set up the schema.
	if err := s.DB.AutoMigrate(&models.DomainRoute{},
		&models.UserData{},
		&models.Domain{},
		&models.Certificate{},
		&leproviders.DomainMessenger{}).Error; err != nil {
		s.Require().NoError(err)
	}

	// set up the gravel test harness.
	gravelOpts := gravel.NewDefaultGravelOpts()

	internalResolver := fmt.Sprintf("localhost:%d", gravelOpts.DnsOpts.DnsPort)

	gravelOpts.VAOpts.CustomResolverAddress = internalResolver // allows gravel to verify itself.
	gravelOpts.AutoUpdateAuthZRecords = true                   // enable to just give us the certificate.
	s.Gravel, err = gravel.New(gravelOpts)
	s.Require().NoError(err)

	// start the servers
	go s.Gravel.StartDnsServer()
	go s.Gravel.StartWebServer()

	s.RuntimeSettings = &types.RuntimeSettings{
		AcmeUrl:   fmt.Sprintf("https://%s%s", s.Gravel.Opts.ListenAddress, s.Gravel.Opts.WfeOpts.DirectoryPath),
		Email:     "cloud-gov-operations@gsa.gov",
		Resolvers: map[string]string{"localhost": fmt.Sprintf("localhost:%d", s.Gravel.Opts.DnsOpts.DnsPort)},
	}

	// set up our fakes. we need to create an elb so there's something the route manager can query for.
	elbSvc := fakes.NewMockELBV2API()
	iamSvc := fakes.NewMockIAMAPI()

	// create 5 ELBs, and a random number (<= 25) of listeners on each to ensure there's some variety in it, so we can
	// ensure the least assigned logic works.
	for idx := 0; idx < 5; idx++ {
		elbString := fmt.Sprintf("test-elb-%d", idx)
		elbResp, _ := elbSvc.CreateLoadBalancer(&elbv2.CreateLoadBalancerInput{
			Name: aws.String(elbString),
		})
		for nidx := 0; nidx < rand.Intn(25); nidx++ {
			_, _ = elbSvc.CreateListener(&elbv2.CreateListenerInput{
				DefaultActions:  []*elbv2.Action{{}},
				LoadBalancerArn: elbResp.LoadBalancers[0].LoadBalancerArn,
				Port:            aws.Int64(443),
				Protocol:        aws.String("HTTPS"),
				Certificates:    make([]*elbv2.Certificate, rand.Intn(25)),
			})
		}
	}

	// set up our test writers.
	testSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	logger := lager.NewLogger("domain-broker-test")
	logger.RegisterSink(testSink)
	loggerSession := logger.Session("test-suite")

	s.WorkerManagerSettings = &routes.WorkerManagerSettings{
		AutostartWorkerPool:         true,
		AcmeHttpClient:              s.Gravel.Client,
		AcmeUrl:                     s.RuntimeSettings.AcmeUrl,
		AcmeEmail:                   s.RuntimeSettings.Email,
		Db:                          s.DB,
		IamSvc:                      iamSvc,
		CloudFront:                  nil,
		ElbSvc:                      elbSvc,
		ElbUpdateFrequencyInSeconds: 15,
		PersistentDnsProvider:       false,
		DnsChallengeProvider:        s.Gravel.DnsServer.Opts.Provider,
		Resolvers:                   s.RuntimeSettings.Resolvers,
		LogLevel:                    1,
		Logger:                      loggerSession,
	}

	workerManager := routes.NewWorkerManager(s.WorkerManagerSettings)

	s.DomainBrokerSettings = &DomainBrokerSettings{
		Db:            s.DB,
		Logger:        loggerSession,
		WorkerManager: workerManager,
	}

	s.DomainBroker = NewDomainBroker(s.DomainBrokerSettings)

	s.Require().NoError(err)
}

func (s *BrokerSuite) TearDownTest() {
	// clear everything so it can be rebuilt on the next test.
	s.DomainBrokerSettings = &DomainBrokerSettings{}
	s.DomainBroker = &DomainBroker{}
	s.WorkerManagerSettings = &routes.WorkerManagerSettings{}
	s.WorkerManager = &routes.WorkerManager{}
	s.RuntimeSettings = &types.RuntimeSettings{}

	if err := s.DB.Close(); err != nil {
		s.Require().NoError(err, "there should not be an error closing the test db")
	}

	s.DB = &gorm.DB{}

	if err := s.Gravel.CertificateServer.Shutdown(context.TODO()); err != nil {
		s.Require().NoError(err, "gravel certificate server must shutdown cleanly")
	}

	if err := s.Gravel.DnsServer.Server.Shutdown(); err != nil {
		s.Require().NoError(err, "gravel certificate server must shutdown cleanly")
	}
}

// Test where DNS will be autosolved, this is really just ensuring the core functionality works.
func (s *BrokerSuite) TestDomainBroker_AutoProvisionDomainPlan() {
	b := s.DomainBroker

	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service"]}`)),
	}

	res, err := b.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 5)

	var verifyRoute models.DomainRoute
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).Find(&verifyRoute).Error; err != nil {
		s.Require().NoError(err, "there should be no error querying for the domain route")
	}

	s.Require().NotNil(verifyRoute, "the route must not be empty")

	localCert := &models.Certificate{}
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).First(&localCert).Error; err != nil {
		s.Require().NoError(err, "there should be no error when searching for the related certificate in the database")
	}

	s.Require().EqualValues(serviceInstanceId, verifyRoute.InstanceId, "service instance id must match deployed service instance")
	s.Require().EqualValues(cfdomainbroker.Provisioned, verifyRoute.State, "state must be provisioned")
	s.Require().NotNil(localCert, "certificate result must not be nil")
	s.Require().NotEmpty(localCert.Resource.Certificate, "certificate must not be empty")
}

// Test where DNS does not auto-present, a more realistic test.
func (s *BrokerSuite) TestDomainBroker_ProvisionDomainPlanWithDomainMessenger() {

	if testing.Short() {
		s.T().Skip("skipping ProvisionDomainPlanWithDomainMessenger as it is a long test")
	}

	var (
		serviceInstanceId = uuid.New()
	)

	s.Gravel.Opts.AutoUpdateAuthZRecords = false
	s.WorkerManagerSettings.PersistentDnsProvider = true

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service"]}`)),
	}

	res, err := s.DomainBroker.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep for a bit to let the cert get issued and the db store things.
	time.Sleep(time.Second * 5)

	var localDomainMessenger leproviders.DomainMessenger
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).Find(&localDomainMessenger).Error; err != nil {
		s.Require().NoError(err, "there should be no errors when querying the database for a matching domain")
	}

	s.Require().NotEmpty(localDomainMessenger.Domain, "domain value should not be empty")
	s.Require().NotEmpty(localDomainMessenger.KeyAuth, "keyauth value should not be empty")
	s.Require().NotEmpty(localDomainMessenger.Token, "domain token should not be empty")

	// reset the configuration to let the DNS pass the authorization. since the record is already hashed, no need to
	// have the server do it.
	s.Gravel.Opts.DnsOpts.AutoUpdateAuthZRecords = true
	s.Gravel.Opts.DnsOpts.AlreadyHashed = true

	// send the record to the dns server
	s.Gravel.DnsServer.RecordsHandler <- dns.DnsMessage{
		Domain:  localDomainMessenger.Domain,
		Token:   localDomainMessenger.Token,
		KeyAuth: localDomainMessenger.KeyAuth,
	}

	// sleep for awhile until the client checks things normally.
	time.Sleep(cfdomainbroker.DomainCreateCheck * 2)

	localCert := models.Certificate{
		InstanceId: serviceInstanceId,
	}
	if err := s.DB.Where("instance_id = ?", localCert.InstanceId).Find(&localCert).Error; err != nil {
		s.Require().NoError(err, "there should be no errors when querying the database for a provisioned certificate")
	}

	s.Require().NotEmpty(localCert.Certificate, "the certificate should not be empty")
	s.Require().NotEmpty(localCert.PrivateKey, "the private key should not be empty")
}

func (s *BrokerSuite) TestDomainBroker_AutoProvisionDomainPlanWithMultipleSAN() {
	b := s.DomainBroker

	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service", "test2.service", "test3.service"]}`)),
	}

	res, err := b.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 15)

	var verifyRoute models.DomainRoute
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).First(&verifyRoute).Error; err != nil {
		s.Require().NoError(err, "there should be no error querying for the domain route")
	}

	s.Require().NotNil(verifyRoute, "the route must not be empty")

	localCert := &models.Certificate{}
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).First(&localCert).Error; err != nil {
		s.Require().NoError(err, "there should be no error when searching for the related certificate in the database")
	}

	s.Require().EqualValues(serviceInstanceId, verifyRoute.InstanceId, "service instance id must match deployed service instance")
	s.Require().EqualValues(cfdomainbroker.Provisioned, verifyRoute.State, "state must be provisioned")
	s.Require().NotNil(localCert, "certificate result must not be nil")
	s.Require().NotEmpty(localCert.Resource.Certificate, "certificate must not be empty")
}

// Test where DNS does not auto-present, a more realistic test.
func (s *BrokerSuite) TestDomainBroker_ProvisionDomainPlanWithMultipleSANUsingTheDomainMessenger() {
	if testing.Short() {
		s.T().Skip("skipping ProvisionDomainPlanWithDomainMessenger as it is a long test")
	}

	var (
		serviceInstanceId = uuid.New()
	)

	s.Gravel.Opts.AutoUpdateAuthZRecords = false
	s.Gravel.Opts.DnsOpts.AlreadyHashed = true
	s.WorkerManagerSettings.PersistentDnsProvider = true

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service", "test2.service", "test3.service"]}`)),
	}

	res, err := s.DomainBroker.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep for a bit to let the cert get issues and the db store things.
	time.Sleep(time.Second * 5)

	var localDomainMessengers []leproviders.DomainMessenger
	if err := s.DB.Where("instance_id = ?", serviceInstanceId).Find(&localDomainMessengers).Error; err != nil {
		s.Require().NoError(err, "there should be no errors when querying the database for a matching domain")
	}
	s.Require().Equal(3, len(localDomainMessengers), "there should be 3 domain authentication items")

	for _, localDomainMessenger := range localDomainMessengers {
		s.Require().NotEmpty(localDomainMessenger.Domain, "domain value should not be empty")
		s.Require().NotEmpty(localDomainMessenger.KeyAuth, "keyauth value should not be empty")
		s.Require().NotEmpty(localDomainMessenger.Token, "domain token should not be empty")

		s.Gravel.DnsServer.RecordsHandler <- dns.DnsMessage{
			Domain:  localDomainMessenger.Domain,
			Token:   localDomainMessenger.Token,
			KeyAuth: localDomainMessenger.KeyAuth,
		}
	}

	// reset the configuration to let the DNS pass the authorization. since the record is already hashed, no need to
	// have the server do it.
	s.Gravel.Opts.DnsOpts.AutoUpdateAuthZRecords = true

	// sleep for awhile until the client checks things normally.
	time.Sleep(cfdomainbroker.DomainCreateCheck * 2)

	localCert := models.Certificate{
		InstanceId: serviceInstanceId,
	}
	if err := s.DB.Where("instance_id = ?", localCert.InstanceId).Find(&localCert).Error; err != nil {
		s.Require().NoError(err, "there should be no errors when querying the database for a provisioned certificate")
	}

	s.Require().NotEmpty(localCert.Certificate, "the certificate should not be empty")
	s.Require().NotEmpty(localCert.PrivateKey, "the private key should not be empty")
}

func (s *BrokerSuite) TestDomainBroker_Deprovision() {
	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service"]}`)),
	}

	res, err := s.DomainBroker.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 5)

	delResp, err := s.DomainBroker.Deprovision(context.Background(), serviceInstanceId, domain.DeprovisionDetails{
		PlanID:    "",
		ServiceID: "",
		Force:     true,
	}, true)
	s.Require().NoError(err, "there must not be an error deprovisioning the service instance")
	s.Require().Equal(true, delResp.IsAsync, "deprovision must be async")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 5)

	// verify the route does not exist in the db.
	localRoute := models.DomainRoute{
		InstanceId: serviceInstanceId,
	}
	dbResp := s.DB.Where("instance_id = ?", &localRoute.InstanceId).Find(&localRoute)

	s.Require().NoError(dbResp.Error, "there must not be an error when querying the db")
	s.Require().Equal(cfdomainbroker.Deprovisioned, localRoute.State, "the state must be deprovisioned")
}

func (s *BrokerSuite) TestDomainBroker_DeprovisionMultipleCertificates() {
	var (
		serviceInstanceId = uuid.New()
	)

	// test the domain plan.
	d := domain.ProvisionDetails{
		PlanID:        cfdomainbroker.DomainPlanId,
		RawParameters: []byte(fmt.Sprintf(`{"domains": ["test.service", "test2.service", "test3.service"]}`)),
	}

	res, err := s.DomainBroker.Provision(context.Background(), serviceInstanceId, d, true)
	if err != nil {
		s.Require().NoError(err, "provisioning should not throw an error")
	}
	s.EqualValues(domain.ProvisionedServiceSpec{IsAsync: true}, res, "expected async response")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 5)

	delResp, err := s.DomainBroker.Deprovision(context.Background(), serviceInstanceId, domain.DeprovisionDetails{
		PlanID:    "",
		ServiceID: "",
		Force:     true,
	}, true)
	s.Require().NoError(err, "there must not be an error deprovisioning the service instance")
	s.Require().Equal(true, delResp.IsAsync, "deprovision must be async")

	// sleep a bit to let the workers do their thing.
	time.Sleep(time.Second * 5)

	// verify the route does not exist in the db.
	localRoute := models.DomainRoute{
		InstanceId: serviceInstanceId,
	}
	dbResp := s.DB.Where("instance_id = ?", &localRoute.InstanceId).Find(&localRoute)

	s.Require().NoError(dbResp.Error, "there must not be an error when querying the db")
	s.Require().Equal(cfdomainbroker.Deprovisioned, localRoute.State, "the state must be deprovisioned")
}

func (s *BrokerSuite) TestDomainBroker_Services() {

	res, err := s.DomainBroker.Services(context.Background())

	s.Nil(err, "expected ")
	s.Equal(1, len(res), "expected one service")        // one service
	s.Equal(2, len(res[0].Plans), "expected two plans") //two plans

	// sleep a bit to let the workers finish spinning up before the test ends.
	time.Sleep(time.Second * 2)
}

func (s *BrokerSuite) TestDomainBroker_Bind() {
	b := s.DomainBroker
	_, err := b.Bind(context.Background(), "", "", domain.BindDetails{}, false)
	s.NotNil(err, "expected error on bind")

	// sleep a bit to let the workers finish spinning up before the test ends.
	time.Sleep(time.Second * 2)
}

func (s *BrokerSuite) TestDomainBroker_Unbind() {
	b := s.DomainBroker
	_, err := b.Unbind(context.Background(), "", "", domain.UnbindDetails{}, false)
	s.Error(err, "expected error on unbind")

	// sleep a bit to let the workers finish spinning up before the test ends.
	time.Sleep(time.Second * 2)
}

func (s *BrokerSuite) TestDomainBroker_GetBinding() {
	b := s.DomainBroker
	_, err := b.GetBinding(context.Background(), "", "")
	s.NotNil(err, "expected error on get binding")

	// sleep a bit to let the workers finish spinning up before the test ends.
	time.Sleep(time.Second * 2)
}

func (s *BrokerSuite) TestDomainBroker_LastBindingOperation() {
	b := s.DomainBroker
	_, err := b.LastBindingOperation(context.Background(), "", "", domain.PollDetails{})
	s.NotNil(err, "expected error on last binding operation")

	// sleep a bit to let the workers finish spinning up before the test ends.
	time.Sleep(time.Second * 2)
}
