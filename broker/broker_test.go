package broker

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"code.cloudfoundry.org/lager"
	cfdomainbroker "github.com/18f/cf-domain-broker"
	"github.com/18f/cf-domain-broker/fakes"
	"github.com/18f/cf-domain-broker/managers"
	"github.com/18f/cf-domain-broker/types"
	"github.com/18f/gravel"
	"github.com/18f/gravel/dns"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/go-acme/lego/v3/lego"
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
	DomainBrokerSettings      *DomainBrokerSettings
	DomainBroker              *DomainBroker
	WorkerManagerSettings     *managers.WorkerManagerSettings
	WorkerManager             *managers.WorkerManager
	ObtainmentManagerSettings *managers.ObtainmentManagerSettings
	ObtainmentManager         *managers.ObtainmentManager
	RuntimeSettings           *types.RuntimeSettings

	Db     *gorm.DB
	Gravel *gravel.Gravel

	Logger lager.Logger
}

// This sets up the test suite before each test.
func (s *BrokerSuite) SetupTest() {
	var err error
	s.Db, err = gorm.Open("sqlite3", "test.db")
	s.Require().NoError(err)

	// migrate our Db to set up the schema.
	if err := s.Db.AutoMigrate(&managers.DomainRouteModel{},
		&managers.UserData{},
		&managers.Domain{},
		&managers.Certificate{},
		&managers.DomainMessenger{}).Error; err != nil {
		s.Require().NoError(err)
	}

	// set up the gravel test harness.
	gravelOpts := gravel.NewDefaultGravelOpts()

	internalResolver := fmt.Sprintf("localhost:%d", gravelOpts.DnsOpts.DnsPort)

	gravelOpts.VAOpts.CustomResolverAddress = internalResolver // allows gravel to verify itself.
	//gravelOpts.AutoUpdateAuthZRecords = true                   // enable to just give us the certificate.
	gravelOpts.DnsOpts.AutoUpdateAuthZRecords = true // enable to just give us the certificate.
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
	// set up our logging writers.
	debugSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	normalSink := lager.NewPrettySink(os.Stdout, lager.INFO)
	errorSink := lager.NewPrettySink(os.Stderr, lager.ERROR)
	fatalSink := lager.NewPrettySink(os.Stderr, lager.FATAL)

	logger := lager.NewLogger("test")
	logger.RegisterSink(debugSink)
	logger.RegisterSink(normalSink)
	logger.RegisterSink(errorSink)
	logger.RegisterSink(fatalSink)
	loggerSession := logger.Session("suite")

	// generate a new key.
	key, err := rsa.GenerateKey(crand.Reader, 4096)
	if err != nil {
		s.T().Error(err)
		s.T().FailNow()
		return
	}
	// build the user with the new key, instantiate a client
	user := managers.UserData{
		Email:      s.RuntimeSettings.Email,
		PublicKey:  key.Public(),
		PrivateKey: key,
	}
	conf := lego.NewConfig(&user)
	conf.CADirURL = s.RuntimeSettings.AcmeUrl
	conf.HTTPClient = s.Gravel.Client

	s.ObtainmentManagerSettings = &managers.ObtainmentManagerSettings{
		Autostart:    true,
		ACMEConfig:   conf,
		Db:           s.Db,
		ElbRequester: make(chan managers.ElbRequest, 10),
		Logger:       loggerSession,
		PrivateKey:   conf.User.GetPrivateKey(),
		Resolvers:    s.RuntimeSettings.Resolvers,
	}

	s.WorkerManagerSettings = &managers.WorkerManagerSettings{
		AutoStartWorkerPool:         true,
		Db:                          s.Db,
		IamSvc:                      iamSvc,
		CloudFront:                  nil,
		ElbSvc:                      elbSvc,
		ElbRequest:                  make(chan managers.ElbRequest),
		ElbUpdateFrequencyInSeconds: 15,
		LogLevel:                    1,
		Logger:                      loggerSession,
		ObtainmentManagerSettings:   s.ObtainmentManagerSettings,
	}

	s.WorkerManager, err = managers.NewWorkerManager(s.WorkerManagerSettings)
	if err != nil {
		s.T().Error(err)
		s.T().FailNow()
	}

	s.DomainBrokerSettings = &DomainBrokerSettings{
		Db:            s.Db,
		Logger:        loggerSession,
		WorkerManager: s.WorkerManager,
	}

	s.DomainBroker = NewDomainBroker(s.DomainBrokerSettings)

	s.Require().NoError(err)
}

func (s *BrokerSuite) TearDownTest() {
	// clear everything so it can be rebuilt on the next test.
	s.DomainBrokerSettings = &DomainBrokerSettings{}
	s.DomainBroker = &DomainBroker{}
	s.WorkerManagerSettings = &managers.WorkerManagerSettings{}
	s.WorkerManager = &managers.WorkerManager{}
	s.RuntimeSettings = &types.RuntimeSettings{}

	if err := s.Db.Close(); err != nil {
		s.Require().NoError(err, "there should not be an error closing the test db")
	}

	if err := os.Remove("test.db"); err != nil {
		s.Require().NoError(err, "there should be no error deleting the test db file.")
	}

	s.Db = &gorm.DB{}

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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

	var verifyRoute managers.DomainRouteModel
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).Find(&verifyRoute).Error; err != nil {
		s.Require().NoError(err, "there should be no error querying for the domain route")
	}

	s.Require().NotNil(verifyRoute, "the route must not be empty")

	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

	localCert := &managers.Certificate{}
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).First(&localCert).Error; err != nil {
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

	s.Gravel.Opts.DnsOpts.AutoUpdateAuthZRecords = false
	s.WorkerManagerSettings.ObtainmentManagerSettings.PersistentDnsProvider = true

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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

	var localDomainMessenger managers.DomainMessenger
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).Find(&localDomainMessenger).Error; err != nil {
		s.Require().NoError(err, "there should be no errors when querying the database for a matching domain")
	}

	s.Require().NotEmpty(localDomainMessenger.Domain, "domain value should not be empty")
	s.Require().Equal("test.service", localDomainMessenger.Domain, "the domains should match")
	s.Require().NotEmpty(localDomainMessenger.TxtRecord, "the txt record should not be empty.")
	s.Require().NotEmpty(localDomainMessenger.CNAME, "the cname should not be empty.")
	s.Require().Equal(60, localDomainMessenger.TTL, "the ttl must be 60 seconds.")
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

	s.awaiter(serviceInstanceId, "there should be no provisioning errors", true)

	localCert := managers.Certificate{
		InstanceId: serviceInstanceId,
	}
	if err := s.Db.Where("instance_id = ?", localCert.InstanceId).Find(&localCert).Error; err != nil {
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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

	var verifyRoute managers.DomainRouteModel
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).First(&verifyRoute).Error; err != nil {
		s.Require().NoError(err, "there should be no error querying for the domain route")
	}

	s.Require().NotNil(verifyRoute, "the route must not be empty")

	localCert := &managers.Certificate{}
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).First(&localCert).Error; err != nil {
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
	s.WorkerManagerSettings.ObtainmentManagerSettings.PersistentDnsProvider = true

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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", true)

	var localDomainMessengers []managers.DomainMessenger
	if err := s.Db.Where("instance_id = ?", serviceInstanceId).Find(&localDomainMessengers).Error; err != nil {
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

	s.awaiter(serviceInstanceId, "there should be no provisioning errors", true)

	localCert := managers.Certificate{
		InstanceId: serviceInstanceId,
	}
	if err := s.Db.Where("instance_id = ?", localCert.InstanceId).Find(&localCert).Error; err != nil {
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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

	delResp, err := s.DomainBroker.Deprovision(context.Background(), serviceInstanceId, domain.DeprovisionDetails{
		PlanID:    "",
		ServiceID: "",
		Force:     true,
	}, true)
	s.Require().NoError(err, "there must not be an error deprovisioning the service instance")
	s.Require().Equal(true, delResp.IsAsync, "deprovision must be async")

	// sleep a bit to let the workers do their thing.
	s.awaiter(serviceInstanceId, "there should be no deprovisioning errors", false)

	// verify the route does not exist in the db.
	localRoute := managers.DomainRouteModel{
		InstanceId: serviceInstanceId,
	}
	dbResp := s.Db.Where("instance_id = ?", &localRoute.InstanceId).Find(&localRoute)

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
	s.awaiter(serviceInstanceId, "there should be no provisioning errors", false)

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
	localRoute := managers.DomainRouteModel{
		InstanceId: serviceInstanceId,
	}
	dbResp := s.Db.Where("instance_id = ?", &localRoute.InstanceId).Find(&localRoute)

	s.Require().NoError(dbResp.Error, "there must not be an error when querying the db")
	s.Require().Equal(cfdomainbroker.Deprovisioned, localRoute.State, "the state must be deprovisioned")
}

func (s *BrokerSuite) TestDomainBroker_Services() {

	res, err := s.DomainBroker.Services(context.Background())

	s.Nil(err, "expected ")
	s.Equal(1, len(res), "expected one service")        // one service
	s.Equal(1, len(res[0].Plans), "expected two plans") // one plan atm

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

// Sleeper for awaiting an instance provisioning, this mostly exists as a blocking function.
func (s *BrokerSuite) awaiter(si, description string, wait bool) {
	var timeout *time.Timer
	if !wait {
		timeout = time.NewTimer(time.Second * 10)
	} else {
		timeout = time.NewTimer(cfdomainbroker.DomainCreateCheck * 5)
	}
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-timeout.C:
			return // "I want to break free" -Freddie Mercury
		case <-ticker.C:
			s.Require().NoError(func() error {
				getInstanceRespChan := make(chan managers.GetInstanceResponse, 1)
				s.WorkerManager.RequestRouter <- managers.GetInstanceRequest{
					Context:    context.TODO(),
					InstanceId: si,
					Response:   getInstanceRespChan,
				}
				resp := <-getInstanceRespChan
				if resp.ErrorNotFound { // that will happen for awhile, we're just checking for provisioning errors specifically.
					return nil
				}
				return resp.Error
			}(), description)
		}
	}
}
