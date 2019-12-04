package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/18f/cf-domain-broker/broker"
	"github.com/18f/cf-domain-broker/managers"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/kelseyhightower/envconfig"
	"github.com/pivotal-cf/brokerapi"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"

	"code.cloudfoundry.org/lager"
)

// todo (mxplusb): ensure server can restart while working on authorization

var (
	settings *types.GlobalSettings
)

func main() {
	run()
}

func run() {
	domainBroker, db := initBrokerConfig()
	brokerCapiCredentials := brokerapi.BrokerCredentials{
		Username: settings.RuntimeSettings.BrokerUsername,
		Password: settings.RuntimeSettings.BrokerPassword,
	}

	brokerApi := brokerapi.New(domainBroker, settings.Logger, brokerCapiCredentials)
	handlers := bindHTTPHandlers(brokerApi)

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := http.Server{
		Addr:    fmt.Sprintf(":%s", settings.RuntimeSettings.Port),
		Handler: handlers,
	}

	go func() {
		http.Handle("/", handlers)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			settings.Logger.Fatal("http-server-error", err)
		}
	}()

	// everything is initialised, mark the start time.
	startTime := time.Now()
	if err := db.Create(managers.ProcInfo{Start: startTime}).Error; err != nil {
		panic(fmt.Errorf("cannot save start time, %s", err))
	}

	// block forever
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer func() {
		cancel()
	}()

	// we're stopping, so go ahead and mark that too.
	var procInfo managers.ProcInfo
	result := db.Where("start = ?", startTime).Find(&procInfo)

	// if we can't find the record, just create a new one, otherwise, try to update.
	if result.RecordNotFound() {
		db.Create(managers.ProcInfo{Stop: time.Now()})
	} else {
		if err := db.Update(managers.ProcInfo{Stop: time.Now()}).Error; err != nil {
			panic(fmt.Errorf("cannot save stop time, %s", err))
		}
	}

	if err := srv.Shutdown(ctx); err != nil {
		settings.Logger.Fatal("server-not-stopping-cleanly", err)
	}
	settings.Logger.Info("goodbye")
}

// todo (mxplusb): make this more cf friendly.
func initBrokerConfig() (*broker.DomainBroker, *gorm.DB) {
	// before anything else, we need to grab our config so we know what to do.
	var runtimeSettings types.RuntimeSettings
	err := envconfig.Process("", &runtimeSettings)
	if err != nil {
		panic(fmt.Errorf("cannot read environment variables for configuration, %s", err))
	}

	// set up our logging writers.
	debugSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	normalSink := lager.NewPrettySink(os.Stdout, lager.INFO)
	errorSink := lager.NewPrettySink(os.Stderr, lager.ERROR)
	fatalSink := lager.NewPrettySink(os.Stderr, lager.FATAL)

	logger := lager.NewLogger("main")
	logger.RegisterSink(debugSink)
	logger.RegisterSink(normalSink)
	logger.RegisterSink(errorSink)
	logger.RegisterSink(fatalSink)

	// open up the database and prepare it
	db, err := gorm.Open("postgres", runtimeSettings.DatabaseUrl)
	if err != nil {
		logger.Fatal("db-connection-builder", err)
	}
	// todo (mxplusb): this needs to go in the respective components.
	if err := db.AutoMigrate(&managers.DomainRouteModel{},
		&managers.UserData{},
		&types.Domain{},
		&managers.Certificate{},
		&managers.DomainMessenger{},
		&managers.ProcInfo{}).Error; err != nil {
		logger.Fatal("db-auto-migrate", err)
	}

	// prep our AWS session.
	sess, err := session.NewSession(
		aws.NewConfig().WithCredentials(
			credentials.NewEnvCredentials()).WithRegion(
			runtimeSettings.AwsDefaultRegion))

	var albNames []*string
	for idx := range runtimeSettings.ALBNames {
		albNames = append(albNames, aws.String(runtimeSettings.ALBNames[idx]))
	}

	workerManagerSettings := &managers.WorkerManagerSettings{
		AutoStartWorkerPool:         true,
		//AcmeHttpClient:              http.DefaultClient,
		//AcmeUrl:                     runtimeSettings.AcmeUrl,
		//AcmeEmail:                   runtimeSettings.Email,
		Db:                          db,
		IamSvc:                      iam.New(sess),
		CloudFront:                  cloudfront.New(sess),
		ElbNames:                    albNames,
		ElbSvc:                      elbv2.New(sess),
		ElbUpdateFrequencyInSeconds: 15,
		//PersistentDnsProvider:       true,
		//DnsChallengeProvider:        nil,
		//Resolvers:                   runtimeSettings.Resolvers,
		LogLevel:                    runtimeSettings.LogLevel,
		Logger:                      logger,
	}

	workerManager, err := managers.NewWorkerManager(workerManagerSettings)
	if err != nil {
		panic(fmt.Errorf("cannot instantiate worker manager, %s", err))
	}

	domainBrokerSettings := &broker.DomainBrokerSettings{
		Db:            db,
		Logger:        logger,
		WorkerManager: workerManager,
	}

	settings = &types.GlobalSettings{
		Db:                    db,
		Logger:                logger,
		RuntimeSettings:       runtimeSettings,
		IamSvc:                iam.New(sess),
		CloudFront:            cloudfront.New(sess),
		ElbSvc:                elbv2.New(sess),
		PersistentDnsProvider: true,
		DnsChallengeProvider:  nil,
		AcmeHttpClient:        http.DefaultClient,
		Resolvers:             runtimeSettings.Resolvers,
	}

	return broker.NewDomainBroker(domainBrokerSettings), db
}

func bindHTTPHandlers(handler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	Bind(mux)

	return mux
}

//var checks = map[string]func(types.RuntimeSettings) error{
//	"cloudfoundry": Cloudfoundry,
//	"postgresql":   Postgresql,
//}

// todo (mxplusb): fix the health checks to be more comprehensive
func Bind(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		body := ""
		//for name, function := range checks {
		//	err := function(settings)
		//	if err != nil {
		//		body = body + fmt.Sprintf("%s error: %s\n", name, err)
		//	}
		//}
		if body != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "%s", body)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
}

//func Postgresql() {
//	db := settings.Db.DB()
//
//	ticker := time.NewTicker(time.Second * 5)
//
//	for ; true; <-ticker.C {
//		return db.Ping()
//	}
//}

//func Cloudfoundry(settings types.RuntimeSettings) error {
//	// We're only validating that the CF endpoint is contactable here, as
//	// testing the authentication is tricky
//	_, err := cfclient.NewClient(&cfclient.Config{
//		ApiAddress:   settings.CfApiAddress,
//		ClientID:     settings.ClientID,
//		ClientSecret: settings.ClientSecret,
//		HttpClient: &http.Client{
//			Timeout: time.Second * 10,
//		},
//	})
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
