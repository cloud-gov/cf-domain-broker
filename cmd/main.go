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
	"github.com/go-pg/pg/v9"
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
	if err := db.Insert(&managers.ProcInfo{Start: startTime}); err != nil {
		panic(fmt.Errorf("cannot save start time, %s", err))
	}

	// block forever, until we shut down.
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer func() {
		cancel()
	}()

	// we're stopping, so go ahead and mark that too.
	var procInfo managers.ProcInfo
	if err := db.Model(&procInfo).Where("start = ?", startTime).First(); err != nil {
		if err := db.Insert(managers.ProcInfo{Stop: time.Now()}); err != nil {
			panic(fmt.Errorf("cannot save current stop time: %s", err))
		}
	} else {
		if err := db.Update(managers.ProcInfo{Stop: time.Now()}); err != nil {
			panic(fmt.Errorf("cannot save stop time: %s", err))
		}
	}

	if err := srv.Shutdown(ctx); err != nil {
		settings.Logger.Fatal("server-not-stopping-cleanly", err)
	}
	settings.Logger.Info("goodbye")
}

// todo (mxplusb): make this more cf friendly.
func initBrokerConfig() (*broker.DomainBroker, *pg.DB) {
	// before anything else, we need to grab our config so we know what to do.
	var runtimeSettings types.RuntimeSettings
	err := envconfig.Process("", &runtimeSettings)
	if err != nil {
		panic(fmt.Errorf("cannot read environment variables for configuration, %s", err))
	}

	// set up our logging writers.
	debugSink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	errorSink := lager.NewPrettySink(os.Stderr, lager.ERROR)
	fatalSink := lager.NewPrettySink(os.Stderr, lager.FATAL)

	logger := lager.NewLogger("main")
	logger.RegisterSink(debugSink)
	logger.RegisterSink(errorSink)
	logger.RegisterSink(fatalSink)

	// open up the database and prepare it
	// todo (mxplusb): ensure this uses the right connection string, might need more env vars or to parse vcap services
	db := pg.Connect(&pg.Options{Addr: ""})

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
		Db:                          db,
		IamSvc:                      iam.New(sess),
		CloudFront:                  cloudfront.New(sess),
		ElbNames:                    albNames,
		ElbSvc:                      elbv2.New(sess),
		ElbUpdateFrequencyInSeconds: 15,
		LogLevel:                    runtimeSettings.LogLevel,
		Logger:                      logger,
	}

	// todo (mxplusb): lego config, elb request, resolvers, and private key.
	obtainmentManagerSettings := &managers.ObtainmentManagerSettings{
		Autostart:             true,
		Db:                    db,
		ElbRequest:            nil,
		Logger:                logger,
		PersistentDnsProvider: true,
	}

	stateManagerSettings := &managers.StateManagerSettings{
		Autostart: true,
		AutoPoll:  true,
		Db:        db,
		Logger:    logger,
	}

	gm, err := managers.NewGlobalQueueManager(&managers.GlobalQueueManagerSettings{
		Autostart:                 true,
		QueueDepth:                150,
		ObtainmentManagerSettings: obtainmentManagerSettings,
		StateManagerSettings:      stateManagerSettings,
		WorkerManagerSettings:     workerManagerSettings,
	})
	if err != nil {
		panic(err)
	}

	domainBrokerSettings := &broker.DomainBrokerSettings{
		Logger:             logger,
		GlobalQueueManager: gm,
	}

	settings = &types.GlobalSettings{
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
