package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/18f/cf-domain-broker/broker"
	"github.com/18f/cf-domain-broker/interfaces"
	le_providers "github.com/18f/cf-domain-broker/le-providers"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/cloudfoundry-community/go-cfclient"
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

func main() {
	// before anything else, we need to grab our config so we know what to do.
	var settings types.Settings
	err := envconfig.Process("domainBroker", &settings)
	if err != nil {
		panic(err)
	}

	// now that we have our config, we can start instantiating.
	logger := lager.NewLogger("domain-domainBroker")

	sink := lager.NewPrettySink(os.Stdout, lager.DEBUG)
	logger.RegisterSink(sink)

	loggerSession := logger.Session("main")

	db, err := gorm.Open("postgres", settings.DatabaseUrl)
	if err != nil {
		loggerSession.Fatal("db-connection-builder", err)
	}

	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))

	if err := db.AutoMigrate(&models.DomainRoute{},
		&models.UserData{},
		&models.Domain{},
		&models.Certificate{},
		&le_providers.DomainMessenger{}).Error; err != nil {
		loggerSession.Fatal("db-auto-migrate", err)
	}

	rms := loggerSession.Session("route-manager")
	routeManager, err := routes.NewManager(rms,
		types.IAM{
			Settings: settings,
			Service:  iam.New(session)}.Service,
		&interfaces.CloudfrontDistribution{
			Settings: settings,
			Service:  cloudfront.New(session),
		},
		elbv2.New(session),
		settings,
		db)
	if err != nil {
		loggerSession.Fatal("create-route-manager", err)

	}
	domainBroker := broker.NewDomainBroker(&routeManager, loggerSession)

	credentials := brokerapi.BrokerCredentials{
		Username: settings.BrokerUsername,
		Password: settings.BrokerPassword,
	}

	if err := routeManager.Populate(); err != nil {
		logger.Fatal("populate", err)
	}

	brokerAPI := brokerapi.New(domainBroker, logger, credentials)
	server := bindHTTPHandlers(brokerAPI, settings)
	http.ListenAndServe(fmt.Sprintf(":%s", settings.Port), server)
}

func bindHTTPHandlers(handler http.Handler, settings types.Settings) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	Bind(mux, settings)

	return mux
}

var checks = map[string]func(types.Settings) error{
	"cloudfoundry": Cloudfoundry,
	"postgresql":   Postgresql,
}

func Bind(mux *http.ServeMux, settings types.Settings) {
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		body := ""
		for name, function := range checks {
			err := function(settings)
			if err != nil {
				body = body + fmt.Sprintf("%s error: %s\n", name, err)
			}
		}
		if body != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "%s", body)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})

	mux.HandleFunc("/healthcheck/http", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for name, function := range checks {
		mux.HandleFunc("/healthcheck/"+name, func(w http.ResponseWriter, r *http.Request) {
			err := function(settings)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "%s error: %s", name, err)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		})
	}
}

func Postgresql(settings types.Settings) error {
	db, err := gorm.Open("postgres", settings.DatabaseUrl)
	defer db.Close()

	if err != nil {
		return err
	}

	return nil
}

func Cloudfoundry(settings types.Settings) error {
	// We're only validating that the CF endpoint is contactable here, as
	// testing the authentication is tricky
	_, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress:   settings.APIAddress,
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		HttpClient: &http.Client{
			Timeout: time.Second * 10,
		},
	})
	if err != nil {
		return err
	}

	return nil
}
