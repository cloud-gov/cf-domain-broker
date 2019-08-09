package main

import (
	"fmt"
	"net/http"

	"github.com/18f/cf-domain-broker/broker"
	"github.com/18f/cf-domain-broker/models"
	"github.com/18f/cf-domain-broker/routes"
	"github.com/18f/cf-domain-broker/types"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/jinzhu/gorm"
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
	err := envconfig.Process("broker", &settings)
	if err != nil {
		panic(err)
	}

	// now that we have our config, we can start instantiating.
	logger := lager.NewLogger("domain-broker")
	loggerSession := logger.Session("main")

	db, err := gorm.Open("postgres", settings.DatabaseUrl)
	if err != nil {
		loggerSession.Fatal("db-connection-builder", err)
	}

	cf, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress:   settings.APIAddress,
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
	})
	if err != nil {
		loggerSession.Fatal("cf-client-builder", err)
	}

	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))

	if err := db.AutoMigrate(&models.DomainRoute{}, &types.ALBProxy{}, &models.Certificate{}, &models.UserData{}).Error; err != nil {
		loggerSession.Fatal("db-auto-migrate", err)
	}

	rms := loggerSession.Session("route-manager")
	routeManager := routes.NewManager(rms, types.IAM{Settings: settings, Service: iam.New(session)}, types.CloudfrontDistribution{settings, cloudfront.New(session)}, elbv2.New(session), settings, db)

	broker := broker.NewDomainBroker(routeManager, cf, settings, loggerSession)

	credentials := brokerapi.BrokerCredentials{
		Username: settings.BrokerUsername,
		Password: settings.BrokerPassword,
	}

	if err := routeManager.Populate(); err != nil {
		logger.Fatal("populate", err)
	}

	brokerAPI := brokerapi.New(broker, logger, credentials)
	server := bindHTTPHandlers(brokerAPI, settings)
	http.ListenAndServe(fmt.Sprintf(":%s", settings.Port), server)
}

func bindHTTPHandlers(handler http.Handler, settings config.Settings) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	healthchecks.Bind(mux, settings)

	return mux
}
