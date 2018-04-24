package main

import (
	"os"
	"os/signal"

	"code.cloudfoundry.org/lager"
	"github.com/robfig/cron"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/18F/cf-domain-broker-alb/models"
	"github.com/18F/cf-domain-broker-alb/utils"
)

func main() {
	logger := lager.NewLogger("cdn-cron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.INFO))

	settings, err := config.NewSettings()
	if err != nil {
		logger.Fatal("new-settings", err)
	}

	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))

	db, err := config.Connect(settings)
	if err != nil {
		logger.Fatal("connect", err)
	}

	if err := db.AutoMigrate(&models.Route{}, &models.Certificate{}, &models.UserData{}).Error; err != nil {
		logger.Fatal("migrate", err)
	}

	manager := models.NewManager(
		logger,
		&utils.Iam{settings, iam.New(session)},
		elbv2.New(session),
		settings,
		db,
	)

	c := cron.New()

	c.AddFunc(settings.Schedule, func() {
		logger.Info("Running renew")
		manager.RenewAll()
	})

	c.AddFunc(settings.Schedule, func() {
		logger.Info("Running cert cleanup")
		manager.DeleteOrphanedCerts()
	})

	logger.Info("Starting cron")
	c.Start()

	waitForExit()
}

func waitForExit() os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	return <-c
}
