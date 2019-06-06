package broker

import (
	"github.com/18f/cf-domain-broker/interfaces"
	"github.com/18f/cf-domain-broker/types"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/sirupsen/logrus"
)

type DomainBroker struct {
	manager  interfaces.RouteManager
	cfclient cfclient.Client
	settings types.Settings
	logger   logrus.Logger
}
