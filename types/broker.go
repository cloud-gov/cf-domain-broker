package types

import (
	"github.com/18f/cf-domain-broker/interfaces"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
)

type BrokerOptions struct {
	Domain         string   `json:"domain"`
	Origin         string   `json:"origin"`
	Path           string   `json:"path"`
	InsecureOrigin bool     `json:"insecure_origin"`
	Cookies        bool     `json:"cookies"`
	Headers        []string `json:"headers"`
	Cdn            bool     `json:"cdn"`
}

type DomainOptions struct {
	Domains []string `json:"domains"`
}

type DomainBroker struct {
	manager  interfaces.RouteManager
	cfclient cfclient.Client
	settings Settings
	logger   logrus.Logger
}

type RouteManager struct {
	logger     logrus.Logger
	iam        interfaces.Iam
	cloudFront interfaces.Distribution
	settings   Settings
	db         *gorm.DB
	elbSvc     elbv2iface.ELBV2API
}
