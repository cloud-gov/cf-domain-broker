package models

import (
	"github.com/18f/cf-domain-broker/managers"
	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/jinzhu/gorm"
)

// Our certificate representation in the database.
type Certificate struct {
	*certificate.Resource `gorm:"not_null"`
	InstanceId            string `gorm:"primary_key"`
	ARN                   string
}

// The checkpoint state of a provisioning certificate
type ObtainCheckpoint struct {
	gorm.Model
	ObtainRequest  managers.ObtainRequest
	Order          acme.ExtendedOrder
	State          managers.ObtainState
	Authorizations []acme.Authorization
	CSR            []byte
	InstanceId     string `gorm:"primary_key"`
}
