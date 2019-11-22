package models

import (
	"github.com/go-acme/lego/v3/certificate"
)

type Certificate struct {
	*certificate.Resource `gorm:"not_null"`
	InstanceId            string `gorm:primary_key`
	ARN                   string
}
