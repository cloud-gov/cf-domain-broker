package models

import (
	"github.com/go-acme/lego/v3/certificate"
	"github.com/jinzhu/gorm"
)

type Certificate struct {
	gorm.Model
	Resource *certificate.Resource
}
