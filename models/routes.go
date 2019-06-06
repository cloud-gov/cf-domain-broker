package models

import (
	"github.com/18f/cf-domain-broker/types"
	"github.com/jinzhu/gorm"
	"time"
)

type Certificate struct {
	gorm.Model
	Id          string `gorm:"primary_key"`
	RouteId     uint
	Domain      string
	CertURL     string
	Certificate []byte
	Expires     time.Time
	ARN         string
	Name        string
}

// DomainRoute is a single response type for both custom domains and CDN domains.
type DomainRoute struct {
	gorm.Model
	InstanceId     string `gorm:"not null;unique_index;primary_key"`
	ChallengeJSON  []byte
	DomainExternal string
	DomainInternal string

	// Cloudfront Distribution Id.
	DistId         string
	Origin         string
	Path           string
	InsecureOrigin bool
	Certificate    Certificate `gorm:"foreignkey:CertRef"`
	UserData       UserData `gorm:"foreignkey:UserRef"`
	ALBProxy       types.ALBProxy
	ALBProxyARN    string
}
