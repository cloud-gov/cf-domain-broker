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

type Route struct {
	gorm.Model
	Id             string `gorm:"primary_key"`
	InstanceId     string `gorm:"not null;unique_index"`
	ChallengeJSON  []byte
	DomainExternal string
	DomainInternal string
	DistId         string
	Origin         string
	Path           string
	InsecureOrigin bool
	Certificate    Certificate `gorm:"foreignkey:CertRef"`
	UserData       types.UserData
	UserDataID     int
	ALBProxy       types.ALBProxy
	ALBProxyARN    string
}
