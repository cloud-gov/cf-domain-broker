package managers

import (
	"github.com/go-acme/lego/v3/certificate"
)

// Our certificate representation in the database.
type Certificate struct {
	*certificate.Resource `gorm:"not_null"`
	InstanceId            string `gorm:"primary_key"`
	ARN                   string
}
