package models

import (
	"github.com/jinzhu/gorm"
)

type InstanceStatus struct {
	gorm.Model
	InstanceId string
	Error error
}
