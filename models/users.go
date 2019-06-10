package models

import (
	"crypto"
	"github.com/go-acme/lego/registration"
	"github.com/jinzhu/gorm"
)

type UserData struct {
	gorm.Model
	Id           string `gorm:"primary_key"`
	Email        string `gorm:"not null"`
	Registration *registration.Resource
	PublicKey    crypto.PublicKey
	PrivateKey   crypto.PrivateKey
}

func (u UserData) GetEmail() string {
	return u.Email
}

func (u UserData) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u UserData) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}
