package models

import "github.com/jinzhu/gorm"

type UserData struct {
	gorm.Model
	Id string `gorm:"primary_key"`
	Email string `gorm:"not null"`
	Reg   []byte
	Key   []byte
}
