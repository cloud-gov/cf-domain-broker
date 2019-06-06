package config

import (
	"github.com/kelseyhightower/envconfig"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/lib/pq"
)


func NewSettings() (Settings, error) {
	var settings Settings
	err := envconfig.Process("cdn", &settings)
	if err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func Connect(settings Settings) (*gorm.DB, error) {
	return gorm.Open("postgres", settings.DatabaseUrl)
}
