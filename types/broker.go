package types

type CdnPlanOptions struct {
	Domain         string   `json:"domain"`
	Origin         string   `json:"origin"`
	Path           string   `json:"path"`
	InsecureOrigin bool     `json:"insecure_origin"`
	Cookies        bool     `json:"cookies"`
	Headers        []string `json:"headers"`
	Cdn            bool     `json:"cdn"`
}

type DomainPlanOptions struct {
	Domains []string `json:"domains"`
}

type Settings struct {
	Port                 string `envconfig:"port" default:"3000"`
	BrokerUsername       string `envconfig:"broker_username" required:"true"`
	BrokerPassword       string `envconfig:"broker_password" required:"true"`
	DatabaseUrl          string `envconfig:"database_url" required:"true"`
	Email                string `envconfig:"email" required:"true"`
	AcmeUrl              string `envconfig:"acme_url" required:"true"`
	Bucket               string `envconfig:"bucket" required:"true"`
	IamPathPrefix        string `envconfig:"iam_path_prefix" default:"/domains-broker/"`
	CloudFrontPrefix     string `envconfig:"cloudfront_prefix" default:""`
	AwsAccessKeyId       string `envconfig:"aws_access_key_id" required:"true"`
	AwsSecretAccessKey   string `envconfig:"aws_secret_access_key" required:"true"`
	AwsDefaultRegion     string `envconfig:"aws_default_region" required:"true"`
	ServerSideEncryption string `envconfig:"server_side_encryption"`
	APIAddress           string `envconfig:"api_address" required:"true"`
	ClientID             string `envconfig:"client_id" required:"true"`
	ClientSecret         string `envconfig:"client_secret" required:"true"`
	DefaultOrigin        string `envconfig:"default_origin" required:"true"`
	Schedule             string `envconfig:"schedule" default:"0 0 * * * *"`
	MaxRoutes            int    `envconfig:"max_routes" default:"24"`
	ALBPrefix            string `envconfig:"alb_prefix" default:"domains-broker"`
	RenewDays            int    `envconfig:"renew_days" default:"30"`

	/*
		Sets the logging level of the program. The higher the number, the less this will log.

		1 = log.Debug("Useful debugging information.")
		2 = log.Info("Something noteworthy happened!")
		3 = log.Error("Something failed but I'm not quitting.")
		4 = log.Fatal("Bye.")
	*/
	LogLevel int `envconfig:"log_level" default:"2"`
}
