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
	Domains []Domain `json:"domains"`
}

type DomainString struct {
	Domains []string `json:"domains"`
}

// todo (mxplusb): finish plumbing all of this.
type RuntimeSettings struct {
	ALBNames             []string `envconfig:"alb_names" required:"true"`
	AcmeUrl              string   `envconfig:"acme_url" required:"true"`
	AwsAccessKeyId       string   `envconfig:"aws_access_key_id" required:"true"`
	AwsDefaultRegion     string   `envconfig:"aws_default_region" required:"true"`
	AwsSecretAccessKey   string   `envconfig:"aws_secret_access_key" required:"true"`
	BrokerPassword       string   `envconfig:"broker_password" required:"true"`
	BrokerUsername       string   `envconfig:"broker_username" required:"true"`
	Bucket               string   `envconfig:"bucket" required:"true"`
	CfApiAddress         string   `envconfig:"cf_api_address" required:"true"`
	DatabaseUrl          string   `envconfig:"database_url" required:"true"`
	Email                string   `envconfig:"email" required:"true"`
	IamPathPrefix        string   `envconfig:"iam_path_prefix" default:"/domains-broker-v2/"`
	MaxRoutes            int      `envconfig:"max_routes" default:"24"`
	Port                 string   `envconfig:"port" default:"3000"`
	RenewDays            int      `envconfig:"renew_days" default:"30"`
	Resolvers            Resolver `envconfig:"resolvers" default:"cloudflare:1.1.1.1"`
	Schedule             string   `envconfig:"schedule" default:"0 0 * * * *"`
	ServerSideEncryption string   `envconfig:"server_side_encryption"`

	/*
		Sets the logging level of the program. The higher the number, the less this will log.

		1 = log.Debug("Useful debugging information.")
		2 = log.Info("Something noteworthy happened!")
		3 = log.Error("Something failed but I'm not quitting.")
		4 = log.Fatal("Bye.")
	*/
	LogLevel int `envconfig:"log_level" default:"1"`
}

// Domain is an instance of a domain.
type Domain struct {
	Value string
}
