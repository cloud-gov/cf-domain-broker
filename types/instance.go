package types

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
}
