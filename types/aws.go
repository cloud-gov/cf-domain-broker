package types

import (
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/iam"
)

type Distribution struct {
	Settings Settings
	Service  *cloudfront.CloudFront
}

type ALBProxy struct {
	ALBARN      string `gorm:"primary_key;column:alb_arn"`
	ALBDNSName  string `gorm:"column:alb_dns_name"`
	ListenerARN string
}

type IamSettings struct {
	Settings Settings
	Service  *iam.IAM
}
