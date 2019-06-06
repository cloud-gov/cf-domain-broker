package types

import (
	"github.com/aws/aws-sdk-go/service/cloudfront/cloudfrontiface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type CloudfrontDistribution struct {
	Settings Settings
	Service  cloudfrontiface.CloudFrontAPI
}

type ALBProxy struct {
	ALBARN      string `gorm:"primary_key;column:alb_arn"`
	ALBDNSName  string `gorm:"column:alb_dns_name"`
	ListenerARN string
}

type IAM struct {
	Settings Settings
	Service  iamiface.IAMAPI
}
