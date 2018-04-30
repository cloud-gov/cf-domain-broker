package healthchecks

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"

	"github.com/18F/cf-domain-broker-alb/config"
)

func ALB(settings config.Settings) error {
	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))
	svc := elbv2.New(session)

	_, err := svc.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{})
	return err
}
