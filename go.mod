module github.com/18f/cf-domain-broker

go 1.12

require (
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/18F/cf-cdn-service-broker v0.0.0-20190603161008-b2df4416bef5
	github.com/18F/cf-domain-broker-alb v0.0.0-20190604210022-931b786921e7
	github.com/aws/aws-sdk-go v1.19.44
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190201205600-f136f9222381
	github.com/jinzhu/gorm v1.9.8
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.1.1
	github.com/pivotal-cf/brokerapi v5.0.0+incompatible
	github.com/robfig/cron v1.1.0
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/xenolf/lego v2.6.0+incompatible
)
