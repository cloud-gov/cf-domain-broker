module github.com/18f/cf-domain-broker

go 1.12

require (
	cloud.google.com/go v0.40.0 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/18F/cf-cdn-service-broker v0.0.0-20190603161008-b2df4416bef5 // indirect
	github.com/18F/cf-domain-broker-alb v0.0.0-20190801182336-1085344d9032
	github.com/18f/gravel v0.0.0-20191108205842-be9f275d6d6f
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/aws/aws-sdk-go v1.25.30
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190808214049-35bcce23fc5f
	github.com/drewolson/testflight v1.0.0 // indirect
	github.com/go-acme/lego v2.7.2+incompatible // indirect
	github.com/go-acme/lego/v3 v3.1.0
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.9.5 // indirect
	github.com/jinzhu/gorm v1.9.11
	github.com/jmcarp/lego v0.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.2.0 // indirect
	github.com/maxbrunsfeld/counterfeiter/v6 v6.2.2 // indirect
	github.com/miekg/dns v1.1.22
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pivotal-cf/brokerapi v6.4.2+incompatible
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/xenolf/lego v2.7.2+incompatible // indirect
	golang.org/x/lint v0.0.0-20190511005446-959b441ac422 // indirect
	golang.org/x/net v0.0.0-20191108174545-380dde419d29 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	gopkg.in/square/go-jose.v1 v1.1.2 // indirect
)

replace (
	golang.org/x/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	golang.org/x/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
)
