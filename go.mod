module github.com/18f/cf-domain-broker

go 1.12

require (
	cloud.google.com/go v0.40.0 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/18F/cf-cdn-service-broker v0.0.0-20190603161008-b2df4416bef5 // indirect
	github.com/18F/cf-domain-broker-alb v0.0.0-20190604210022-931b786921e7
	github.com/18f/gravel v0.0.0-20190808204658-76b9a5bd8c5b
	github.com/aws/aws-sdk-go v1.22.3
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190611131856-16c98753d315
	github.com/drewolson/testflight v1.0.0 // indirect
	github.com/go-acme/lego v2.7.2+incompatible // indirect
	github.com/go-acme/lego/v3 v3.0.0
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/jinzhu/gorm v1.9.8
	github.com/jmcarp/lego v0.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.1.1 // indirect
	github.com/maxbrunsfeld/counterfeiter/v6 v6.2.2 // indirect
	github.com/miekg/dns v1.1.15
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pivotal-cf/brokerapi v5.0.0+incompatible
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/xenolf/lego v2.7.2+incompatible // indirect
	google.golang.org/appengine v1.6.1 // indirect
	gopkg.in/square/go-jose.v1 v1.1.2 // indirect
)

replace (
	golang.org/x/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	golang.org/x/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
)
