module github.com/18f/cf-domain-broker

go 1.12

require (
	cloud.google.com/go v0.40.0 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/18F/cf-domain-broker-alb v0.0.0-20190801182336-1085344d9032
	github.com/18f/gravel v0.0.0-20191119175617-eff5e3f82bc5
	github.com/aws/aws-sdk-go v1.25.37
	github.com/drewolson/testflight v1.0.0 // indirect
	github.com/go-acme/lego/v3 v3.2.0
	github.com/jinzhu/gorm v1.9.11
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.2.0 // indirect
	github.com/miekg/dns v1.1.22
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pivotal-cf/brokerapi v6.4.2+incompatible
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20191117063200-497ca9f6d64f // indirect
	golang.org/x/net v0.0.0-20191119073136-fc4aabc6c914 // indirect
	golang.org/x/sys v0.0.0-20191119060738-e882bf8e40c2 // indirect
	google.golang.org/appengine v1.6.5 // indirect
)

replace (
	golang.org/x/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	golang.org/x/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
)
