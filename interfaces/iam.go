package interfaces

import (
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/xenolf/lego/acme"
)

type Iam interface {
	UploadCertificate(name string, cert acme.CertificateResource) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error
}
