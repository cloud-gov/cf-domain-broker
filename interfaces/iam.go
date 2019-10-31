package interfaces

import (
	"fmt"

	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-acme/lego/v3/certificate"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . IamCertificateManager
type IamCertificateManager interface {
	UploadCertificate(name string, resource certificate.Resource) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error
}

type Iam struct {
	Settings config.Settings
	Service  *iam.IAM
}

func (i *Iam) UploadCertificate(name string, cert certificate.Resource) (string, error) {
	resp, err := i.Service.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(cert.Certificate)),
		PrivateKey:            aws.String(string(cert.PrivateKey)),
		ServerCertificateName: aws.String(name),
		Path:                  aws.String(fmt.Sprintf("/cloudfront/%s/", i.Settings.IamPathPrefix)),
	})
	if err != nil {
		return "", err
	}

	return *resp.ServerCertificateMetadata.ServerCertificateId, nil
}

func (i *Iam) ListCertificates(callback func(iam.ServerCertificateMetadata) bool) error {
	return i.Service.ListServerCertificatesPages(
		&iam.ListServerCertificatesInput{
			PathPrefix: aws.String(fmt.Sprintf("/cloudfront/%s/", i.Settings.IamPathPrefix)),
		},
		func(page *iam.ListServerCertificatesOutput, lastPage bool) bool {
			for _, v := range page.ServerCertificateMetadataList {
				// stop iteration if the callback tells us to
				if callback(*v) == false {
					return false
				}
			}

			return true
		},
	)
}

func (i *Iam) DeleteCertificate(name string) error {
	_, err := i.Service.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
		ServerCertificateName: aws.String(name),
	})

	return err
}
