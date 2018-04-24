package utils

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/xenolf/lego/acme"
)

type IamIface interface {
	UploadCertificate(name, path string, cert acme.CertificateResource) (string, error)
	DeleteCertificate(name string) error
	ListCertificates(path string, callback func(iam.ServerCertificateMetadata) bool) error
}

type Iam struct {
	Service *iam.IAM
}

func (i *Iam) UploadCertificate(name, path string, cert acme.CertificateResource) (string, error) {
	resp, err := i.Service.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(cert.Certificate)),
		PrivateKey:            aws.String(string(cert.PrivateKey)),
		ServerCertificateName: aws.String(name),
		Path: aws.String(path),
	})
	if err != nil {
		return "", err
	}

	return *resp.ServerCertificateMetadata.Arn, nil
}

func (i *Iam) ListCertificates(path string, callback func(iam.ServerCertificateMetadata) bool) error {
	return i.Service.ListServerCertificatesPages(
		&iam.ListServerCertificatesInput{
			PathPrefix: aws.String(path),
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
