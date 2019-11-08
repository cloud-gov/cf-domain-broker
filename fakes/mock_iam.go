package fakes

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/pborman/uuid"
)

type MockIAMAPI struct {
	VpcId string
	uploadedCertificates []*iam.UploadServerCertificateOutput
}

func NewMockIAMAPI() *MockIAMAPI {
	return &MockIAMAPI{
		VpcId: fmt.Sprintf("test-vpc-%s", uuid.New()[len(uuid.New())-4:]),
	}
}

func (iamsvc *MockIAMAPI) Arner(name string) string {
	return fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:%s:loadbalancer/net/%s/%s",
		iamsvc.VpcId,
		name,
		strings.Replace(uuid.New()[len(uuid.New())-17:], "-", "", -1))
}

func (iamsvc *MockIAMAPI) AddClientIDToOpenIDConnectProvider(*iam.AddClientIDToOpenIDConnectProviderInput) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddClientIDToOpenIDConnectProviderWithContext(aws.Context, *iam.AddClientIDToOpenIDConnectProviderInput, ...request.Option) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddClientIDToOpenIDConnectProviderRequest(*iam.AddClientIDToOpenIDConnectProviderInput) (*request.Request, *iam.AddClientIDToOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddRoleToInstanceProfile(*iam.AddRoleToInstanceProfileInput) (*iam.AddRoleToInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddRoleToInstanceProfileWithContext(aws.Context, *iam.AddRoleToInstanceProfileInput, ...request.Option) (*iam.AddRoleToInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddRoleToInstanceProfileRequest(*iam.AddRoleToInstanceProfileInput) (*request.Request, *iam.AddRoleToInstanceProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddUserToGroup(*iam.AddUserToGroupInput) (*iam.AddUserToGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddUserToGroupWithContext(aws.Context, *iam.AddUserToGroupInput, ...request.Option) (*iam.AddUserToGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AddUserToGroupRequest(*iam.AddUserToGroupInput) (*request.Request, *iam.AddUserToGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachGroupPolicy(*iam.AttachGroupPolicyInput) (*iam.AttachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachGroupPolicyWithContext(aws.Context, *iam.AttachGroupPolicyInput, ...request.Option) (*iam.AttachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachGroupPolicyRequest(*iam.AttachGroupPolicyInput) (*request.Request, *iam.AttachGroupPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachRolePolicy(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachRolePolicyWithContext(aws.Context, *iam.AttachRolePolicyInput, ...request.Option) (*iam.AttachRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachRolePolicyRequest(*iam.AttachRolePolicyInput) (*request.Request, *iam.AttachRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachUserPolicy(*iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachUserPolicyWithContext(aws.Context, *iam.AttachUserPolicyInput, ...request.Option) (*iam.AttachUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) AttachUserPolicyRequest(*iam.AttachUserPolicyInput) (*request.Request, *iam.AttachUserPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ChangePassword(*iam.ChangePasswordInput) (*iam.ChangePasswordOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ChangePasswordWithContext(aws.Context, *iam.ChangePasswordInput, ...request.Option) (*iam.ChangePasswordOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ChangePasswordRequest(*iam.ChangePasswordInput) (*request.Request, *iam.ChangePasswordOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccessKey(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccessKeyWithContext(aws.Context, *iam.CreateAccessKeyInput, ...request.Option) (*iam.CreateAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccessKeyRequest(*iam.CreateAccessKeyInput) (*request.Request, *iam.CreateAccessKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccountAlias(*iam.CreateAccountAliasInput) (*iam.CreateAccountAliasOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccountAliasWithContext(aws.Context, *iam.CreateAccountAliasInput, ...request.Option) (*iam.CreateAccountAliasOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateAccountAliasRequest(*iam.CreateAccountAliasInput) (*request.Request, *iam.CreateAccountAliasOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateGroup(*iam.CreateGroupInput) (*iam.CreateGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateGroupWithContext(aws.Context, *iam.CreateGroupInput, ...request.Option) (*iam.CreateGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateGroupRequest(*iam.CreateGroupInput) (*request.Request, *iam.CreateGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateInstanceProfile(*iam.CreateInstanceProfileInput) (*iam.CreateInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateInstanceProfileWithContext(aws.Context, *iam.CreateInstanceProfileInput, ...request.Option) (*iam.CreateInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateInstanceProfileRequest(*iam.CreateInstanceProfileInput) (*request.Request, *iam.CreateInstanceProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateLoginProfile(*iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateLoginProfileWithContext(aws.Context, *iam.CreateLoginProfileInput, ...request.Option) (*iam.CreateLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateLoginProfileRequest(*iam.CreateLoginProfileInput) (*request.Request, *iam.CreateLoginProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateOpenIDConnectProvider(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateOpenIDConnectProviderWithContext(aws.Context, *iam.CreateOpenIDConnectProviderInput, ...request.Option) (*iam.CreateOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateOpenIDConnectProviderRequest(*iam.CreateOpenIDConnectProviderInput) (*request.Request, *iam.CreateOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicy(*iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicyWithContext(aws.Context, *iam.CreatePolicyInput, ...request.Option) (*iam.CreatePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicyRequest(*iam.CreatePolicyInput) (*request.Request, *iam.CreatePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicyVersion(*iam.CreatePolicyVersionInput) (*iam.CreatePolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicyVersionWithContext(aws.Context, *iam.CreatePolicyVersionInput, ...request.Option) (*iam.CreatePolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreatePolicyVersionRequest(*iam.CreatePolicyVersionInput) (*request.Request, *iam.CreatePolicyVersionOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateRole(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateRoleWithContext(aws.Context, *iam.CreateRoleInput, ...request.Option) (*iam.CreateRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateRoleRequest(*iam.CreateRoleInput) (*request.Request, *iam.CreateRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateSAMLProvider(*iam.CreateSAMLProviderInput) (*iam.CreateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateSAMLProviderWithContext(aws.Context, *iam.CreateSAMLProviderInput, ...request.Option) (*iam.CreateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateSAMLProviderRequest(*iam.CreateSAMLProviderInput) (*request.Request, *iam.CreateSAMLProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceLinkedRole(*iam.CreateServiceLinkedRoleInput) (*iam.CreateServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceLinkedRoleWithContext(aws.Context, *iam.CreateServiceLinkedRoleInput, ...request.Option) (*iam.CreateServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceLinkedRoleRequest(*iam.CreateServiceLinkedRoleInput) (*request.Request, *iam.CreateServiceLinkedRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceSpecificCredential(*iam.CreateServiceSpecificCredentialInput) (*iam.CreateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceSpecificCredentialWithContext(aws.Context, *iam.CreateServiceSpecificCredentialInput, ...request.Option) (*iam.CreateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateServiceSpecificCredentialRequest(*iam.CreateServiceSpecificCredentialInput) (*request.Request, *iam.CreateServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateUser(*iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateUserWithContext(aws.Context, *iam.CreateUserInput, ...request.Option) (*iam.CreateUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateUserRequest(*iam.CreateUserInput) (*request.Request, *iam.CreateUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateVirtualMFADevice(*iam.CreateVirtualMFADeviceInput) (*iam.CreateVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateVirtualMFADeviceWithContext(aws.Context, *iam.CreateVirtualMFADeviceInput, ...request.Option) (*iam.CreateVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) CreateVirtualMFADeviceRequest(*iam.CreateVirtualMFADeviceInput) (*request.Request, *iam.CreateVirtualMFADeviceOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeactivateMFADevice(*iam.DeactivateMFADeviceInput) (*iam.DeactivateMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeactivateMFADeviceWithContext(aws.Context, *iam.DeactivateMFADeviceInput, ...request.Option) (*iam.DeactivateMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeactivateMFADeviceRequest(*iam.DeactivateMFADeviceInput) (*request.Request, *iam.DeactivateMFADeviceOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccessKey(*iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccessKeyWithContext(aws.Context, *iam.DeleteAccessKeyInput, ...request.Option) (*iam.DeleteAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccessKeyRequest(*iam.DeleteAccessKeyInput) (*request.Request, *iam.DeleteAccessKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountAlias(*iam.DeleteAccountAliasInput) (*iam.DeleteAccountAliasOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountAliasWithContext(aws.Context, *iam.DeleteAccountAliasInput, ...request.Option) (*iam.DeleteAccountAliasOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountAliasRequest(*iam.DeleteAccountAliasInput) (*request.Request, *iam.DeleteAccountAliasOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountPasswordPolicy(*iam.DeleteAccountPasswordPolicyInput) (*iam.DeleteAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountPasswordPolicyWithContext(aws.Context, *iam.DeleteAccountPasswordPolicyInput, ...request.Option) (*iam.DeleteAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteAccountPasswordPolicyRequest(*iam.DeleteAccountPasswordPolicyInput) (*request.Request, *iam.DeleteAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroup(*iam.DeleteGroupInput) (*iam.DeleteGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroupWithContext(aws.Context, *iam.DeleteGroupInput, ...request.Option) (*iam.DeleteGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroupRequest(*iam.DeleteGroupInput) (*request.Request, *iam.DeleteGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroupPolicy(*iam.DeleteGroupPolicyInput) (*iam.DeleteGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroupPolicyWithContext(aws.Context, *iam.DeleteGroupPolicyInput, ...request.Option) (*iam.DeleteGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteGroupPolicyRequest(*iam.DeleteGroupPolicyInput) (*request.Request, *iam.DeleteGroupPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteInstanceProfile(*iam.DeleteInstanceProfileInput) (*iam.DeleteInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteInstanceProfileWithContext(aws.Context, *iam.DeleteInstanceProfileInput, ...request.Option) (*iam.DeleteInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteInstanceProfileRequest(*iam.DeleteInstanceProfileInput) (*request.Request, *iam.DeleteInstanceProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteLoginProfile(*iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteLoginProfileWithContext(aws.Context, *iam.DeleteLoginProfileInput, ...request.Option) (*iam.DeleteLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteLoginProfileRequest(*iam.DeleteLoginProfileInput) (*request.Request, *iam.DeleteLoginProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteOpenIDConnectProvider(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteOpenIDConnectProviderWithContext(aws.Context, *iam.DeleteOpenIDConnectProviderInput, ...request.Option) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteOpenIDConnectProviderRequest(*iam.DeleteOpenIDConnectProviderInput) (*request.Request, *iam.DeleteOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicy(*iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicyWithContext(aws.Context, *iam.DeletePolicyInput, ...request.Option) (*iam.DeletePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicyRequest(*iam.DeletePolicyInput) (*request.Request, *iam.DeletePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicyVersion(*iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicyVersionWithContext(aws.Context, *iam.DeletePolicyVersionInput, ...request.Option) (*iam.DeletePolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeletePolicyVersionRequest(*iam.DeletePolicyVersionInput) (*request.Request, *iam.DeletePolicyVersionOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRole(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRoleWithContext(aws.Context, *iam.DeleteRoleInput, ...request.Option) (*iam.DeleteRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRoleRequest(*iam.DeleteRoleInput) (*request.Request, *iam.DeleteRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePermissionsBoundary(*iam.DeleteRolePermissionsBoundaryInput) (*iam.DeleteRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePermissionsBoundaryWithContext(aws.Context, *iam.DeleteRolePermissionsBoundaryInput, ...request.Option) (*iam.DeleteRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePermissionsBoundaryRequest(*iam.DeleteRolePermissionsBoundaryInput) (*request.Request, *iam.DeleteRolePermissionsBoundaryOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePolicy(*iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePolicyWithContext(aws.Context, *iam.DeleteRolePolicyInput, ...request.Option) (*iam.DeleteRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteRolePolicyRequest(*iam.DeleteRolePolicyInput) (*request.Request, *iam.DeleteRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSAMLProvider(*iam.DeleteSAMLProviderInput) (*iam.DeleteSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSAMLProviderWithContext(aws.Context, *iam.DeleteSAMLProviderInput, ...request.Option) (*iam.DeleteSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSAMLProviderRequest(*iam.DeleteSAMLProviderInput) (*request.Request, *iam.DeleteSAMLProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSSHPublicKey(*iam.DeleteSSHPublicKeyInput) (*iam.DeleteSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSSHPublicKeyWithContext(aws.Context, *iam.DeleteSSHPublicKeyInput, ...request.Option) (*iam.DeleteSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSSHPublicKeyRequest(*iam.DeleteSSHPublicKeyInput) (*request.Request, *iam.DeleteSSHPublicKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServerCertificate(input *iam.DeleteServerCertificateInput) (*iam.DeleteServerCertificateOutput, error) {
	return &iam.DeleteServerCertificateOutput{}, nil
}

func (iamsvc *MockIAMAPI) DeleteServerCertificateWithContext(aws.Context, *iam.DeleteServerCertificateInput, ...request.Option) (*iam.DeleteServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServerCertificateRequest(*iam.DeleteServerCertificateInput) (*request.Request, *iam.DeleteServerCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceLinkedRole(*iam.DeleteServiceLinkedRoleInput) (*iam.DeleteServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceLinkedRoleWithContext(aws.Context, *iam.DeleteServiceLinkedRoleInput, ...request.Option) (*iam.DeleteServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceLinkedRoleRequest(*iam.DeleteServiceLinkedRoleInput) (*request.Request, *iam.DeleteServiceLinkedRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceSpecificCredential(*iam.DeleteServiceSpecificCredentialInput) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceSpecificCredentialWithContext(aws.Context, *iam.DeleteServiceSpecificCredentialInput, ...request.Option) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteServiceSpecificCredentialRequest(*iam.DeleteServiceSpecificCredentialInput) (*request.Request, *iam.DeleteServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSigningCertificate(*iam.DeleteSigningCertificateInput) (*iam.DeleteSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSigningCertificateWithContext(aws.Context, *iam.DeleteSigningCertificateInput, ...request.Option) (*iam.DeleteSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteSigningCertificateRequest(*iam.DeleteSigningCertificateInput) (*request.Request, *iam.DeleteSigningCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUser(*iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserWithContext(aws.Context, *iam.DeleteUserInput, ...request.Option) (*iam.DeleteUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserRequest(*iam.DeleteUserInput) (*request.Request, *iam.DeleteUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPermissionsBoundary(*iam.DeleteUserPermissionsBoundaryInput) (*iam.DeleteUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPermissionsBoundaryWithContext(aws.Context, *iam.DeleteUserPermissionsBoundaryInput, ...request.Option) (*iam.DeleteUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPermissionsBoundaryRequest(*iam.DeleteUserPermissionsBoundaryInput) (*request.Request, *iam.DeleteUserPermissionsBoundaryOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPolicy(*iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPolicyWithContext(aws.Context, *iam.DeleteUserPolicyInput, ...request.Option) (*iam.DeleteUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteUserPolicyRequest(*iam.DeleteUserPolicyInput) (*request.Request, *iam.DeleteUserPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteVirtualMFADevice(*iam.DeleteVirtualMFADeviceInput) (*iam.DeleteVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteVirtualMFADeviceWithContext(aws.Context, *iam.DeleteVirtualMFADeviceInput, ...request.Option) (*iam.DeleteVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DeleteVirtualMFADeviceRequest(*iam.DeleteVirtualMFADeviceInput) (*request.Request, *iam.DeleteVirtualMFADeviceOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachGroupPolicy(*iam.DetachGroupPolicyInput) (*iam.DetachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachGroupPolicyWithContext(aws.Context, *iam.DetachGroupPolicyInput, ...request.Option) (*iam.DetachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachGroupPolicyRequest(*iam.DetachGroupPolicyInput) (*request.Request, *iam.DetachGroupPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachRolePolicy(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachRolePolicyWithContext(aws.Context, *iam.DetachRolePolicyInput, ...request.Option) (*iam.DetachRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachRolePolicyRequest(*iam.DetachRolePolicyInput) (*request.Request, *iam.DetachRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachUserPolicy(*iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachUserPolicyWithContext(aws.Context, *iam.DetachUserPolicyInput, ...request.Option) (*iam.DetachUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) DetachUserPolicyRequest(*iam.DetachUserPolicyInput) (*request.Request, *iam.DetachUserPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) EnableMFADevice(*iam.EnableMFADeviceInput) (*iam.EnableMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) EnableMFADeviceWithContext(aws.Context, *iam.EnableMFADeviceInput, ...request.Option) (*iam.EnableMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) EnableMFADeviceRequest(*iam.EnableMFADeviceInput) (*request.Request, *iam.EnableMFADeviceOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateCredentialReport(*iam.GenerateCredentialReportInput) (*iam.GenerateCredentialReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateCredentialReportWithContext(aws.Context, *iam.GenerateCredentialReportInput, ...request.Option) (*iam.GenerateCredentialReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateCredentialReportRequest(*iam.GenerateCredentialReportInput) (*request.Request, *iam.GenerateCredentialReportOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateOrganizationsAccessReport(*iam.GenerateOrganizationsAccessReportInput) (*iam.GenerateOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateOrganizationsAccessReportWithContext(aws.Context, *iam.GenerateOrganizationsAccessReportInput, ...request.Option) (*iam.GenerateOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateOrganizationsAccessReportRequest(*iam.GenerateOrganizationsAccessReportInput) (*request.Request, *iam.GenerateOrganizationsAccessReportOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateServiceLastAccessedDetails(*iam.GenerateServiceLastAccessedDetailsInput) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateServiceLastAccessedDetailsWithContext(aws.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...request.Option) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GenerateServiceLastAccessedDetailsRequest(*iam.GenerateServiceLastAccessedDetailsInput) (*request.Request, *iam.GenerateServiceLastAccessedDetailsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccessKeyLastUsed(*iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccessKeyLastUsedWithContext(aws.Context, *iam.GetAccessKeyLastUsedInput, ...request.Option) (*iam.GetAccessKeyLastUsedOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccessKeyLastUsedRequest(*iam.GetAccessKeyLastUsedInput) (*request.Request, *iam.GetAccessKeyLastUsedOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountAuthorizationDetails(*iam.GetAccountAuthorizationDetailsInput) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountAuthorizationDetailsWithContext(aws.Context, *iam.GetAccountAuthorizationDetailsInput, ...request.Option) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountAuthorizationDetailsRequest(*iam.GetAccountAuthorizationDetailsInput) (*request.Request, *iam.GetAccountAuthorizationDetailsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountAuthorizationDetailsPages(*iam.GetAccountAuthorizationDetailsInput, func(*iam.GetAccountAuthorizationDetailsOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountAuthorizationDetailsPagesWithContext(aws.Context, *iam.GetAccountAuthorizationDetailsInput, func(*iam.GetAccountAuthorizationDetailsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountPasswordPolicy(*iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountPasswordPolicyWithContext(aws.Context, *iam.GetAccountPasswordPolicyInput, ...request.Option) (*iam.GetAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountPasswordPolicyRequest(*iam.GetAccountPasswordPolicyInput) (*request.Request, *iam.GetAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountSummary(*iam.GetAccountSummaryInput) (*iam.GetAccountSummaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountSummaryWithContext(aws.Context, *iam.GetAccountSummaryInput, ...request.Option) (*iam.GetAccountSummaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetAccountSummaryRequest(*iam.GetAccountSummaryInput) (*request.Request, *iam.GetAccountSummaryOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForCustomPolicy(*iam.GetContextKeysForCustomPolicyInput) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForCustomPolicyWithContext(aws.Context, *iam.GetContextKeysForCustomPolicyInput, ...request.Option) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForCustomPolicyRequest(*iam.GetContextKeysForCustomPolicyInput) (*request.Request, *iam.GetContextKeysForPolicyResponse) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForPrincipalPolicy(*iam.GetContextKeysForPrincipalPolicyInput) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForPrincipalPolicyWithContext(aws.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...request.Option) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetContextKeysForPrincipalPolicyRequest(*iam.GetContextKeysForPrincipalPolicyInput) (*request.Request, *iam.GetContextKeysForPolicyResponse) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetCredentialReport(*iam.GetCredentialReportInput) (*iam.GetCredentialReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetCredentialReportWithContext(aws.Context, *iam.GetCredentialReportInput, ...request.Option) (*iam.GetCredentialReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetCredentialReportRequest(*iam.GetCredentialReportInput) (*request.Request, *iam.GetCredentialReportOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroup(*iam.GetGroupInput) (*iam.GetGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupWithContext(aws.Context, *iam.GetGroupInput, ...request.Option) (*iam.GetGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupRequest(*iam.GetGroupInput) (*request.Request, *iam.GetGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupPages(*iam.GetGroupInput, func(*iam.GetGroupOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupPagesWithContext(aws.Context, *iam.GetGroupInput, func(*iam.GetGroupOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupPolicy(*iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupPolicyWithContext(aws.Context, *iam.GetGroupPolicyInput, ...request.Option) (*iam.GetGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetGroupPolicyRequest(*iam.GetGroupPolicyInput) (*request.Request, *iam.GetGroupPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetInstanceProfile(*iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetInstanceProfileRequest(*iam.GetInstanceProfileInput) (*request.Request, *iam.GetInstanceProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetLoginProfile(*iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetLoginProfileWithContext(aws.Context, *iam.GetLoginProfileInput, ...request.Option) (*iam.GetLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetLoginProfileRequest(*iam.GetLoginProfileInput) (*request.Request, *iam.GetLoginProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOpenIDConnectProvider(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOpenIDConnectProviderWithContext(aws.Context, *iam.GetOpenIDConnectProviderInput, ...request.Option) (*iam.GetOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOpenIDConnectProviderRequest(*iam.GetOpenIDConnectProviderInput) (*request.Request, *iam.GetOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOrganizationsAccessReport(*iam.GetOrganizationsAccessReportInput) (*iam.GetOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOrganizationsAccessReportWithContext(aws.Context, *iam.GetOrganizationsAccessReportInput, ...request.Option) (*iam.GetOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetOrganizationsAccessReportRequest(*iam.GetOrganizationsAccessReportInput) (*request.Request, *iam.GetOrganizationsAccessReportOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicy(*iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicyWithContext(aws.Context, *iam.GetPolicyInput, ...request.Option) (*iam.GetPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicyRequest(*iam.GetPolicyInput) (*request.Request, *iam.GetPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicyVersion(*iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicyVersionWithContext(aws.Context, *iam.GetPolicyVersionInput, ...request.Option) (*iam.GetPolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetPolicyVersionRequest(*iam.GetPolicyVersionInput) (*request.Request, *iam.GetPolicyVersionOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRole(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRoleWithContext(aws.Context, *iam.GetRoleInput, ...request.Option) (*iam.GetRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRoleRequest(*iam.GetRoleInput) (*request.Request, *iam.GetRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRolePolicy(*iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRolePolicyWithContext(aws.Context, *iam.GetRolePolicyInput, ...request.Option) (*iam.GetRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetRolePolicyRequest(*iam.GetRolePolicyInput) (*request.Request, *iam.GetRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSAMLProvider(*iam.GetSAMLProviderInput) (*iam.GetSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSAMLProviderWithContext(aws.Context, *iam.GetSAMLProviderInput, ...request.Option) (*iam.GetSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSAMLProviderRequest(*iam.GetSAMLProviderInput) (*request.Request, *iam.GetSAMLProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSSHPublicKey(*iam.GetSSHPublicKeyInput) (*iam.GetSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSSHPublicKeyWithContext(aws.Context, *iam.GetSSHPublicKeyInput, ...request.Option) (*iam.GetSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetSSHPublicKeyRequest(*iam.GetSSHPublicKeyInput) (*request.Request, *iam.GetSSHPublicKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServerCertificate(*iam.GetServerCertificateInput) (*iam.GetServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServerCertificateWithContext(aws.Context, *iam.GetServerCertificateInput, ...request.Option) (*iam.GetServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServerCertificateRequest(*iam.GetServerCertificateInput) (*request.Request, *iam.GetServerCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetails(*iam.GetServiceLastAccessedDetailsInput) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetailsWithContext(aws.Context, *iam.GetServiceLastAccessedDetailsInput, ...request.Option) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetailsRequest(*iam.GetServiceLastAccessedDetailsInput) (*request.Request, *iam.GetServiceLastAccessedDetailsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetailsWithEntities(*iam.GetServiceLastAccessedDetailsWithEntitiesInput) (*iam.GetServiceLastAccessedDetailsWithEntitiesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetailsWithEntitiesWithContext(aws.Context, *iam.GetServiceLastAccessedDetailsWithEntitiesInput, ...request.Option) (*iam.GetServiceLastAccessedDetailsWithEntitiesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLastAccessedDetailsWithEntitiesRequest(*iam.GetServiceLastAccessedDetailsWithEntitiesInput) (*request.Request, *iam.GetServiceLastAccessedDetailsWithEntitiesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLinkedRoleDeletionStatus(*iam.GetServiceLinkedRoleDeletionStatusInput) (*iam.GetServiceLinkedRoleDeletionStatusOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLinkedRoleDeletionStatusWithContext(aws.Context, *iam.GetServiceLinkedRoleDeletionStatusInput, ...request.Option) (*iam.GetServiceLinkedRoleDeletionStatusOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetServiceLinkedRoleDeletionStatusRequest(*iam.GetServiceLinkedRoleDeletionStatusInput) (*request.Request, *iam.GetServiceLinkedRoleDeletionStatusOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUser(*iam.GetUserInput) (*iam.GetUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUserWithContext(aws.Context, *iam.GetUserInput, ...request.Option) (*iam.GetUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUserRequest(*iam.GetUserInput) (*request.Request, *iam.GetUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUserPolicy(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUserPolicyWithContext(aws.Context, *iam.GetUserPolicyInput, ...request.Option) (*iam.GetUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) GetUserPolicyRequest(*iam.GetUserPolicyInput) (*request.Request, *iam.GetUserPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccessKeys(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccessKeysWithContext(aws.Context, *iam.ListAccessKeysInput, ...request.Option) (*iam.ListAccessKeysOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccessKeysRequest(*iam.ListAccessKeysInput) (*request.Request, *iam.ListAccessKeysOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccessKeysPages(*iam.ListAccessKeysInput, func(*iam.ListAccessKeysOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccessKeysPagesWithContext(aws.Context, *iam.ListAccessKeysInput, func(*iam.ListAccessKeysOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccountAliases(*iam.ListAccountAliasesInput) (*iam.ListAccountAliasesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccountAliasesWithContext(aws.Context, *iam.ListAccountAliasesInput, ...request.Option) (*iam.ListAccountAliasesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccountAliasesRequest(*iam.ListAccountAliasesInput) (*request.Request, *iam.ListAccountAliasesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccountAliasesPages(*iam.ListAccountAliasesInput, func(*iam.ListAccountAliasesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAccountAliasesPagesWithContext(aws.Context, *iam.ListAccountAliasesInput, func(*iam.ListAccountAliasesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedGroupPolicies(*iam.ListAttachedGroupPoliciesInput) (*iam.ListAttachedGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedGroupPoliciesWithContext(aws.Context, *iam.ListAttachedGroupPoliciesInput, ...request.Option) (*iam.ListAttachedGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedGroupPoliciesRequest(*iam.ListAttachedGroupPoliciesInput) (*request.Request, *iam.ListAttachedGroupPoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedGroupPoliciesPages(*iam.ListAttachedGroupPoliciesInput, func(*iam.ListAttachedGroupPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedGroupPoliciesPagesWithContext(aws.Context, *iam.ListAttachedGroupPoliciesInput, func(*iam.ListAttachedGroupPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedRolePolicies(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedRolePoliciesWithContext(aws.Context, *iam.ListAttachedRolePoliciesInput, ...request.Option) (*iam.ListAttachedRolePoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedRolePoliciesRequest(*iam.ListAttachedRolePoliciesInput) (*request.Request, *iam.ListAttachedRolePoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedRolePoliciesPages(*iam.ListAttachedRolePoliciesInput, func(*iam.ListAttachedRolePoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedRolePoliciesPagesWithContext(aws.Context, *iam.ListAttachedRolePoliciesInput, func(*iam.ListAttachedRolePoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedUserPolicies(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedUserPoliciesWithContext(aws.Context, *iam.ListAttachedUserPoliciesInput, ...request.Option) (*iam.ListAttachedUserPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedUserPoliciesRequest(*iam.ListAttachedUserPoliciesInput) (*request.Request, *iam.ListAttachedUserPoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedUserPoliciesPages(*iam.ListAttachedUserPoliciesInput, func(*iam.ListAttachedUserPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListAttachedUserPoliciesPagesWithContext(aws.Context, *iam.ListAttachedUserPoliciesInput, func(*iam.ListAttachedUserPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListEntitiesForPolicy(*iam.ListEntitiesForPolicyInput) (*iam.ListEntitiesForPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListEntitiesForPolicyWithContext(aws.Context, *iam.ListEntitiesForPolicyInput, ...request.Option) (*iam.ListEntitiesForPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListEntitiesForPolicyRequest(*iam.ListEntitiesForPolicyInput) (*request.Request, *iam.ListEntitiesForPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListEntitiesForPolicyPages(*iam.ListEntitiesForPolicyInput, func(*iam.ListEntitiesForPolicyOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListEntitiesForPolicyPagesWithContext(aws.Context, *iam.ListEntitiesForPolicyInput, func(*iam.ListEntitiesForPolicyOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupPolicies(*iam.ListGroupPoliciesInput) (*iam.ListGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupPoliciesWithContext(aws.Context, *iam.ListGroupPoliciesInput, ...request.Option) (*iam.ListGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupPoliciesRequest(*iam.ListGroupPoliciesInput) (*request.Request, *iam.ListGroupPoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupPoliciesPages(*iam.ListGroupPoliciesInput, func(*iam.ListGroupPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupPoliciesPagesWithContext(aws.Context, *iam.ListGroupPoliciesInput, func(*iam.ListGroupPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroups(*iam.ListGroupsInput) (*iam.ListGroupsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsWithContext(aws.Context, *iam.ListGroupsInput, ...request.Option) (*iam.ListGroupsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsRequest(*iam.ListGroupsInput) (*request.Request, *iam.ListGroupsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsPages(*iam.ListGroupsInput, func(*iam.ListGroupsOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsPagesWithContext(aws.Context, *iam.ListGroupsInput, func(*iam.ListGroupsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsForUser(*iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsForUserWithContext(aws.Context, *iam.ListGroupsForUserInput, ...request.Option) (*iam.ListGroupsForUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsForUserRequest(*iam.ListGroupsForUserInput) (*request.Request, *iam.ListGroupsForUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsForUserPages(*iam.ListGroupsForUserInput, func(*iam.ListGroupsForUserOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListGroupsForUserPagesWithContext(aws.Context, *iam.ListGroupsForUserInput, func(*iam.ListGroupsForUserOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfiles(*iam.ListInstanceProfilesInput) (*iam.ListInstanceProfilesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesWithContext(aws.Context, *iam.ListInstanceProfilesInput, ...request.Option) (*iam.ListInstanceProfilesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesRequest(*iam.ListInstanceProfilesInput) (*request.Request, *iam.ListInstanceProfilesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesPages(*iam.ListInstanceProfilesInput, func(*iam.ListInstanceProfilesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesPagesWithContext(aws.Context, *iam.ListInstanceProfilesInput, func(*iam.ListInstanceProfilesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesForRole(*iam.ListInstanceProfilesForRoleInput) (*iam.ListInstanceProfilesForRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesForRoleWithContext(aws.Context, *iam.ListInstanceProfilesForRoleInput, ...request.Option) (*iam.ListInstanceProfilesForRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesForRoleRequest(*iam.ListInstanceProfilesForRoleInput) (*request.Request, *iam.ListInstanceProfilesForRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesForRolePages(*iam.ListInstanceProfilesForRoleInput, func(*iam.ListInstanceProfilesForRoleOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListInstanceProfilesForRolePagesWithContext(aws.Context, *iam.ListInstanceProfilesForRoleInput, func(*iam.ListInstanceProfilesForRoleOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListMFADevices(*iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListMFADevicesWithContext(aws.Context, *iam.ListMFADevicesInput, ...request.Option) (*iam.ListMFADevicesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListMFADevicesRequest(*iam.ListMFADevicesInput) (*request.Request, *iam.ListMFADevicesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListMFADevicesPages(*iam.ListMFADevicesInput, func(*iam.ListMFADevicesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListMFADevicesPagesWithContext(aws.Context, *iam.ListMFADevicesInput, func(*iam.ListMFADevicesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListOpenIDConnectProviders(*iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListOpenIDConnectProvidersWithContext(aws.Context, *iam.ListOpenIDConnectProvidersInput, ...request.Option) (*iam.ListOpenIDConnectProvidersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListOpenIDConnectProvidersRequest(*iam.ListOpenIDConnectProvidersInput) (*request.Request, *iam.ListOpenIDConnectProvidersOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicies(*iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesWithContext(aws.Context, *iam.ListPoliciesInput, ...request.Option) (*iam.ListPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesRequest(*iam.ListPoliciesInput) (*request.Request, *iam.ListPoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesPages(*iam.ListPoliciesInput, func(*iam.ListPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesPagesWithContext(aws.Context, *iam.ListPoliciesInput, func(*iam.ListPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesGrantingServiceAccess(*iam.ListPoliciesGrantingServiceAccessInput) (*iam.ListPoliciesGrantingServiceAccessOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesGrantingServiceAccessWithContext(aws.Context, *iam.ListPoliciesGrantingServiceAccessInput, ...request.Option) (*iam.ListPoliciesGrantingServiceAccessOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPoliciesGrantingServiceAccessRequest(*iam.ListPoliciesGrantingServiceAccessInput) (*request.Request, *iam.ListPoliciesGrantingServiceAccessOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicyVersions(*iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicyVersionsWithContext(aws.Context, *iam.ListPolicyVersionsInput, ...request.Option) (*iam.ListPolicyVersionsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicyVersionsRequest(*iam.ListPolicyVersionsInput) (*request.Request, *iam.ListPolicyVersionsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicyVersionsPages(*iam.ListPolicyVersionsInput, func(*iam.ListPolicyVersionsOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListPolicyVersionsPagesWithContext(aws.Context, *iam.ListPolicyVersionsInput, func(*iam.ListPolicyVersionsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolePolicies(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolePoliciesWithContext(aws.Context, *iam.ListRolePoliciesInput, ...request.Option) (*iam.ListRolePoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolePoliciesRequest(*iam.ListRolePoliciesInput) (*request.Request, *iam.ListRolePoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolePoliciesPages(*iam.ListRolePoliciesInput, func(*iam.ListRolePoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolePoliciesPagesWithContext(aws.Context, *iam.ListRolePoliciesInput, func(*iam.ListRolePoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRoleTags(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRoleTagsWithContext(aws.Context, *iam.ListRoleTagsInput, ...request.Option) (*iam.ListRoleTagsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRoleTagsRequest(*iam.ListRoleTagsInput) (*request.Request, *iam.ListRoleTagsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRoles(*iam.ListRolesInput) (*iam.ListRolesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolesWithContext(aws.Context, *iam.ListRolesInput, ...request.Option) (*iam.ListRolesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolesRequest(*iam.ListRolesInput) (*request.Request, *iam.ListRolesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolesPages(*iam.ListRolesInput, func(*iam.ListRolesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListRolesPagesWithContext(aws.Context, *iam.ListRolesInput, func(*iam.ListRolesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSAMLProviders(*iam.ListSAMLProvidersInput) (*iam.ListSAMLProvidersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSAMLProvidersWithContext(aws.Context, *iam.ListSAMLProvidersInput, ...request.Option) (*iam.ListSAMLProvidersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSAMLProvidersRequest(*iam.ListSAMLProvidersInput) (*request.Request, *iam.ListSAMLProvidersOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSSHPublicKeys(*iam.ListSSHPublicKeysInput) (*iam.ListSSHPublicKeysOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSSHPublicKeysWithContext(aws.Context, *iam.ListSSHPublicKeysInput, ...request.Option) (*iam.ListSSHPublicKeysOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSSHPublicKeysRequest(*iam.ListSSHPublicKeysInput) (*request.Request, *iam.ListSSHPublicKeysOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSSHPublicKeysPages(*iam.ListSSHPublicKeysInput, func(*iam.ListSSHPublicKeysOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSSHPublicKeysPagesWithContext(aws.Context, *iam.ListSSHPublicKeysInput, func(*iam.ListSSHPublicKeysOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServerCertificates(*iam.ListServerCertificatesInput) (*iam.ListServerCertificatesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServerCertificatesWithContext(aws.Context, *iam.ListServerCertificatesInput, ...request.Option) (*iam.ListServerCertificatesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServerCertificatesRequest(*iam.ListServerCertificatesInput) (*request.Request, *iam.ListServerCertificatesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServerCertificatesPages(*iam.ListServerCertificatesInput, func(*iam.ListServerCertificatesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServerCertificatesPagesWithContext(aws.Context, *iam.ListServerCertificatesInput, func(*iam.ListServerCertificatesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServiceSpecificCredentials(*iam.ListServiceSpecificCredentialsInput) (*iam.ListServiceSpecificCredentialsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServiceSpecificCredentialsWithContext(aws.Context, *iam.ListServiceSpecificCredentialsInput, ...request.Option) (*iam.ListServiceSpecificCredentialsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListServiceSpecificCredentialsRequest(*iam.ListServiceSpecificCredentialsInput) (*request.Request, *iam.ListServiceSpecificCredentialsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSigningCertificates(*iam.ListSigningCertificatesInput) (*iam.ListSigningCertificatesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSigningCertificatesWithContext(aws.Context, *iam.ListSigningCertificatesInput, ...request.Option) (*iam.ListSigningCertificatesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSigningCertificatesRequest(*iam.ListSigningCertificatesInput) (*request.Request, *iam.ListSigningCertificatesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSigningCertificatesPages(*iam.ListSigningCertificatesInput, func(*iam.ListSigningCertificatesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListSigningCertificatesPagesWithContext(aws.Context, *iam.ListSigningCertificatesInput, func(*iam.ListSigningCertificatesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserPoliciesWithContext(aws.Context, *iam.ListUserPoliciesInput, ...request.Option) (*iam.ListUserPoliciesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserPoliciesRequest(*iam.ListUserPoliciesInput) (*request.Request, *iam.ListUserPoliciesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserPoliciesPages(*iam.ListUserPoliciesInput, func(*iam.ListUserPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserPoliciesPagesWithContext(aws.Context, *iam.ListUserPoliciesInput, func(*iam.ListUserPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserTags(*iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserTagsWithContext(aws.Context, *iam.ListUserTagsInput, ...request.Option) (*iam.ListUserTagsOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUserTagsRequest(*iam.ListUserTagsInput) (*request.Request, *iam.ListUserTagsOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUsers(*iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUsersWithContext(aws.Context, *iam.ListUsersInput, ...request.Option) (*iam.ListUsersOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUsersRequest(*iam.ListUsersInput) (*request.Request, *iam.ListUsersOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUsersPages(*iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListUsersPagesWithContext(aws.Context, *iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListVirtualMFADevices(*iam.ListVirtualMFADevicesInput) (*iam.ListVirtualMFADevicesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListVirtualMFADevicesWithContext(aws.Context, *iam.ListVirtualMFADevicesInput, ...request.Option) (*iam.ListVirtualMFADevicesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListVirtualMFADevicesRequest(*iam.ListVirtualMFADevicesInput) (*request.Request, *iam.ListVirtualMFADevicesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListVirtualMFADevicesPages(*iam.ListVirtualMFADevicesInput, func(*iam.ListVirtualMFADevicesOutput, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ListVirtualMFADevicesPagesWithContext(aws.Context, *iam.ListVirtualMFADevicesInput, func(*iam.ListVirtualMFADevicesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutGroupPolicy(*iam.PutGroupPolicyInput) (*iam.PutGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutGroupPolicyWithContext(aws.Context, *iam.PutGroupPolicyInput, ...request.Option) (*iam.PutGroupPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutGroupPolicyRequest(*iam.PutGroupPolicyInput) (*request.Request, *iam.PutGroupPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePermissionsBoundary(*iam.PutRolePermissionsBoundaryInput) (*iam.PutRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePermissionsBoundaryWithContext(aws.Context, *iam.PutRolePermissionsBoundaryInput, ...request.Option) (*iam.PutRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePermissionsBoundaryRequest(*iam.PutRolePermissionsBoundaryInput) (*request.Request, *iam.PutRolePermissionsBoundaryOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePolicy(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePolicyWithContext(aws.Context, *iam.PutRolePolicyInput, ...request.Option) (*iam.PutRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutRolePolicyRequest(*iam.PutRolePolicyInput) (*request.Request, *iam.PutRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPermissionsBoundary(*iam.PutUserPermissionsBoundaryInput) (*iam.PutUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPermissionsBoundaryWithContext(aws.Context, *iam.PutUserPermissionsBoundaryInput, ...request.Option) (*iam.PutUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPermissionsBoundaryRequest(*iam.PutUserPermissionsBoundaryInput) (*request.Request, *iam.PutUserPermissionsBoundaryOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPolicy(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPolicyWithContext(aws.Context, *iam.PutUserPolicyInput, ...request.Option) (*iam.PutUserPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) PutUserPolicyRequest(*iam.PutUserPolicyInput) (*request.Request, *iam.PutUserPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveClientIDFromOpenIDConnectProvider(*iam.RemoveClientIDFromOpenIDConnectProviderInput) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveClientIDFromOpenIDConnectProviderWithContext(aws.Context, *iam.RemoveClientIDFromOpenIDConnectProviderInput, ...request.Option) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveClientIDFromOpenIDConnectProviderRequest(*iam.RemoveClientIDFromOpenIDConnectProviderInput) (*request.Request, *iam.RemoveClientIDFromOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveRoleFromInstanceProfile(*iam.RemoveRoleFromInstanceProfileInput) (*iam.RemoveRoleFromInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveRoleFromInstanceProfileWithContext(aws.Context, *iam.RemoveRoleFromInstanceProfileInput, ...request.Option) (*iam.RemoveRoleFromInstanceProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveRoleFromInstanceProfileRequest(*iam.RemoveRoleFromInstanceProfileInput) (*request.Request, *iam.RemoveRoleFromInstanceProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveUserFromGroup(*iam.RemoveUserFromGroupInput) (*iam.RemoveUserFromGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveUserFromGroupWithContext(aws.Context, *iam.RemoveUserFromGroupInput, ...request.Option) (*iam.RemoveUserFromGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) RemoveUserFromGroupRequest(*iam.RemoveUserFromGroupInput) (*request.Request, *iam.RemoveUserFromGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResetServiceSpecificCredential(*iam.ResetServiceSpecificCredentialInput) (*iam.ResetServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResetServiceSpecificCredentialWithContext(aws.Context, *iam.ResetServiceSpecificCredentialInput, ...request.Option) (*iam.ResetServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResetServiceSpecificCredentialRequest(*iam.ResetServiceSpecificCredentialInput) (*request.Request, *iam.ResetServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResyncMFADevice(*iam.ResyncMFADeviceInput) (*iam.ResyncMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResyncMFADeviceWithContext(aws.Context, *iam.ResyncMFADeviceInput, ...request.Option) (*iam.ResyncMFADeviceOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) ResyncMFADeviceRequest(*iam.ResyncMFADeviceInput) (*request.Request, *iam.ResyncMFADeviceOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetDefaultPolicyVersion(*iam.SetDefaultPolicyVersionInput) (*iam.SetDefaultPolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetDefaultPolicyVersionWithContext(aws.Context, *iam.SetDefaultPolicyVersionInput, ...request.Option) (*iam.SetDefaultPolicyVersionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetDefaultPolicyVersionRequest(*iam.SetDefaultPolicyVersionInput) (*request.Request, *iam.SetDefaultPolicyVersionOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetSecurityTokenServicePreferences(*iam.SetSecurityTokenServicePreferencesInput) (*iam.SetSecurityTokenServicePreferencesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetSecurityTokenServicePreferencesWithContext(aws.Context, *iam.SetSecurityTokenServicePreferencesInput, ...request.Option) (*iam.SetSecurityTokenServicePreferencesOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SetSecurityTokenServicePreferencesRequest(*iam.SetSecurityTokenServicePreferencesInput) (*request.Request, *iam.SetSecurityTokenServicePreferencesOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulateCustomPolicy(*iam.SimulateCustomPolicyInput) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulateCustomPolicyWithContext(aws.Context, *iam.SimulateCustomPolicyInput, ...request.Option) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulateCustomPolicyRequest(*iam.SimulateCustomPolicyInput) (*request.Request, *iam.SimulatePolicyResponse) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulateCustomPolicyPages(*iam.SimulateCustomPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulateCustomPolicyPagesWithContext(aws.Context, *iam.SimulateCustomPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulatePrincipalPolicy(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulatePrincipalPolicyWithContext(aws.Context, *iam.SimulatePrincipalPolicyInput, ...request.Option) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulatePrincipalPolicyRequest(*iam.SimulatePrincipalPolicyInput) (*request.Request, *iam.SimulatePolicyResponse) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulatePrincipalPolicyPages(*iam.SimulatePrincipalPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) SimulatePrincipalPolicyPagesWithContext(aws.Context, *iam.SimulatePrincipalPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagRole(*iam.TagRoleInput) (*iam.TagRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagRoleWithContext(aws.Context, *iam.TagRoleInput, ...request.Option) (*iam.TagRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagRoleRequest(*iam.TagRoleInput) (*request.Request, *iam.TagRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagUser(*iam.TagUserInput) (*iam.TagUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagUserWithContext(aws.Context, *iam.TagUserInput, ...request.Option) (*iam.TagUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) TagUserRequest(*iam.TagUserInput) (*request.Request, *iam.TagUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagRole(*iam.UntagRoleInput) (*iam.UntagRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagRoleWithContext(aws.Context, *iam.UntagRoleInput, ...request.Option) (*iam.UntagRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagRoleRequest(*iam.UntagRoleInput) (*request.Request, *iam.UntagRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagUser(*iam.UntagUserInput) (*iam.UntagUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagUserWithContext(aws.Context, *iam.UntagUserInput, ...request.Option) (*iam.UntagUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UntagUserRequest(*iam.UntagUserInput) (*request.Request, *iam.UntagUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccessKey(*iam.UpdateAccessKeyInput) (*iam.UpdateAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccessKeyWithContext(aws.Context, *iam.UpdateAccessKeyInput, ...request.Option) (*iam.UpdateAccessKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccessKeyRequest(*iam.UpdateAccessKeyInput) (*request.Request, *iam.UpdateAccessKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccountPasswordPolicy(*iam.UpdateAccountPasswordPolicyInput) (*iam.UpdateAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccountPasswordPolicyWithContext(aws.Context, *iam.UpdateAccountPasswordPolicyInput, ...request.Option) (*iam.UpdateAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAccountPasswordPolicyRequest(*iam.UpdateAccountPasswordPolicyInput) (*request.Request, *iam.UpdateAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAssumeRolePolicy(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAssumeRolePolicyWithContext(aws.Context, *iam.UpdateAssumeRolePolicyInput, ...request.Option) (*iam.UpdateAssumeRolePolicyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateAssumeRolePolicyRequest(*iam.UpdateAssumeRolePolicyInput) (*request.Request, *iam.UpdateAssumeRolePolicyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateGroup(*iam.UpdateGroupInput) (*iam.UpdateGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateGroupWithContext(aws.Context, *iam.UpdateGroupInput, ...request.Option) (*iam.UpdateGroupOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateGroupRequest(*iam.UpdateGroupInput) (*request.Request, *iam.UpdateGroupOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateLoginProfile(*iam.UpdateLoginProfileInput) (*iam.UpdateLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateLoginProfileWithContext(aws.Context, *iam.UpdateLoginProfileInput, ...request.Option) (*iam.UpdateLoginProfileOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateLoginProfileRequest(*iam.UpdateLoginProfileInput) (*request.Request, *iam.UpdateLoginProfileOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateOpenIDConnectProviderThumbprint(*iam.UpdateOpenIDConnectProviderThumbprintInput) (*iam.UpdateOpenIDConnectProviderThumbprintOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateOpenIDConnectProviderThumbprintWithContext(aws.Context, *iam.UpdateOpenIDConnectProviderThumbprintInput, ...request.Option) (*iam.UpdateOpenIDConnectProviderThumbprintOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateOpenIDConnectProviderThumbprintRequest(*iam.UpdateOpenIDConnectProviderThumbprintInput) (*request.Request, *iam.UpdateOpenIDConnectProviderThumbprintOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRole(*iam.UpdateRoleInput) (*iam.UpdateRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRoleWithContext(aws.Context, *iam.UpdateRoleInput, ...request.Option) (*iam.UpdateRoleOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRoleRequest(*iam.UpdateRoleInput) (*request.Request, *iam.UpdateRoleOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRoleDescription(*iam.UpdateRoleDescriptionInput) (*iam.UpdateRoleDescriptionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRoleDescriptionWithContext(aws.Context, *iam.UpdateRoleDescriptionInput, ...request.Option) (*iam.UpdateRoleDescriptionOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateRoleDescriptionRequest(*iam.UpdateRoleDescriptionInput) (*request.Request, *iam.UpdateRoleDescriptionOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSAMLProvider(*iam.UpdateSAMLProviderInput) (*iam.UpdateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSAMLProviderWithContext(aws.Context, *iam.UpdateSAMLProviderInput, ...request.Option) (*iam.UpdateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSAMLProviderRequest(*iam.UpdateSAMLProviderInput) (*request.Request, *iam.UpdateSAMLProviderOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSSHPublicKey(*iam.UpdateSSHPublicKeyInput) (*iam.UpdateSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSSHPublicKeyWithContext(aws.Context, *iam.UpdateSSHPublicKeyInput, ...request.Option) (*iam.UpdateSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSSHPublicKeyRequest(*iam.UpdateSSHPublicKeyInput) (*request.Request, *iam.UpdateSSHPublicKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServerCertificate(*iam.UpdateServerCertificateInput) (*iam.UpdateServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServerCertificateWithContext(aws.Context, *iam.UpdateServerCertificateInput, ...request.Option) (*iam.UpdateServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServerCertificateRequest(*iam.UpdateServerCertificateInput) (*request.Request, *iam.UpdateServerCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServiceSpecificCredential(*iam.UpdateServiceSpecificCredentialInput) (*iam.UpdateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServiceSpecificCredentialWithContext(aws.Context, *iam.UpdateServiceSpecificCredentialInput, ...request.Option) (*iam.UpdateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateServiceSpecificCredentialRequest(*iam.UpdateServiceSpecificCredentialInput) (*request.Request, *iam.UpdateServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSigningCertificate(*iam.UpdateSigningCertificateInput) (*iam.UpdateSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSigningCertificateWithContext(aws.Context, *iam.UpdateSigningCertificateInput, ...request.Option) (*iam.UpdateSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateSigningCertificateRequest(*iam.UpdateSigningCertificateInput) (*request.Request, *iam.UpdateSigningCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateUser(*iam.UpdateUserInput) (*iam.UpdateUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateUserWithContext(aws.Context, *iam.UpdateUserInput, ...request.Option) (*iam.UpdateUserOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UpdateUserRequest(*iam.UpdateUserInput) (*request.Request, *iam.UpdateUserOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSSHPublicKey(*iam.UploadSSHPublicKeyInput) (*iam.UploadSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSSHPublicKeyWithContext(aws.Context, *iam.UploadSSHPublicKeyInput, ...request.Option) (*iam.UploadSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSSHPublicKeyRequest(*iam.UploadSSHPublicKeyInput) (*request.Request, *iam.UploadSSHPublicKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadServerCertificate(input *iam.UploadServerCertificateInput) (*iam.UploadServerCertificateOutput, error) {
	certInput := &iam.UploadServerCertificateOutput{
		ServerCertificateMetadata: &iam.ServerCertificateMetadata{
			Arn: aws.String(iamsvc.Arner(*input.ServerCertificateName)),
		},
	}
	iamsvc.uploadedCertificates = append(iamsvc.uploadedCertificates, certInput)
	return certInput, nil
}

func (iamsvc *MockIAMAPI) UploadServerCertificateWithContext(aws.Context, *iam.UploadServerCertificateInput, ...request.Option) (*iam.UploadServerCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadServerCertificateRequest(*iam.UploadServerCertificateInput) (*request.Request, *iam.UploadServerCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSigningCertificate(*iam.UploadSigningCertificateInput) (*iam.UploadSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSigningCertificateWithContext(aws.Context, *iam.UploadSigningCertificateInput, ...request.Option) (*iam.UploadSigningCertificateOutput, error) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadSigningCertificateRequest(*iam.UploadSigningCertificateInput) (*request.Request, *iam.UploadSigningCertificateOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilInstanceProfileExists(*iam.GetInstanceProfileInput) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilInstanceProfileExistsWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilPolicyExists(*iam.GetPolicyInput) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilPolicyExistsWithContext(aws.Context, *iam.GetPolicyInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilRoleExists(*iam.GetRoleInput) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilRoleExistsWithContext(aws.Context, *iam.GetRoleInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilUserExists(*iam.GetUserInput) error {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) WaitUntilUserExistsWithContext(aws.Context, *iam.GetUserInput, ...request.WaiterOption) error {
	panic("implement me")
}
