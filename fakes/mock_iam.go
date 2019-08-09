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
}

func NewMockIAMAPI() *MockIAMAPI {
	return &MockIAMAPI{
		VpcId: fmt.Sprintf("test-vpc-%s", uuid.New()[len(uuid.New())-4:]),
	}
}

func (iam *MockIAMAPI) Arner(name string) string {
	return fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:%s:loadbalancer/net/%s/%s",
		iam.VpcId,
		name,
		strings.Replace(uuid.New()[len(uuid.New())-17:], "-", "", -1))
}

func (iam *MockIAMAPI) AddClientIDToOpenIDConnectProvider(*iam.AddClientIDToOpenIDConnectProviderInput) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddClientIDToOpenIDConnectProviderWithContext(aws.Context, *iam.AddClientIDToOpenIDConnectProviderInput, ...request.Option) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddClientIDToOpenIDConnectProviderRequest(*iam.AddClientIDToOpenIDConnectProviderInput) (*request.Request, *iam.AddClientIDToOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddRoleToInstanceProfile(*iam.AddRoleToInstanceProfileInput) (*iam.AddRoleToInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddRoleToInstanceProfileWithContext(aws.Context, *iam.AddRoleToInstanceProfileInput, ...request.Option) (*iam.AddRoleToInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddRoleToInstanceProfileRequest(*iam.AddRoleToInstanceProfileInput) (*request.Request, *iam.AddRoleToInstanceProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddUserToGroup(*iam.AddUserToGroupInput) (*iam.AddUserToGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddUserToGroupWithContext(aws.Context, *iam.AddUserToGroupInput, ...request.Option) (*iam.AddUserToGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AddUserToGroupRequest(*iam.AddUserToGroupInput) (*request.Request, *iam.AddUserToGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachGroupPolicy(*iam.AttachGroupPolicyInput) (*iam.AttachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachGroupPolicyWithContext(aws.Context, *iam.AttachGroupPolicyInput, ...request.Option) (*iam.AttachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachGroupPolicyRequest(*iam.AttachGroupPolicyInput) (*request.Request, *iam.AttachGroupPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachRolePolicy(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachRolePolicyWithContext(aws.Context, *iam.AttachRolePolicyInput, ...request.Option) (*iam.AttachRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachRolePolicyRequest(*iam.AttachRolePolicyInput) (*request.Request, *iam.AttachRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachUserPolicy(*iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachUserPolicyWithContext(aws.Context, *iam.AttachUserPolicyInput, ...request.Option) (*iam.AttachUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) AttachUserPolicyRequest(*iam.AttachUserPolicyInput) (*request.Request, *iam.AttachUserPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ChangePassword(*iam.ChangePasswordInput) (*iam.ChangePasswordOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ChangePasswordWithContext(aws.Context, *iam.ChangePasswordInput, ...request.Option) (*iam.ChangePasswordOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ChangePasswordRequest(*iam.ChangePasswordInput) (*request.Request, *iam.ChangePasswordOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccessKey(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccessKeyWithContext(aws.Context, *iam.CreateAccessKeyInput, ...request.Option) (*iam.CreateAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccessKeyRequest(*iam.CreateAccessKeyInput) (*request.Request, *iam.CreateAccessKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccountAlias(*iam.CreateAccountAliasInput) (*iam.CreateAccountAliasOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccountAliasWithContext(aws.Context, *iam.CreateAccountAliasInput, ...request.Option) (*iam.CreateAccountAliasOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateAccountAliasRequest(*iam.CreateAccountAliasInput) (*request.Request, *iam.CreateAccountAliasOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateGroup(*iam.CreateGroupInput) (*iam.CreateGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateGroupWithContext(aws.Context, *iam.CreateGroupInput, ...request.Option) (*iam.CreateGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateGroupRequest(*iam.CreateGroupInput) (*request.Request, *iam.CreateGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateInstanceProfile(*iam.CreateInstanceProfileInput) (*iam.CreateInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateInstanceProfileWithContext(aws.Context, *iam.CreateInstanceProfileInput, ...request.Option) (*iam.CreateInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateInstanceProfileRequest(*iam.CreateInstanceProfileInput) (*request.Request, *iam.CreateInstanceProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateLoginProfile(*iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateLoginProfileWithContext(aws.Context, *iam.CreateLoginProfileInput, ...request.Option) (*iam.CreateLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateLoginProfileRequest(*iam.CreateLoginProfileInput) (*request.Request, *iam.CreateLoginProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateOpenIDConnectProvider(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateOpenIDConnectProviderWithContext(aws.Context, *iam.CreateOpenIDConnectProviderInput, ...request.Option) (*iam.CreateOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateOpenIDConnectProviderRequest(*iam.CreateOpenIDConnectProviderInput) (*request.Request, *iam.CreateOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicy(*iam.CreatePolicyInput) (*iam.CreatePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicyWithContext(aws.Context, *iam.CreatePolicyInput, ...request.Option) (*iam.CreatePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicyRequest(*iam.CreatePolicyInput) (*request.Request, *iam.CreatePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicyVersion(*iam.CreatePolicyVersionInput) (*iam.CreatePolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicyVersionWithContext(aws.Context, *iam.CreatePolicyVersionInput, ...request.Option) (*iam.CreatePolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreatePolicyVersionRequest(*iam.CreatePolicyVersionInput) (*request.Request, *iam.CreatePolicyVersionOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateRole(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateRoleWithContext(aws.Context, *iam.CreateRoleInput, ...request.Option) (*iam.CreateRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateRoleRequest(*iam.CreateRoleInput) (*request.Request, *iam.CreateRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateSAMLProvider(*iam.CreateSAMLProviderInput) (*iam.CreateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateSAMLProviderWithContext(aws.Context, *iam.CreateSAMLProviderInput, ...request.Option) (*iam.CreateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateSAMLProviderRequest(*iam.CreateSAMLProviderInput) (*request.Request, *iam.CreateSAMLProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceLinkedRole(*iam.CreateServiceLinkedRoleInput) (*iam.CreateServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceLinkedRoleWithContext(aws.Context, *iam.CreateServiceLinkedRoleInput, ...request.Option) (*iam.CreateServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceLinkedRoleRequest(*iam.CreateServiceLinkedRoleInput) (*request.Request, *iam.CreateServiceLinkedRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceSpecificCredential(*iam.CreateServiceSpecificCredentialInput) (*iam.CreateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceSpecificCredentialWithContext(aws.Context, *iam.CreateServiceSpecificCredentialInput, ...request.Option) (*iam.CreateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateServiceSpecificCredentialRequest(*iam.CreateServiceSpecificCredentialInput) (*request.Request, *iam.CreateServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateUser(*iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateUserWithContext(aws.Context, *iam.CreateUserInput, ...request.Option) (*iam.CreateUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateUserRequest(*iam.CreateUserInput) (*request.Request, *iam.CreateUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateVirtualMFADevice(*iam.CreateVirtualMFADeviceInput) (*iam.CreateVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateVirtualMFADeviceWithContext(aws.Context, *iam.CreateVirtualMFADeviceInput, ...request.Option) (*iam.CreateVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) CreateVirtualMFADeviceRequest(*iam.CreateVirtualMFADeviceInput) (*request.Request, *iam.CreateVirtualMFADeviceOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeactivateMFADevice(*iam.DeactivateMFADeviceInput) (*iam.DeactivateMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeactivateMFADeviceWithContext(aws.Context, *iam.DeactivateMFADeviceInput, ...request.Option) (*iam.DeactivateMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeactivateMFADeviceRequest(*iam.DeactivateMFADeviceInput) (*request.Request, *iam.DeactivateMFADeviceOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccessKey(*iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccessKeyWithContext(aws.Context, *iam.DeleteAccessKeyInput, ...request.Option) (*iam.DeleteAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccessKeyRequest(*iam.DeleteAccessKeyInput) (*request.Request, *iam.DeleteAccessKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountAlias(*iam.DeleteAccountAliasInput) (*iam.DeleteAccountAliasOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountAliasWithContext(aws.Context, *iam.DeleteAccountAliasInput, ...request.Option) (*iam.DeleteAccountAliasOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountAliasRequest(*iam.DeleteAccountAliasInput) (*request.Request, *iam.DeleteAccountAliasOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountPasswordPolicy(*iam.DeleteAccountPasswordPolicyInput) (*iam.DeleteAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountPasswordPolicyWithContext(aws.Context, *iam.DeleteAccountPasswordPolicyInput, ...request.Option) (*iam.DeleteAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteAccountPasswordPolicyRequest(*iam.DeleteAccountPasswordPolicyInput) (*request.Request, *iam.DeleteAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroup(*iam.DeleteGroupInput) (*iam.DeleteGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroupWithContext(aws.Context, *iam.DeleteGroupInput, ...request.Option) (*iam.DeleteGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroupRequest(*iam.DeleteGroupInput) (*request.Request, *iam.DeleteGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroupPolicy(*iam.DeleteGroupPolicyInput) (*iam.DeleteGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroupPolicyWithContext(aws.Context, *iam.DeleteGroupPolicyInput, ...request.Option) (*iam.DeleteGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteGroupPolicyRequest(*iam.DeleteGroupPolicyInput) (*request.Request, *iam.DeleteGroupPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteInstanceProfile(*iam.DeleteInstanceProfileInput) (*iam.DeleteInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteInstanceProfileWithContext(aws.Context, *iam.DeleteInstanceProfileInput, ...request.Option) (*iam.DeleteInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteInstanceProfileRequest(*iam.DeleteInstanceProfileInput) (*request.Request, *iam.DeleteInstanceProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteLoginProfile(*iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteLoginProfileWithContext(aws.Context, *iam.DeleteLoginProfileInput, ...request.Option) (*iam.DeleteLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteLoginProfileRequest(*iam.DeleteLoginProfileInput) (*request.Request, *iam.DeleteLoginProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteOpenIDConnectProvider(*iam.DeleteOpenIDConnectProviderInput) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteOpenIDConnectProviderWithContext(aws.Context, *iam.DeleteOpenIDConnectProviderInput, ...request.Option) (*iam.DeleteOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteOpenIDConnectProviderRequest(*iam.DeleteOpenIDConnectProviderInput) (*request.Request, *iam.DeleteOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicy(*iam.DeletePolicyInput) (*iam.DeletePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicyWithContext(aws.Context, *iam.DeletePolicyInput, ...request.Option) (*iam.DeletePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicyRequest(*iam.DeletePolicyInput) (*request.Request, *iam.DeletePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicyVersion(*iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicyVersionWithContext(aws.Context, *iam.DeletePolicyVersionInput, ...request.Option) (*iam.DeletePolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeletePolicyVersionRequest(*iam.DeletePolicyVersionInput) (*request.Request, *iam.DeletePolicyVersionOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRole(*iam.DeleteRoleInput) (*iam.DeleteRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRoleWithContext(aws.Context, *iam.DeleteRoleInput, ...request.Option) (*iam.DeleteRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRoleRequest(*iam.DeleteRoleInput) (*request.Request, *iam.DeleteRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePermissionsBoundary(*iam.DeleteRolePermissionsBoundaryInput) (*iam.DeleteRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePermissionsBoundaryWithContext(aws.Context, *iam.DeleteRolePermissionsBoundaryInput, ...request.Option) (*iam.DeleteRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePermissionsBoundaryRequest(*iam.DeleteRolePermissionsBoundaryInput) (*request.Request, *iam.DeleteRolePermissionsBoundaryOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePolicy(*iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePolicyWithContext(aws.Context, *iam.DeleteRolePolicyInput, ...request.Option) (*iam.DeleteRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteRolePolicyRequest(*iam.DeleteRolePolicyInput) (*request.Request, *iam.DeleteRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSAMLProvider(*iam.DeleteSAMLProviderInput) (*iam.DeleteSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSAMLProviderWithContext(aws.Context, *iam.DeleteSAMLProviderInput, ...request.Option) (*iam.DeleteSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSAMLProviderRequest(*iam.DeleteSAMLProviderInput) (*request.Request, *iam.DeleteSAMLProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSSHPublicKey(*iam.DeleteSSHPublicKeyInput) (*iam.DeleteSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSSHPublicKeyWithContext(aws.Context, *iam.DeleteSSHPublicKeyInput, ...request.Option) (*iam.DeleteSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSSHPublicKeyRequest(*iam.DeleteSSHPublicKeyInput) (*request.Request, *iam.DeleteSSHPublicKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServerCertificate(*iam.DeleteServerCertificateInput) (*iam.DeleteServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServerCertificateWithContext(aws.Context, *iam.DeleteServerCertificateInput, ...request.Option) (*iam.DeleteServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServerCertificateRequest(*iam.DeleteServerCertificateInput) (*request.Request, *iam.DeleteServerCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceLinkedRole(*iam.DeleteServiceLinkedRoleInput) (*iam.DeleteServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceLinkedRoleWithContext(aws.Context, *iam.DeleteServiceLinkedRoleInput, ...request.Option) (*iam.DeleteServiceLinkedRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceLinkedRoleRequest(*iam.DeleteServiceLinkedRoleInput) (*request.Request, *iam.DeleteServiceLinkedRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceSpecificCredential(*iam.DeleteServiceSpecificCredentialInput) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceSpecificCredentialWithContext(aws.Context, *iam.DeleteServiceSpecificCredentialInput, ...request.Option) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteServiceSpecificCredentialRequest(*iam.DeleteServiceSpecificCredentialInput) (*request.Request, *iam.DeleteServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSigningCertificate(*iam.DeleteSigningCertificateInput) (*iam.DeleteSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSigningCertificateWithContext(aws.Context, *iam.DeleteSigningCertificateInput, ...request.Option) (*iam.DeleteSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteSigningCertificateRequest(*iam.DeleteSigningCertificateInput) (*request.Request, *iam.DeleteSigningCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUser(*iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserWithContext(aws.Context, *iam.DeleteUserInput, ...request.Option) (*iam.DeleteUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserRequest(*iam.DeleteUserInput) (*request.Request, *iam.DeleteUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPermissionsBoundary(*iam.DeleteUserPermissionsBoundaryInput) (*iam.DeleteUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPermissionsBoundaryWithContext(aws.Context, *iam.DeleteUserPermissionsBoundaryInput, ...request.Option) (*iam.DeleteUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPermissionsBoundaryRequest(*iam.DeleteUserPermissionsBoundaryInput) (*request.Request, *iam.DeleteUserPermissionsBoundaryOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPolicy(*iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPolicyWithContext(aws.Context, *iam.DeleteUserPolicyInput, ...request.Option) (*iam.DeleteUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteUserPolicyRequest(*iam.DeleteUserPolicyInput) (*request.Request, *iam.DeleteUserPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteVirtualMFADevice(*iam.DeleteVirtualMFADeviceInput) (*iam.DeleteVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteVirtualMFADeviceWithContext(aws.Context, *iam.DeleteVirtualMFADeviceInput, ...request.Option) (*iam.DeleteVirtualMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DeleteVirtualMFADeviceRequest(*iam.DeleteVirtualMFADeviceInput) (*request.Request, *iam.DeleteVirtualMFADeviceOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachGroupPolicy(*iam.DetachGroupPolicyInput) (*iam.DetachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachGroupPolicyWithContext(aws.Context, *iam.DetachGroupPolicyInput, ...request.Option) (*iam.DetachGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachGroupPolicyRequest(*iam.DetachGroupPolicyInput) (*request.Request, *iam.DetachGroupPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachRolePolicy(*iam.DetachRolePolicyInput) (*iam.DetachRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachRolePolicyWithContext(aws.Context, *iam.DetachRolePolicyInput, ...request.Option) (*iam.DetachRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachRolePolicyRequest(*iam.DetachRolePolicyInput) (*request.Request, *iam.DetachRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachUserPolicy(*iam.DetachUserPolicyInput) (*iam.DetachUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachUserPolicyWithContext(aws.Context, *iam.DetachUserPolicyInput, ...request.Option) (*iam.DetachUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) DetachUserPolicyRequest(*iam.DetachUserPolicyInput) (*request.Request, *iam.DetachUserPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) EnableMFADevice(*iam.EnableMFADeviceInput) (*iam.EnableMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) EnableMFADeviceWithContext(aws.Context, *iam.EnableMFADeviceInput, ...request.Option) (*iam.EnableMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) EnableMFADeviceRequest(*iam.EnableMFADeviceInput) (*request.Request, *iam.EnableMFADeviceOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateCredentialReport(*iam.GenerateCredentialReportInput) (*iam.GenerateCredentialReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateCredentialReportWithContext(aws.Context, *iam.GenerateCredentialReportInput, ...request.Option) (*iam.GenerateCredentialReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateCredentialReportRequest(*iam.GenerateCredentialReportInput) (*request.Request, *iam.GenerateCredentialReportOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateOrganizationsAccessReport(*iam.GenerateOrganizationsAccessReportInput) (*iam.GenerateOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateOrganizationsAccessReportWithContext(aws.Context, *iam.GenerateOrganizationsAccessReportInput, ...request.Option) (*iam.GenerateOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateOrganizationsAccessReportRequest(*iam.GenerateOrganizationsAccessReportInput) (*request.Request, *iam.GenerateOrganizationsAccessReportOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateServiceLastAccessedDetails(*iam.GenerateServiceLastAccessedDetailsInput) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateServiceLastAccessedDetailsWithContext(aws.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...request.Option) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GenerateServiceLastAccessedDetailsRequest(*iam.GenerateServiceLastAccessedDetailsInput) (*request.Request, *iam.GenerateServiceLastAccessedDetailsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccessKeyLastUsed(*iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccessKeyLastUsedWithContext(aws.Context, *iam.GetAccessKeyLastUsedInput, ...request.Option) (*iam.GetAccessKeyLastUsedOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccessKeyLastUsedRequest(*iam.GetAccessKeyLastUsedInput) (*request.Request, *iam.GetAccessKeyLastUsedOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountAuthorizationDetails(*iam.GetAccountAuthorizationDetailsInput) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountAuthorizationDetailsWithContext(aws.Context, *iam.GetAccountAuthorizationDetailsInput, ...request.Option) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountAuthorizationDetailsRequest(*iam.GetAccountAuthorizationDetailsInput) (*request.Request, *iam.GetAccountAuthorizationDetailsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountAuthorizationDetailsPages(*iam.GetAccountAuthorizationDetailsInput, func(*iam.GetAccountAuthorizationDetailsOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountAuthorizationDetailsPagesWithContext(aws.Context, *iam.GetAccountAuthorizationDetailsInput, func(*iam.GetAccountAuthorizationDetailsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountPasswordPolicy(*iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountPasswordPolicyWithContext(aws.Context, *iam.GetAccountPasswordPolicyInput, ...request.Option) (*iam.GetAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountPasswordPolicyRequest(*iam.GetAccountPasswordPolicyInput) (*request.Request, *iam.GetAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountSummary(*iam.GetAccountSummaryInput) (*iam.GetAccountSummaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountSummaryWithContext(aws.Context, *iam.GetAccountSummaryInput, ...request.Option) (*iam.GetAccountSummaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetAccountSummaryRequest(*iam.GetAccountSummaryInput) (*request.Request, *iam.GetAccountSummaryOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForCustomPolicy(*iam.GetContextKeysForCustomPolicyInput) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForCustomPolicyWithContext(aws.Context, *iam.GetContextKeysForCustomPolicyInput, ...request.Option) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForCustomPolicyRequest(*iam.GetContextKeysForCustomPolicyInput) (*request.Request, *iam.GetContextKeysForPolicyResponse) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForPrincipalPolicy(*iam.GetContextKeysForPrincipalPolicyInput) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForPrincipalPolicyWithContext(aws.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...request.Option) (*iam.GetContextKeysForPolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetContextKeysForPrincipalPolicyRequest(*iam.GetContextKeysForPrincipalPolicyInput) (*request.Request, *iam.GetContextKeysForPolicyResponse) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetCredentialReport(*iam.GetCredentialReportInput) (*iam.GetCredentialReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetCredentialReportWithContext(aws.Context, *iam.GetCredentialReportInput, ...request.Option) (*iam.GetCredentialReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetCredentialReportRequest(*iam.GetCredentialReportInput) (*request.Request, *iam.GetCredentialReportOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroup(*iam.GetGroupInput) (*iam.GetGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupWithContext(aws.Context, *iam.GetGroupInput, ...request.Option) (*iam.GetGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupRequest(*iam.GetGroupInput) (*request.Request, *iam.GetGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupPages(*iam.GetGroupInput, func(*iam.GetGroupOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupPagesWithContext(aws.Context, *iam.GetGroupInput, func(*iam.GetGroupOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupPolicy(*iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupPolicyWithContext(aws.Context, *iam.GetGroupPolicyInput, ...request.Option) (*iam.GetGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetGroupPolicyRequest(*iam.GetGroupPolicyInput) (*request.Request, *iam.GetGroupPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetInstanceProfile(*iam.GetInstanceProfileInput) (*iam.GetInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetInstanceProfileRequest(*iam.GetInstanceProfileInput) (*request.Request, *iam.GetInstanceProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetLoginProfile(*iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetLoginProfileWithContext(aws.Context, *iam.GetLoginProfileInput, ...request.Option) (*iam.GetLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetLoginProfileRequest(*iam.GetLoginProfileInput) (*request.Request, *iam.GetLoginProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOpenIDConnectProvider(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOpenIDConnectProviderWithContext(aws.Context, *iam.GetOpenIDConnectProviderInput, ...request.Option) (*iam.GetOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOpenIDConnectProviderRequest(*iam.GetOpenIDConnectProviderInput) (*request.Request, *iam.GetOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOrganizationsAccessReport(*iam.GetOrganizationsAccessReportInput) (*iam.GetOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOrganizationsAccessReportWithContext(aws.Context, *iam.GetOrganizationsAccessReportInput, ...request.Option) (*iam.GetOrganizationsAccessReportOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetOrganizationsAccessReportRequest(*iam.GetOrganizationsAccessReportInput) (*request.Request, *iam.GetOrganizationsAccessReportOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicy(*iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicyWithContext(aws.Context, *iam.GetPolicyInput, ...request.Option) (*iam.GetPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicyRequest(*iam.GetPolicyInput) (*request.Request, *iam.GetPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicyVersion(*iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicyVersionWithContext(aws.Context, *iam.GetPolicyVersionInput, ...request.Option) (*iam.GetPolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetPolicyVersionRequest(*iam.GetPolicyVersionInput) (*request.Request, *iam.GetPolicyVersionOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRole(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRoleWithContext(aws.Context, *iam.GetRoleInput, ...request.Option) (*iam.GetRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRoleRequest(*iam.GetRoleInput) (*request.Request, *iam.GetRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRolePolicy(*iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRolePolicyWithContext(aws.Context, *iam.GetRolePolicyInput, ...request.Option) (*iam.GetRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetRolePolicyRequest(*iam.GetRolePolicyInput) (*request.Request, *iam.GetRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSAMLProvider(*iam.GetSAMLProviderInput) (*iam.GetSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSAMLProviderWithContext(aws.Context, *iam.GetSAMLProviderInput, ...request.Option) (*iam.GetSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSAMLProviderRequest(*iam.GetSAMLProviderInput) (*request.Request, *iam.GetSAMLProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSSHPublicKey(*iam.GetSSHPublicKeyInput) (*iam.GetSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSSHPublicKeyWithContext(aws.Context, *iam.GetSSHPublicKeyInput, ...request.Option) (*iam.GetSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetSSHPublicKeyRequest(*iam.GetSSHPublicKeyInput) (*request.Request, *iam.GetSSHPublicKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServerCertificate(*iam.GetServerCertificateInput) (*iam.GetServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServerCertificateWithContext(aws.Context, *iam.GetServerCertificateInput, ...request.Option) (*iam.GetServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServerCertificateRequest(*iam.GetServerCertificateInput) (*request.Request, *iam.GetServerCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetails(*iam.GetServiceLastAccessedDetailsInput) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetailsWithContext(aws.Context, *iam.GetServiceLastAccessedDetailsInput, ...request.Option) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetailsRequest(*iam.GetServiceLastAccessedDetailsInput) (*request.Request, *iam.GetServiceLastAccessedDetailsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetailsWithEntities(*iam.GetServiceLastAccessedDetailsWithEntitiesInput) (*iam.GetServiceLastAccessedDetailsWithEntitiesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetailsWithEntitiesWithContext(aws.Context, *iam.GetServiceLastAccessedDetailsWithEntitiesInput, ...request.Option) (*iam.GetServiceLastAccessedDetailsWithEntitiesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLastAccessedDetailsWithEntitiesRequest(*iam.GetServiceLastAccessedDetailsWithEntitiesInput) (*request.Request, *iam.GetServiceLastAccessedDetailsWithEntitiesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLinkedRoleDeletionStatus(*iam.GetServiceLinkedRoleDeletionStatusInput) (*iam.GetServiceLinkedRoleDeletionStatusOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLinkedRoleDeletionStatusWithContext(aws.Context, *iam.GetServiceLinkedRoleDeletionStatusInput, ...request.Option) (*iam.GetServiceLinkedRoleDeletionStatusOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetServiceLinkedRoleDeletionStatusRequest(*iam.GetServiceLinkedRoleDeletionStatusInput) (*request.Request, *iam.GetServiceLinkedRoleDeletionStatusOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUser(*iam.GetUserInput) (*iam.GetUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUserWithContext(aws.Context, *iam.GetUserInput, ...request.Option) (*iam.GetUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUserRequest(*iam.GetUserInput) (*request.Request, *iam.GetUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUserPolicy(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUserPolicyWithContext(aws.Context, *iam.GetUserPolicyInput, ...request.Option) (*iam.GetUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) GetUserPolicyRequest(*iam.GetUserPolicyInput) (*request.Request, *iam.GetUserPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccessKeys(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccessKeysWithContext(aws.Context, *iam.ListAccessKeysInput, ...request.Option) (*iam.ListAccessKeysOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccessKeysRequest(*iam.ListAccessKeysInput) (*request.Request, *iam.ListAccessKeysOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccessKeysPages(*iam.ListAccessKeysInput, func(*iam.ListAccessKeysOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccessKeysPagesWithContext(aws.Context, *iam.ListAccessKeysInput, func(*iam.ListAccessKeysOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccountAliases(*iam.ListAccountAliasesInput) (*iam.ListAccountAliasesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccountAliasesWithContext(aws.Context, *iam.ListAccountAliasesInput, ...request.Option) (*iam.ListAccountAliasesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccountAliasesRequest(*iam.ListAccountAliasesInput) (*request.Request, *iam.ListAccountAliasesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccountAliasesPages(*iam.ListAccountAliasesInput, func(*iam.ListAccountAliasesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAccountAliasesPagesWithContext(aws.Context, *iam.ListAccountAliasesInput, func(*iam.ListAccountAliasesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedGroupPolicies(*iam.ListAttachedGroupPoliciesInput) (*iam.ListAttachedGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedGroupPoliciesWithContext(aws.Context, *iam.ListAttachedGroupPoliciesInput, ...request.Option) (*iam.ListAttachedGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedGroupPoliciesRequest(*iam.ListAttachedGroupPoliciesInput) (*request.Request, *iam.ListAttachedGroupPoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedGroupPoliciesPages(*iam.ListAttachedGroupPoliciesInput, func(*iam.ListAttachedGroupPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedGroupPoliciesPagesWithContext(aws.Context, *iam.ListAttachedGroupPoliciesInput, func(*iam.ListAttachedGroupPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedRolePolicies(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedRolePoliciesWithContext(aws.Context, *iam.ListAttachedRolePoliciesInput, ...request.Option) (*iam.ListAttachedRolePoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedRolePoliciesRequest(*iam.ListAttachedRolePoliciesInput) (*request.Request, *iam.ListAttachedRolePoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedRolePoliciesPages(*iam.ListAttachedRolePoliciesInput, func(*iam.ListAttachedRolePoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedRolePoliciesPagesWithContext(aws.Context, *iam.ListAttachedRolePoliciesInput, func(*iam.ListAttachedRolePoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedUserPolicies(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedUserPoliciesWithContext(aws.Context, *iam.ListAttachedUserPoliciesInput, ...request.Option) (*iam.ListAttachedUserPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedUserPoliciesRequest(*iam.ListAttachedUserPoliciesInput) (*request.Request, *iam.ListAttachedUserPoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedUserPoliciesPages(*iam.ListAttachedUserPoliciesInput, func(*iam.ListAttachedUserPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListAttachedUserPoliciesPagesWithContext(aws.Context, *iam.ListAttachedUserPoliciesInput, func(*iam.ListAttachedUserPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListEntitiesForPolicy(*iam.ListEntitiesForPolicyInput) (*iam.ListEntitiesForPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListEntitiesForPolicyWithContext(aws.Context, *iam.ListEntitiesForPolicyInput, ...request.Option) (*iam.ListEntitiesForPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListEntitiesForPolicyRequest(*iam.ListEntitiesForPolicyInput) (*request.Request, *iam.ListEntitiesForPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListEntitiesForPolicyPages(*iam.ListEntitiesForPolicyInput, func(*iam.ListEntitiesForPolicyOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListEntitiesForPolicyPagesWithContext(aws.Context, *iam.ListEntitiesForPolicyInput, func(*iam.ListEntitiesForPolicyOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupPolicies(*iam.ListGroupPoliciesInput) (*iam.ListGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupPoliciesWithContext(aws.Context, *iam.ListGroupPoliciesInput, ...request.Option) (*iam.ListGroupPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupPoliciesRequest(*iam.ListGroupPoliciesInput) (*request.Request, *iam.ListGroupPoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupPoliciesPages(*iam.ListGroupPoliciesInput, func(*iam.ListGroupPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupPoliciesPagesWithContext(aws.Context, *iam.ListGroupPoliciesInput, func(*iam.ListGroupPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroups(*iam.ListGroupsInput) (*iam.ListGroupsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsWithContext(aws.Context, *iam.ListGroupsInput, ...request.Option) (*iam.ListGroupsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsRequest(*iam.ListGroupsInput) (*request.Request, *iam.ListGroupsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsPages(*iam.ListGroupsInput, func(*iam.ListGroupsOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsPagesWithContext(aws.Context, *iam.ListGroupsInput, func(*iam.ListGroupsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsForUser(*iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsForUserWithContext(aws.Context, *iam.ListGroupsForUserInput, ...request.Option) (*iam.ListGroupsForUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsForUserRequest(*iam.ListGroupsForUserInput) (*request.Request, *iam.ListGroupsForUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsForUserPages(*iam.ListGroupsForUserInput, func(*iam.ListGroupsForUserOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListGroupsForUserPagesWithContext(aws.Context, *iam.ListGroupsForUserInput, func(*iam.ListGroupsForUserOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfiles(*iam.ListInstanceProfilesInput) (*iam.ListInstanceProfilesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesWithContext(aws.Context, *iam.ListInstanceProfilesInput, ...request.Option) (*iam.ListInstanceProfilesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesRequest(*iam.ListInstanceProfilesInput) (*request.Request, *iam.ListInstanceProfilesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesPages(*iam.ListInstanceProfilesInput, func(*iam.ListInstanceProfilesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesPagesWithContext(aws.Context, *iam.ListInstanceProfilesInput, func(*iam.ListInstanceProfilesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesForRole(*iam.ListInstanceProfilesForRoleInput) (*iam.ListInstanceProfilesForRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesForRoleWithContext(aws.Context, *iam.ListInstanceProfilesForRoleInput, ...request.Option) (*iam.ListInstanceProfilesForRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesForRoleRequest(*iam.ListInstanceProfilesForRoleInput) (*request.Request, *iam.ListInstanceProfilesForRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesForRolePages(*iam.ListInstanceProfilesForRoleInput, func(*iam.ListInstanceProfilesForRoleOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListInstanceProfilesForRolePagesWithContext(aws.Context, *iam.ListInstanceProfilesForRoleInput, func(*iam.ListInstanceProfilesForRoleOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListMFADevices(*iam.ListMFADevicesInput) (*iam.ListMFADevicesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListMFADevicesWithContext(aws.Context, *iam.ListMFADevicesInput, ...request.Option) (*iam.ListMFADevicesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListMFADevicesRequest(*iam.ListMFADevicesInput) (*request.Request, *iam.ListMFADevicesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListMFADevicesPages(*iam.ListMFADevicesInput, func(*iam.ListMFADevicesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListMFADevicesPagesWithContext(aws.Context, *iam.ListMFADevicesInput, func(*iam.ListMFADevicesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListOpenIDConnectProviders(*iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListOpenIDConnectProvidersWithContext(aws.Context, *iam.ListOpenIDConnectProvidersInput, ...request.Option) (*iam.ListOpenIDConnectProvidersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListOpenIDConnectProvidersRequest(*iam.ListOpenIDConnectProvidersInput) (*request.Request, *iam.ListOpenIDConnectProvidersOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicies(*iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesWithContext(aws.Context, *iam.ListPoliciesInput, ...request.Option) (*iam.ListPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesRequest(*iam.ListPoliciesInput) (*request.Request, *iam.ListPoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesPages(*iam.ListPoliciesInput, func(*iam.ListPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesPagesWithContext(aws.Context, *iam.ListPoliciesInput, func(*iam.ListPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesGrantingServiceAccess(*iam.ListPoliciesGrantingServiceAccessInput) (*iam.ListPoliciesGrantingServiceAccessOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesGrantingServiceAccessWithContext(aws.Context, *iam.ListPoliciesGrantingServiceAccessInput, ...request.Option) (*iam.ListPoliciesGrantingServiceAccessOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPoliciesGrantingServiceAccessRequest(*iam.ListPoliciesGrantingServiceAccessInput) (*request.Request, *iam.ListPoliciesGrantingServiceAccessOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicyVersions(*iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicyVersionsWithContext(aws.Context, *iam.ListPolicyVersionsInput, ...request.Option) (*iam.ListPolicyVersionsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicyVersionsRequest(*iam.ListPolicyVersionsInput) (*request.Request, *iam.ListPolicyVersionsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicyVersionsPages(*iam.ListPolicyVersionsInput, func(*iam.ListPolicyVersionsOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListPolicyVersionsPagesWithContext(aws.Context, *iam.ListPolicyVersionsInput, func(*iam.ListPolicyVersionsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolePolicies(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolePoliciesWithContext(aws.Context, *iam.ListRolePoliciesInput, ...request.Option) (*iam.ListRolePoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolePoliciesRequest(*iam.ListRolePoliciesInput) (*request.Request, *iam.ListRolePoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolePoliciesPages(*iam.ListRolePoliciesInput, func(*iam.ListRolePoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolePoliciesPagesWithContext(aws.Context, *iam.ListRolePoliciesInput, func(*iam.ListRolePoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRoleTags(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRoleTagsWithContext(aws.Context, *iam.ListRoleTagsInput, ...request.Option) (*iam.ListRoleTagsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRoleTagsRequest(*iam.ListRoleTagsInput) (*request.Request, *iam.ListRoleTagsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRoles(*iam.ListRolesInput) (*iam.ListRolesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolesWithContext(aws.Context, *iam.ListRolesInput, ...request.Option) (*iam.ListRolesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolesRequest(*iam.ListRolesInput) (*request.Request, *iam.ListRolesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolesPages(*iam.ListRolesInput, func(*iam.ListRolesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListRolesPagesWithContext(aws.Context, *iam.ListRolesInput, func(*iam.ListRolesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSAMLProviders(*iam.ListSAMLProvidersInput) (*iam.ListSAMLProvidersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSAMLProvidersWithContext(aws.Context, *iam.ListSAMLProvidersInput, ...request.Option) (*iam.ListSAMLProvidersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSAMLProvidersRequest(*iam.ListSAMLProvidersInput) (*request.Request, *iam.ListSAMLProvidersOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSSHPublicKeys(*iam.ListSSHPublicKeysInput) (*iam.ListSSHPublicKeysOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSSHPublicKeysWithContext(aws.Context, *iam.ListSSHPublicKeysInput, ...request.Option) (*iam.ListSSHPublicKeysOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSSHPublicKeysRequest(*iam.ListSSHPublicKeysInput) (*request.Request, *iam.ListSSHPublicKeysOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSSHPublicKeysPages(*iam.ListSSHPublicKeysInput, func(*iam.ListSSHPublicKeysOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSSHPublicKeysPagesWithContext(aws.Context, *iam.ListSSHPublicKeysInput, func(*iam.ListSSHPublicKeysOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServerCertificates(*iam.ListServerCertificatesInput) (*iam.ListServerCertificatesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServerCertificatesWithContext(aws.Context, *iam.ListServerCertificatesInput, ...request.Option) (*iam.ListServerCertificatesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServerCertificatesRequest(*iam.ListServerCertificatesInput) (*request.Request, *iam.ListServerCertificatesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServerCertificatesPages(*iam.ListServerCertificatesInput, func(*iam.ListServerCertificatesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServerCertificatesPagesWithContext(aws.Context, *iam.ListServerCertificatesInput, func(*iam.ListServerCertificatesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServiceSpecificCredentials(*iam.ListServiceSpecificCredentialsInput) (*iam.ListServiceSpecificCredentialsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServiceSpecificCredentialsWithContext(aws.Context, *iam.ListServiceSpecificCredentialsInput, ...request.Option) (*iam.ListServiceSpecificCredentialsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListServiceSpecificCredentialsRequest(*iam.ListServiceSpecificCredentialsInput) (*request.Request, *iam.ListServiceSpecificCredentialsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSigningCertificates(*iam.ListSigningCertificatesInput) (*iam.ListSigningCertificatesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSigningCertificatesWithContext(aws.Context, *iam.ListSigningCertificatesInput, ...request.Option) (*iam.ListSigningCertificatesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSigningCertificatesRequest(*iam.ListSigningCertificatesInput) (*request.Request, *iam.ListSigningCertificatesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSigningCertificatesPages(*iam.ListSigningCertificatesInput, func(*iam.ListSigningCertificatesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListSigningCertificatesPagesWithContext(aws.Context, *iam.ListSigningCertificatesInput, func(*iam.ListSigningCertificatesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserPoliciesWithContext(aws.Context, *iam.ListUserPoliciesInput, ...request.Option) (*iam.ListUserPoliciesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserPoliciesRequest(*iam.ListUserPoliciesInput) (*request.Request, *iam.ListUserPoliciesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserPoliciesPages(*iam.ListUserPoliciesInput, func(*iam.ListUserPoliciesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserPoliciesPagesWithContext(aws.Context, *iam.ListUserPoliciesInput, func(*iam.ListUserPoliciesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserTags(*iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserTagsWithContext(aws.Context, *iam.ListUserTagsInput, ...request.Option) (*iam.ListUserTagsOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUserTagsRequest(*iam.ListUserTagsInput) (*request.Request, *iam.ListUserTagsOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUsers(*iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUsersWithContext(aws.Context, *iam.ListUsersInput, ...request.Option) (*iam.ListUsersOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUsersRequest(*iam.ListUsersInput) (*request.Request, *iam.ListUsersOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUsersPages(*iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListUsersPagesWithContext(aws.Context, *iam.ListUsersInput, func(*iam.ListUsersOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListVirtualMFADevices(*iam.ListVirtualMFADevicesInput) (*iam.ListVirtualMFADevicesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListVirtualMFADevicesWithContext(aws.Context, *iam.ListVirtualMFADevicesInput, ...request.Option) (*iam.ListVirtualMFADevicesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListVirtualMFADevicesRequest(*iam.ListVirtualMFADevicesInput) (*request.Request, *iam.ListVirtualMFADevicesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ListVirtualMFADevicesPages(*iam.ListVirtualMFADevicesInput, func(*iam.ListVirtualMFADevicesOutput, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) ListVirtualMFADevicesPagesWithContext(aws.Context, *iam.ListVirtualMFADevicesInput, func(*iam.ListVirtualMFADevicesOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) PutGroupPolicy(*iam.PutGroupPolicyInput) (*iam.PutGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutGroupPolicyWithContext(aws.Context, *iam.PutGroupPolicyInput, ...request.Option) (*iam.PutGroupPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutGroupPolicyRequest(*iam.PutGroupPolicyInput) (*request.Request, *iam.PutGroupPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePermissionsBoundary(*iam.PutRolePermissionsBoundaryInput) (*iam.PutRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePermissionsBoundaryWithContext(aws.Context, *iam.PutRolePermissionsBoundaryInput, ...request.Option) (*iam.PutRolePermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePermissionsBoundaryRequest(*iam.PutRolePermissionsBoundaryInput) (*request.Request, *iam.PutRolePermissionsBoundaryOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePolicy(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePolicyWithContext(aws.Context, *iam.PutRolePolicyInput, ...request.Option) (*iam.PutRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutRolePolicyRequest(*iam.PutRolePolicyInput) (*request.Request, *iam.PutRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPermissionsBoundary(*iam.PutUserPermissionsBoundaryInput) (*iam.PutUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPermissionsBoundaryWithContext(aws.Context, *iam.PutUserPermissionsBoundaryInput, ...request.Option) (*iam.PutUserPermissionsBoundaryOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPermissionsBoundaryRequest(*iam.PutUserPermissionsBoundaryInput) (*request.Request, *iam.PutUserPermissionsBoundaryOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPolicy(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPolicyWithContext(aws.Context, *iam.PutUserPolicyInput, ...request.Option) (*iam.PutUserPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) PutUserPolicyRequest(*iam.PutUserPolicyInput) (*request.Request, *iam.PutUserPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveClientIDFromOpenIDConnectProvider(*iam.RemoveClientIDFromOpenIDConnectProviderInput) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveClientIDFromOpenIDConnectProviderWithContext(aws.Context, *iam.RemoveClientIDFromOpenIDConnectProviderInput, ...request.Option) (*iam.RemoveClientIDFromOpenIDConnectProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveClientIDFromOpenIDConnectProviderRequest(*iam.RemoveClientIDFromOpenIDConnectProviderInput) (*request.Request, *iam.RemoveClientIDFromOpenIDConnectProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveRoleFromInstanceProfile(*iam.RemoveRoleFromInstanceProfileInput) (*iam.RemoveRoleFromInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveRoleFromInstanceProfileWithContext(aws.Context, *iam.RemoveRoleFromInstanceProfileInput, ...request.Option) (*iam.RemoveRoleFromInstanceProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveRoleFromInstanceProfileRequest(*iam.RemoveRoleFromInstanceProfileInput) (*request.Request, *iam.RemoveRoleFromInstanceProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveUserFromGroup(*iam.RemoveUserFromGroupInput) (*iam.RemoveUserFromGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveUserFromGroupWithContext(aws.Context, *iam.RemoveUserFromGroupInput, ...request.Option) (*iam.RemoveUserFromGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) RemoveUserFromGroupRequest(*iam.RemoveUserFromGroupInput) (*request.Request, *iam.RemoveUserFromGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResetServiceSpecificCredential(*iam.ResetServiceSpecificCredentialInput) (*iam.ResetServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResetServiceSpecificCredentialWithContext(aws.Context, *iam.ResetServiceSpecificCredentialInput, ...request.Option) (*iam.ResetServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResetServiceSpecificCredentialRequest(*iam.ResetServiceSpecificCredentialInput) (*request.Request, *iam.ResetServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResyncMFADevice(*iam.ResyncMFADeviceInput) (*iam.ResyncMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResyncMFADeviceWithContext(aws.Context, *iam.ResyncMFADeviceInput, ...request.Option) (*iam.ResyncMFADeviceOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) ResyncMFADeviceRequest(*iam.ResyncMFADeviceInput) (*request.Request, *iam.ResyncMFADeviceOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetDefaultPolicyVersion(*iam.SetDefaultPolicyVersionInput) (*iam.SetDefaultPolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetDefaultPolicyVersionWithContext(aws.Context, *iam.SetDefaultPolicyVersionInput, ...request.Option) (*iam.SetDefaultPolicyVersionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetDefaultPolicyVersionRequest(*iam.SetDefaultPolicyVersionInput) (*request.Request, *iam.SetDefaultPolicyVersionOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetSecurityTokenServicePreferences(*iam.SetSecurityTokenServicePreferencesInput) (*iam.SetSecurityTokenServicePreferencesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetSecurityTokenServicePreferencesWithContext(aws.Context, *iam.SetSecurityTokenServicePreferencesInput, ...request.Option) (*iam.SetSecurityTokenServicePreferencesOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SetSecurityTokenServicePreferencesRequest(*iam.SetSecurityTokenServicePreferencesInput) (*request.Request, *iam.SetSecurityTokenServicePreferencesOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulateCustomPolicy(*iam.SimulateCustomPolicyInput) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulateCustomPolicyWithContext(aws.Context, *iam.SimulateCustomPolicyInput, ...request.Option) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulateCustomPolicyRequest(*iam.SimulateCustomPolicyInput) (*request.Request, *iam.SimulatePolicyResponse) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulateCustomPolicyPages(*iam.SimulateCustomPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulateCustomPolicyPagesWithContext(aws.Context, *iam.SimulateCustomPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulatePrincipalPolicy(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulatePrincipalPolicyWithContext(aws.Context, *iam.SimulatePrincipalPolicyInput, ...request.Option) (*iam.SimulatePolicyResponse, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulatePrincipalPolicyRequest(*iam.SimulatePrincipalPolicyInput) (*request.Request, *iam.SimulatePolicyResponse) {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulatePrincipalPolicyPages(*iam.SimulatePrincipalPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool) error {
	panic("implement me")
}

func (iam *MockIAMAPI) SimulatePrincipalPolicyPagesWithContext(aws.Context, *iam.SimulatePrincipalPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (iam *MockIAMAPI) TagRole(*iam.TagRoleInput) (*iam.TagRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) TagRoleWithContext(aws.Context, *iam.TagRoleInput, ...request.Option) (*iam.TagRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) TagRoleRequest(*iam.TagRoleInput) (*request.Request, *iam.TagRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) TagUser(*iam.TagUserInput) (*iam.TagUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) TagUserWithContext(aws.Context, *iam.TagUserInput, ...request.Option) (*iam.TagUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) TagUserRequest(*iam.TagUserInput) (*request.Request, *iam.TagUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagRole(*iam.UntagRoleInput) (*iam.UntagRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagRoleWithContext(aws.Context, *iam.UntagRoleInput, ...request.Option) (*iam.UntagRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagRoleRequest(*iam.UntagRoleInput) (*request.Request, *iam.UntagRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagUser(*iam.UntagUserInput) (*iam.UntagUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagUserWithContext(aws.Context, *iam.UntagUserInput, ...request.Option) (*iam.UntagUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UntagUserRequest(*iam.UntagUserInput) (*request.Request, *iam.UntagUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccessKey(*iam.UpdateAccessKeyInput) (*iam.UpdateAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccessKeyWithContext(aws.Context, *iam.UpdateAccessKeyInput, ...request.Option) (*iam.UpdateAccessKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccessKeyRequest(*iam.UpdateAccessKeyInput) (*request.Request, *iam.UpdateAccessKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccountPasswordPolicy(*iam.UpdateAccountPasswordPolicyInput) (*iam.UpdateAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccountPasswordPolicyWithContext(aws.Context, *iam.UpdateAccountPasswordPolicyInput, ...request.Option) (*iam.UpdateAccountPasswordPolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAccountPasswordPolicyRequest(*iam.UpdateAccountPasswordPolicyInput) (*request.Request, *iam.UpdateAccountPasswordPolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAssumeRolePolicy(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAssumeRolePolicyWithContext(aws.Context, *iam.UpdateAssumeRolePolicyInput, ...request.Option) (*iam.UpdateAssumeRolePolicyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateAssumeRolePolicyRequest(*iam.UpdateAssumeRolePolicyInput) (*request.Request, *iam.UpdateAssumeRolePolicyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateGroup(*iam.UpdateGroupInput) (*iam.UpdateGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateGroupWithContext(aws.Context, *iam.UpdateGroupInput, ...request.Option) (*iam.UpdateGroupOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateGroupRequest(*iam.UpdateGroupInput) (*request.Request, *iam.UpdateGroupOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateLoginProfile(*iam.UpdateLoginProfileInput) (*iam.UpdateLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateLoginProfileWithContext(aws.Context, *iam.UpdateLoginProfileInput, ...request.Option) (*iam.UpdateLoginProfileOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateLoginProfileRequest(*iam.UpdateLoginProfileInput) (*request.Request, *iam.UpdateLoginProfileOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateOpenIDConnectProviderThumbprint(*iam.UpdateOpenIDConnectProviderThumbprintInput) (*iam.UpdateOpenIDConnectProviderThumbprintOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateOpenIDConnectProviderThumbprintWithContext(aws.Context, *iam.UpdateOpenIDConnectProviderThumbprintInput, ...request.Option) (*iam.UpdateOpenIDConnectProviderThumbprintOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateOpenIDConnectProviderThumbprintRequest(*iam.UpdateOpenIDConnectProviderThumbprintInput) (*request.Request, *iam.UpdateOpenIDConnectProviderThumbprintOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRole(*iam.UpdateRoleInput) (*iam.UpdateRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRoleWithContext(aws.Context, *iam.UpdateRoleInput, ...request.Option) (*iam.UpdateRoleOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRoleRequest(*iam.UpdateRoleInput) (*request.Request, *iam.UpdateRoleOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRoleDescription(*iam.UpdateRoleDescriptionInput) (*iam.UpdateRoleDescriptionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRoleDescriptionWithContext(aws.Context, *iam.UpdateRoleDescriptionInput, ...request.Option) (*iam.UpdateRoleDescriptionOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateRoleDescriptionRequest(*iam.UpdateRoleDescriptionInput) (*request.Request, *iam.UpdateRoleDescriptionOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSAMLProvider(*iam.UpdateSAMLProviderInput) (*iam.UpdateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSAMLProviderWithContext(aws.Context, *iam.UpdateSAMLProviderInput, ...request.Option) (*iam.UpdateSAMLProviderOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSAMLProviderRequest(*iam.UpdateSAMLProviderInput) (*request.Request, *iam.UpdateSAMLProviderOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSSHPublicKey(*iam.UpdateSSHPublicKeyInput) (*iam.UpdateSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSSHPublicKeyWithContext(aws.Context, *iam.UpdateSSHPublicKeyInput, ...request.Option) (*iam.UpdateSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSSHPublicKeyRequest(*iam.UpdateSSHPublicKeyInput) (*request.Request, *iam.UpdateSSHPublicKeyOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServerCertificate(*iam.UpdateServerCertificateInput) (*iam.UpdateServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServerCertificateWithContext(aws.Context, *iam.UpdateServerCertificateInput, ...request.Option) (*iam.UpdateServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServerCertificateRequest(*iam.UpdateServerCertificateInput) (*request.Request, *iam.UpdateServerCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServiceSpecificCredential(*iam.UpdateServiceSpecificCredentialInput) (*iam.UpdateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServiceSpecificCredentialWithContext(aws.Context, *iam.UpdateServiceSpecificCredentialInput, ...request.Option) (*iam.UpdateServiceSpecificCredentialOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateServiceSpecificCredentialRequest(*iam.UpdateServiceSpecificCredentialInput) (*request.Request, *iam.UpdateServiceSpecificCredentialOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSigningCertificate(*iam.UpdateSigningCertificateInput) (*iam.UpdateSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSigningCertificateWithContext(aws.Context, *iam.UpdateSigningCertificateInput, ...request.Option) (*iam.UpdateSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateSigningCertificateRequest(*iam.UpdateSigningCertificateInput) (*request.Request, *iam.UpdateSigningCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateUser(*iam.UpdateUserInput) (*iam.UpdateUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateUserWithContext(aws.Context, *iam.UpdateUserInput, ...request.Option) (*iam.UpdateUserOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UpdateUserRequest(*iam.UpdateUserInput) (*request.Request, *iam.UpdateUserOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSSHPublicKey(*iam.UploadSSHPublicKeyInput) (*iam.UploadSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSSHPublicKeyWithContext(aws.Context, *iam.UploadSSHPublicKeyInput, ...request.Option) (*iam.UploadSSHPublicKeyOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSSHPublicKeyRequest(*iam.UploadSSHPublicKeyInput) (*request.Request, *iam.UploadSSHPublicKeyOutput) {
	panic("implement me")
}

func (iamsvc *MockIAMAPI) UploadServerCertificate(input *iam.UploadServerCertificateInput) (*iam.UploadServerCertificateOutput, error) {
	return &iam.UploadServerCertificateOutput{
		ServerCertificateMetadata: &iam.ServerCertificateMetadata{
			Arn: aws.String(iamsvc.Arner(*input.ServerCertificateName)),
		},
	}, nil
}

func (iam *MockIAMAPI) UploadServerCertificateWithContext(aws.Context, *iam.UploadServerCertificateInput, ...request.Option) (*iam.UploadServerCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadServerCertificateRequest(*iam.UploadServerCertificateInput) (*request.Request, *iam.UploadServerCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSigningCertificate(*iam.UploadSigningCertificateInput) (*iam.UploadSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSigningCertificateWithContext(aws.Context, *iam.UploadSigningCertificateInput, ...request.Option) (*iam.UploadSigningCertificateOutput, error) {
	panic("implement me")
}

func (iam *MockIAMAPI) UploadSigningCertificateRequest(*iam.UploadSigningCertificateInput) (*request.Request, *iam.UploadSigningCertificateOutput) {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilInstanceProfileExists(*iam.GetInstanceProfileInput) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilInstanceProfileExistsWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilPolicyExists(*iam.GetPolicyInput) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilPolicyExistsWithContext(aws.Context, *iam.GetPolicyInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilRoleExists(*iam.GetRoleInput) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilRoleExistsWithContext(aws.Context, *iam.GetRoleInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilUserExists(*iam.GetUserInput) error {
	panic("implement me")
}

func (iam *MockIAMAPI) WaitUntilUserExistsWithContext(aws.Context, *iam.GetUserInput, ...request.WaiterOption) error {
	panic("implement me")
}
