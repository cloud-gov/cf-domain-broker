// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

// Package emriface provides an interface to enable mocking the Amazon Elastic MapReduce service client
// for testing your code.
//
// It is important to note that this interface will have breaking changes
// when the service model is updated and adds new API operations, paginators,
// and waiters.
package emriface

import (
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/emr"
)

// EMRAPI provides an interface to enable mocking the
// emr.EMR service client's API operation,
// paginators, and waiters. This make unit testing your code that calls out
// to the SDK's service client's calls easier.
//
// The best way to use this interface is so the SDK's service client's calls
// can be stubbed out for unit testing your code with the SDK without needing
// to inject custom request handlers into the the SDK's request pipeline.
//
//    // myFunc uses an SDK service client to make a request to
//    // Amazon Elastic MapReduce.
//    func myFunc(svc emriface.EMRAPI) bool {
//        // Make svc.AddInstanceGroups request
//    }
//
//    func main() {
//        sess := session.New()
//        svc := emr.New(sess)
//
//        myFunc(svc)
//    }
//
// In your _test.go file:
//
//    // Define a mock struct to be used in your unit tests of myFunc.
//    type mockEMRClient struct {
//        emriface.EMRAPI
//    }
//    func (m *mockEMRClient) AddInstanceGroups(input *emr.AddInstanceGroupsInput) (*emr.AddInstanceGroupsOutput, error) {
//        // mock response/functionality
//    }
//
//    TestMyFunc(t *testing.T) {
//        // Setup Test
//        mockSvc := &mockEMRClient{}
//
//        myfunc(mockSvc)
//
//        // Verify myFunc's functionality
//    }
//
// It is important to note that this interface will have breaking changes
// when the service model is updated and adds new API operations, paginators,
// and waiters. Its suggested to use the pattern above for testing, or using
// tooling to generate mocks to satisfy the interfaces.
type EMRAPI interface {
	AddInstanceGroupsRequest(*emr.AddInstanceGroupsInput) (*request.Request, *emr.AddInstanceGroupsOutput)

	AddInstanceGroups(*emr.AddInstanceGroupsInput) (*emr.AddInstanceGroupsOutput, error)

	AddJobFlowStepsRequest(*emr.AddJobFlowStepsInput) (*request.Request, *emr.AddJobFlowStepsOutput)

	AddJobFlowSteps(*emr.AddJobFlowStepsInput) (*emr.AddJobFlowStepsOutput, error)

	AddTagsRequest(*emr.AddTagsInput) (*request.Request, *emr.AddTagsOutput)

	AddTags(*emr.AddTagsInput) (*emr.AddTagsOutput, error)

	CancelStepsRequest(*emr.CancelStepsInput) (*request.Request, *emr.CancelStepsOutput)

	CancelSteps(*emr.CancelStepsInput) (*emr.CancelStepsOutput, error)

	CreateSecurityConfigurationRequest(*emr.CreateSecurityConfigurationInput) (*request.Request, *emr.CreateSecurityConfigurationOutput)

	CreateSecurityConfiguration(*emr.CreateSecurityConfigurationInput) (*emr.CreateSecurityConfigurationOutput, error)

	DeleteSecurityConfigurationRequest(*emr.DeleteSecurityConfigurationInput) (*request.Request, *emr.DeleteSecurityConfigurationOutput)

	DeleteSecurityConfiguration(*emr.DeleteSecurityConfigurationInput) (*emr.DeleteSecurityConfigurationOutput, error)

	DescribeClusterRequest(*emr.DescribeClusterInput) (*request.Request, *emr.DescribeClusterOutput)

	DescribeCluster(*emr.DescribeClusterInput) (*emr.DescribeClusterOutput, error)

	DescribeJobFlowsRequest(*emr.DescribeJobFlowsInput) (*request.Request, *emr.DescribeJobFlowsOutput)

	DescribeJobFlows(*emr.DescribeJobFlowsInput) (*emr.DescribeJobFlowsOutput, error)

	DescribeSecurityConfigurationRequest(*emr.DescribeSecurityConfigurationInput) (*request.Request, *emr.DescribeSecurityConfigurationOutput)

	DescribeSecurityConfiguration(*emr.DescribeSecurityConfigurationInput) (*emr.DescribeSecurityConfigurationOutput, error)

	DescribeStepRequest(*emr.DescribeStepInput) (*request.Request, *emr.DescribeStepOutput)

	DescribeStep(*emr.DescribeStepInput) (*emr.DescribeStepOutput, error)

	ListBootstrapActionsRequest(*emr.ListBootstrapActionsInput) (*request.Request, *emr.ListBootstrapActionsOutput)

	ListBootstrapActions(*emr.ListBootstrapActionsInput) (*emr.ListBootstrapActionsOutput, error)

	ListBootstrapActionsPages(*emr.ListBootstrapActionsInput, func(*emr.ListBootstrapActionsOutput, bool) bool) error

	ListClustersRequest(*emr.ListClustersInput) (*request.Request, *emr.ListClustersOutput)

	ListClusters(*emr.ListClustersInput) (*emr.ListClustersOutput, error)

	ListClustersPages(*emr.ListClustersInput, func(*emr.ListClustersOutput, bool) bool) error

	ListInstanceGroupsRequest(*emr.ListInstanceGroupsInput) (*request.Request, *emr.ListInstanceGroupsOutput)

	ListInstanceGroups(*emr.ListInstanceGroupsInput) (*emr.ListInstanceGroupsOutput, error)

	ListInstanceGroupsPages(*emr.ListInstanceGroupsInput, func(*emr.ListInstanceGroupsOutput, bool) bool) error

	ListInstancesRequest(*emr.ListInstancesInput) (*request.Request, *emr.ListInstancesOutput)

	ListInstances(*emr.ListInstancesInput) (*emr.ListInstancesOutput, error)

	ListInstancesPages(*emr.ListInstancesInput, func(*emr.ListInstancesOutput, bool) bool) error

	ListSecurityConfigurationsRequest(*emr.ListSecurityConfigurationsInput) (*request.Request, *emr.ListSecurityConfigurationsOutput)

	ListSecurityConfigurations(*emr.ListSecurityConfigurationsInput) (*emr.ListSecurityConfigurationsOutput, error)

	ListStepsRequest(*emr.ListStepsInput) (*request.Request, *emr.ListStepsOutput)

	ListSteps(*emr.ListStepsInput) (*emr.ListStepsOutput, error)

	ListStepsPages(*emr.ListStepsInput, func(*emr.ListStepsOutput, bool) bool) error

	ModifyInstanceGroupsRequest(*emr.ModifyInstanceGroupsInput) (*request.Request, *emr.ModifyInstanceGroupsOutput)

	ModifyInstanceGroups(*emr.ModifyInstanceGroupsInput) (*emr.ModifyInstanceGroupsOutput, error)

	PutAutoScalingPolicyRequest(*emr.PutAutoScalingPolicyInput) (*request.Request, *emr.PutAutoScalingPolicyOutput)

	PutAutoScalingPolicy(*emr.PutAutoScalingPolicyInput) (*emr.PutAutoScalingPolicyOutput, error)

	RemoveAutoScalingPolicyRequest(*emr.RemoveAutoScalingPolicyInput) (*request.Request, *emr.RemoveAutoScalingPolicyOutput)

	RemoveAutoScalingPolicy(*emr.RemoveAutoScalingPolicyInput) (*emr.RemoveAutoScalingPolicyOutput, error)

	RemoveTagsRequest(*emr.RemoveTagsInput) (*request.Request, *emr.RemoveTagsOutput)

	RemoveTags(*emr.RemoveTagsInput) (*emr.RemoveTagsOutput, error)

	RunJobFlowRequest(*emr.RunJobFlowInput) (*request.Request, *emr.RunJobFlowOutput)

	RunJobFlow(*emr.RunJobFlowInput) (*emr.RunJobFlowOutput, error)

	SetTerminationProtectionRequest(*emr.SetTerminationProtectionInput) (*request.Request, *emr.SetTerminationProtectionOutput)

	SetTerminationProtection(*emr.SetTerminationProtectionInput) (*emr.SetTerminationProtectionOutput, error)

	SetVisibleToAllUsersRequest(*emr.SetVisibleToAllUsersInput) (*request.Request, *emr.SetVisibleToAllUsersOutput)

	SetVisibleToAllUsers(*emr.SetVisibleToAllUsersInput) (*emr.SetVisibleToAllUsersOutput, error)

	TerminateJobFlowsRequest(*emr.TerminateJobFlowsInput) (*request.Request, *emr.TerminateJobFlowsOutput)

	TerminateJobFlows(*emr.TerminateJobFlowsInput) (*emr.TerminateJobFlowsOutput, error)

	WaitUntilClusterRunning(*emr.DescribeClusterInput) error

	WaitUntilStepComplete(*emr.DescribeStepInput) error
}

var _ EMRAPI = (*emr.EMR)(nil)
