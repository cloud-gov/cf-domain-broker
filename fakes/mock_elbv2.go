package fakes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/pborman/uuid"
)

type MockELBV2API struct {
	VpcId         string
	LoadBalancers []*elbv2.LoadBalancer
	Listeners     []*elbv2.Listener
}

func NewMockELBV2API() *MockELBV2API {
	return &MockELBV2API{
		VpcId:         fmt.Sprintf("test-vpc-%s", uuid.New()[len(uuid.New())-4:]),
		LoadBalancers: []*elbv2.LoadBalancer{},
		Listeners:     []*elbv2.Listener{},
	}
}

func (elb *MockELBV2API) Arner(name string) string {
	return fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:%s:loadbalancer/net/%s/%s",
		elb.VpcId,
		name,
		strings.Replace(uuid.New()[len(uuid.New())-17:], "-", "", -1))
}

func (elb *MockELBV2API) AddListenerCertificates(input *elbv2.AddListenerCertificatesInput) (*elbv2.AddListenerCertificatesOutput, error) {
	var lelb *elbv2.Listener = nil

	for idx := range elb.Listeners {
		if elb.Listeners[idx].ListenerArn == input.ListenerArn {
			elb.Listeners[idx].Certificates = append(elb.Listeners[idx].Certificates, input.Certificates...)
			lelb = elb.Listeners[idx]
		}
	}

	return &elbv2.AddListenerCertificatesOutput{
		Certificates: lelb.Certificates,
	}, nil
}

func (elb *MockELBV2API) AddListenerCertificatesWithContext(aws.Context, *elbv2.AddListenerCertificatesInput, ...request.Option) (*elbv2.AddListenerCertificatesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) AddListenerCertificatesRequest(*elbv2.AddListenerCertificatesInput) (*request.Request, *elbv2.AddListenerCertificatesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) AddTags(*elbv2.AddTagsInput) (*elbv2.AddTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) AddTagsWithContext(aws.Context, *elbv2.AddTagsInput, ...request.Option) (*elbv2.AddTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) AddTagsRequest(*elbv2.AddTagsInput) (*request.Request, *elbv2.AddTagsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateListener(input *elbv2.CreateListenerInput) (*elbv2.CreateListenerOutput, error) {
	llistener := &elbv2.Listener{
		Certificates:    input.Certificates,
		DefaultActions:  input.DefaultActions,
		LoadBalancerArn: input.LoadBalancerArn,
		ListenerArn:     aws.String(elb.Arner("listener")),
		Port:            input.Port,
		Protocol:        input.Protocol,
		SslPolicy:       input.SslPolicy,
	}

	elb.Listeners = append(elb.Listeners, llistener)

	return &elbv2.CreateListenerOutput{
		Listeners: elb.Listeners,
	}, nil
}

func (elb *MockELBV2API) CreateListenerWithContext(aws.Context, *elbv2.CreateListenerInput, ...request.Option) (*elbv2.CreateListenerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateListenerRequest(*elbv2.CreateListenerInput) (*request.Request, *elbv2.CreateListenerOutput) {
	panic("implement me")
}

// https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html
func (elb *MockELBV2API) CreateLoadBalancer(input *elbv2.CreateLoadBalancerInput) (*elbv2.CreateLoadBalancerOutput, error) {

	lelb := &elbv2.LoadBalancer{
		LoadBalancerName:  input.Name,
		LoadBalancerArn:   aws.String(elb.Arner(*input.Name)),
		IpAddressType:     input.IpAddressType,
		SecurityGroups:    input.SecurityGroups,
		AvailabilityZones: make([]*elbv2.AvailabilityZone, 0),
		Scheme:            input.Scheme,
		VpcId:             aws.String(elb.VpcId),
	}

	elb.LoadBalancers = append(elb.LoadBalancers, lelb)

	return &elbv2.CreateLoadBalancerOutput{
		LoadBalancers: []*elbv2.LoadBalancer{lelb},
	}, nil
}

func (elb *MockELBV2API) CreateLoadBalancerWithContext(aws.Context, *elbv2.CreateLoadBalancerInput, ...request.Option) (*elbv2.CreateLoadBalancerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateLoadBalancerRequest(*elbv2.CreateLoadBalancerInput) (*request.Request, *elbv2.CreateLoadBalancerOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateRule(*elbv2.CreateRuleInput) (*elbv2.CreateRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateRuleWithContext(aws.Context, *elbv2.CreateRuleInput, ...request.Option) (*elbv2.CreateRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateRuleRequest(*elbv2.CreateRuleInput) (*request.Request, *elbv2.CreateRuleOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateTargetGroup(*elbv2.CreateTargetGroupInput) (*elbv2.CreateTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateTargetGroupWithContext(aws.Context, *elbv2.CreateTargetGroupInput, ...request.Option) (*elbv2.CreateTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) CreateTargetGroupRequest(*elbv2.CreateTargetGroupInput) (*request.Request, *elbv2.CreateTargetGroupOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteListener(*elbv2.DeleteListenerInput) (*elbv2.DeleteListenerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteListenerWithContext(aws.Context, *elbv2.DeleteListenerInput, ...request.Option) (*elbv2.DeleteListenerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteListenerRequest(*elbv2.DeleteListenerInput) (*request.Request, *elbv2.DeleteListenerOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteLoadBalancer(*elbv2.DeleteLoadBalancerInput) (*elbv2.DeleteLoadBalancerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteLoadBalancerWithContext(aws.Context, *elbv2.DeleteLoadBalancerInput, ...request.Option) (*elbv2.DeleteLoadBalancerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteLoadBalancerRequest(*elbv2.DeleteLoadBalancerInput) (*request.Request, *elbv2.DeleteLoadBalancerOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteRule(*elbv2.DeleteRuleInput) (*elbv2.DeleteRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteRuleWithContext(aws.Context, *elbv2.DeleteRuleInput, ...request.Option) (*elbv2.DeleteRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteRuleRequest(*elbv2.DeleteRuleInput) (*request.Request, *elbv2.DeleteRuleOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteTargetGroup(*elbv2.DeleteTargetGroupInput) (*elbv2.DeleteTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteTargetGroupWithContext(aws.Context, *elbv2.DeleteTargetGroupInput, ...request.Option) (*elbv2.DeleteTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeleteTargetGroupRequest(*elbv2.DeleteTargetGroupInput) (*request.Request, *elbv2.DeleteTargetGroupOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DeregisterTargets(*elbv2.DeregisterTargetsInput) (*elbv2.DeregisterTargetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeregisterTargetsWithContext(aws.Context, *elbv2.DeregisterTargetsInput, ...request.Option) (*elbv2.DeregisterTargetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DeregisterTargetsRequest(*elbv2.DeregisterTargetsInput) (*request.Request, *elbv2.DeregisterTargetsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeAccountLimits(*elbv2.DescribeAccountLimitsInput) (*elbv2.DescribeAccountLimitsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeAccountLimitsWithContext(aws.Context, *elbv2.DescribeAccountLimitsInput, ...request.Option) (*elbv2.DescribeAccountLimitsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeAccountLimitsRequest(*elbv2.DescribeAccountLimitsInput) (*request.Request, *elbv2.DescribeAccountLimitsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenerCertificates(*elbv2.DescribeListenerCertificatesInput) (*elbv2.DescribeListenerCertificatesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenerCertificatesWithContext(aws.Context, *elbv2.DescribeListenerCertificatesInput, ...request.Option) (*elbv2.DescribeListenerCertificatesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenerCertificatesRequest(*elbv2.DescribeListenerCertificatesInput) (*request.Request, *elbv2.DescribeListenerCertificatesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListeners(input *elbv2.DescribeListenersInput) (*elbv2.DescribeListenersOutput, error) {
	var listeners []*elbv2.Listener

	// if we're looking for specific arns
	if input.LoadBalancerArn != nil {
		for idx := range elb.Listeners {
			if elb.Listeners[idx].LoadBalancerArn == input.LoadBalancerArn {
				listeners = append(listeners, elb.Listeners[idx])
			}
		}

		return &elbv2.DescribeListenersOutput{
			Listeners: listeners,
		}, nil
	} else { // otherwise just return all.
		return &elbv2.DescribeListenersOutput{
			Listeners: elb.Listeners,
		}, nil
	}
}

func (elb *MockELBV2API) DescribeListenersWithContext(aws.Context, *elbv2.DescribeListenersInput, ...request.Option) (*elbv2.DescribeListenersOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenersRequest(*elbv2.DescribeListenersInput) (*request.Request, *elbv2.DescribeListenersOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenersPages(*elbv2.DescribeListenersInput, func(*elbv2.DescribeListenersOutput, bool) bool) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeListenersPagesWithContext(aws.Context, *elbv2.DescribeListenersInput, func(*elbv2.DescribeListenersOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancerAttributes(*elbv2.DescribeLoadBalancerAttributesInput) (*elbv2.DescribeLoadBalancerAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancerAttributesWithContext(aws.Context, *elbv2.DescribeLoadBalancerAttributesInput, ...request.Option) (*elbv2.DescribeLoadBalancerAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancerAttributesRequest(*elbv2.DescribeLoadBalancerAttributesInput) (*request.Request, *elbv2.DescribeLoadBalancerAttributesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancers(input *elbv2.DescribeLoadBalancersInput) (*elbv2.DescribeLoadBalancersOutput, error) {
	var loadBalancers []*elbv2.LoadBalancer

	// if we're looking for specific arns
	if len(input.LoadBalancerArns) > 0 {
		for idx := range input.LoadBalancerArns {
			for nidx := range elb.LoadBalancers {
				if elb.LoadBalancers[nidx].LoadBalancerArn == input.LoadBalancerArns[idx] {
					loadBalancers = append(loadBalancers, elb.LoadBalancers[nidx])
				}
			}
		}
		return &elbv2.DescribeLoadBalancersOutput{
			LoadBalancers: loadBalancers,
		}, nil
	} else { // otherwise just return all.
		return &elbv2.DescribeLoadBalancersOutput{
			LoadBalancers: elb.LoadBalancers,
		}, nil
	}
}

func (elb *MockELBV2API) DescribeLoadBalancersWithContext(aws.Context, *elbv2.DescribeLoadBalancersInput, ...request.Option) (*elbv2.DescribeLoadBalancersOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancersRequest(*elbv2.DescribeLoadBalancersInput) (*request.Request, *elbv2.DescribeLoadBalancersOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancersPages(*elbv2.DescribeLoadBalancersInput, func(*elbv2.DescribeLoadBalancersOutput, bool) bool) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeLoadBalancersPagesWithContext(aws.Context, *elbv2.DescribeLoadBalancersInput, func(*elbv2.DescribeLoadBalancersOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeRules(*elbv2.DescribeRulesInput) (*elbv2.DescribeRulesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeRulesWithContext(aws.Context, *elbv2.DescribeRulesInput, ...request.Option) (*elbv2.DescribeRulesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeRulesRequest(*elbv2.DescribeRulesInput) (*request.Request, *elbv2.DescribeRulesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeSSLPolicies(*elbv2.DescribeSSLPoliciesInput) (*elbv2.DescribeSSLPoliciesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeSSLPoliciesWithContext(aws.Context, *elbv2.DescribeSSLPoliciesInput, ...request.Option) (*elbv2.DescribeSSLPoliciesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeSSLPoliciesRequest(*elbv2.DescribeSSLPoliciesInput) (*request.Request, *elbv2.DescribeSSLPoliciesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTags(*elbv2.DescribeTagsInput) (*elbv2.DescribeTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTagsWithContext(aws.Context, *elbv2.DescribeTagsInput, ...request.Option) (*elbv2.DescribeTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTagsRequest(*elbv2.DescribeTagsInput) (*request.Request, *elbv2.DescribeTagsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupAttributes(*elbv2.DescribeTargetGroupAttributesInput) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupAttributesWithContext(aws.Context, *elbv2.DescribeTargetGroupAttributesInput, ...request.Option) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupAttributesRequest(*elbv2.DescribeTargetGroupAttributesInput) (*request.Request, *elbv2.DescribeTargetGroupAttributesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroups(*elbv2.DescribeTargetGroupsInput) (*elbv2.DescribeTargetGroupsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupsWithContext(aws.Context, *elbv2.DescribeTargetGroupsInput, ...request.Option) (*elbv2.DescribeTargetGroupsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupsRequest(*elbv2.DescribeTargetGroupsInput) (*request.Request, *elbv2.DescribeTargetGroupsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupsPages(*elbv2.DescribeTargetGroupsInput, func(*elbv2.DescribeTargetGroupsOutput, bool) bool) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetGroupsPagesWithContext(aws.Context, *elbv2.DescribeTargetGroupsInput, func(*elbv2.DescribeTargetGroupsOutput, bool) bool, ...request.Option) error {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetHealth(*elbv2.DescribeTargetHealthInput) (*elbv2.DescribeTargetHealthOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetHealthWithContext(aws.Context, *elbv2.DescribeTargetHealthInput, ...request.Option) (*elbv2.DescribeTargetHealthOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) DescribeTargetHealthRequest(*elbv2.DescribeTargetHealthInput) (*request.Request, *elbv2.DescribeTargetHealthOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyListener(*elbv2.ModifyListenerInput) (*elbv2.ModifyListenerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyListenerWithContext(aws.Context, *elbv2.ModifyListenerInput, ...request.Option) (*elbv2.ModifyListenerOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyListenerRequest(*elbv2.ModifyListenerInput) (*request.Request, *elbv2.ModifyListenerOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyLoadBalancerAttributes(*elbv2.ModifyLoadBalancerAttributesInput) (*elbv2.ModifyLoadBalancerAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyLoadBalancerAttributesWithContext(aws.Context, *elbv2.ModifyLoadBalancerAttributesInput, ...request.Option) (*elbv2.ModifyLoadBalancerAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyLoadBalancerAttributesRequest(*elbv2.ModifyLoadBalancerAttributesInput) (*request.Request, *elbv2.ModifyLoadBalancerAttributesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyRule(*elbv2.ModifyRuleInput) (*elbv2.ModifyRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyRuleWithContext(aws.Context, *elbv2.ModifyRuleInput, ...request.Option) (*elbv2.ModifyRuleOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyRuleRequest(*elbv2.ModifyRuleInput) (*request.Request, *elbv2.ModifyRuleOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroup(*elbv2.ModifyTargetGroupInput) (*elbv2.ModifyTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroupWithContext(aws.Context, *elbv2.ModifyTargetGroupInput, ...request.Option) (*elbv2.ModifyTargetGroupOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroupRequest(*elbv2.ModifyTargetGroupInput) (*request.Request, *elbv2.ModifyTargetGroupOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroupAttributes(*elbv2.ModifyTargetGroupAttributesInput) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroupAttributesWithContext(aws.Context, *elbv2.ModifyTargetGroupAttributesInput, ...request.Option) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) ModifyTargetGroupAttributesRequest(*elbv2.ModifyTargetGroupAttributesInput) (*request.Request, *elbv2.ModifyTargetGroupAttributesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) RegisterTargets(*elbv2.RegisterTargetsInput) (*elbv2.RegisterTargetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) RegisterTargetsWithContext(aws.Context, *elbv2.RegisterTargetsInput, ...request.Option) (*elbv2.RegisterTargetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) RegisterTargetsRequest(*elbv2.RegisterTargetsInput) (*request.Request, *elbv2.RegisterTargetsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) RemoveListenerCertificates(input *elbv2.RemoveListenerCertificatesInput) (*elbv2.RemoveListenerCertificatesOutput, error) {
	// for each listener
	for idx := range elb.Listeners {
		// if the listener arn is the same as the one we want
		if *elb.Listeners[idx].ListenerArn == *input.ListenerArn {
			// for each certificate on the listener
			for nidx := range elb.Listeners[idx].Certificates {
				// if the certificate on the listener is the same one we want to remove
				if elb.Listeners[idx].Certificates[nidx] != nil {
					if *elb.Listeners[idx].Certificates[nidx].CertificateArn == *input.Certificates[0].CertificateArn {
						// remove it from the internal slice reference.
						elb.Listeners[idx].Certificates = append(elb.Listeners[idx].Certificates[:nidx], elb.Listeners[idx].Certificates[nidx+1:]...)
						return &elbv2.RemoveListenerCertificatesOutput{}, nil
					}
				}
			}
		}
	}
	return &elbv2.RemoveListenerCertificatesOutput{}, errors.New("cannot find elb listener certificate")
}

func (elb *MockELBV2API) RemoveListenerCertificatesWithContext(aws.Context, *elbv2.RemoveListenerCertificatesInput, ...request.Option) (*elbv2.RemoveListenerCertificatesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) RemoveListenerCertificatesRequest(*elbv2.RemoveListenerCertificatesInput) (*request.Request, *elbv2.RemoveListenerCertificatesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) RemoveTags(*elbv2.RemoveTagsInput) (*elbv2.RemoveTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) RemoveTagsWithContext(aws.Context, *elbv2.RemoveTagsInput, ...request.Option) (*elbv2.RemoveTagsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) RemoveTagsRequest(*elbv2.RemoveTagsInput) (*request.Request, *elbv2.RemoveTagsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) SetIpAddressType(*elbv2.SetIpAddressTypeInput) (*elbv2.SetIpAddressTypeOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetIpAddressTypeWithContext(aws.Context, *elbv2.SetIpAddressTypeInput, ...request.Option) (*elbv2.SetIpAddressTypeOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetIpAddressTypeRequest(*elbv2.SetIpAddressTypeInput) (*request.Request, *elbv2.SetIpAddressTypeOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) SetRulePriorities(*elbv2.SetRulePrioritiesInput) (*elbv2.SetRulePrioritiesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetRulePrioritiesWithContext(aws.Context, *elbv2.SetRulePrioritiesInput, ...request.Option) (*elbv2.SetRulePrioritiesOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetRulePrioritiesRequest(*elbv2.SetRulePrioritiesInput) (*request.Request, *elbv2.SetRulePrioritiesOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSecurityGroups(*elbv2.SetSecurityGroupsInput) (*elbv2.SetSecurityGroupsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSecurityGroupsWithContext(aws.Context, *elbv2.SetSecurityGroupsInput, ...request.Option) (*elbv2.SetSecurityGroupsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSecurityGroupsRequest(*elbv2.SetSecurityGroupsInput) (*request.Request, *elbv2.SetSecurityGroupsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSubnets(*elbv2.SetSubnetsInput) (*elbv2.SetSubnetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSubnetsWithContext(aws.Context, *elbv2.SetSubnetsInput, ...request.Option) (*elbv2.SetSubnetsOutput, error) {
	panic("implement me")
}

func (elb *MockELBV2API) SetSubnetsRequest(*elbv2.SetSubnetsInput) (*request.Request, *elbv2.SetSubnetsOutput) {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancerAvailable(*elbv2.DescribeLoadBalancersInput) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancerAvailableWithContext(aws.Context, *elbv2.DescribeLoadBalancersInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancerExists(*elbv2.DescribeLoadBalancersInput) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancerExistsWithContext(aws.Context, *elbv2.DescribeLoadBalancersInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancersDeleted(*elbv2.DescribeLoadBalancersInput) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilLoadBalancersDeletedWithContext(aws.Context, *elbv2.DescribeLoadBalancersInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilTargetDeregistered(*elbv2.DescribeTargetHealthInput) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilTargetDeregisteredWithContext(aws.Context, *elbv2.DescribeTargetHealthInput, ...request.WaiterOption) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilTargetInService(*elbv2.DescribeTargetHealthInput) error {
	panic("implement me")
}

func (elb *MockELBV2API) WaitUntilTargetInServiceWithContext(aws.Context, *elbv2.DescribeTargetHealthInput, ...request.WaiterOption) error {
	panic("implement me")
}
