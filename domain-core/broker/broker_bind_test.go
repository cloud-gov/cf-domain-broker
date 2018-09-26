package broker_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pivotal-cf/brokerapi"

	"github.com/18F/cf-domain-broker-alb/broker"
)

func TestBind(t *testing.T) {
	b := broker.DomainBroker{}
	_, err := b.Bind(context.Background(), "", "", brokerapi.BindDetails{}, false)
	assert.NotNil(t, err)
}

func TestUnbind(t *testing.T) {
	b := broker.DomainBroker{}
	_, err := b.Unbind(context.Background(), "", "", brokerapi.UnbindDetails{}, false)
	assert.NotNil(t, err)
}

func TestGetBinding(t *testing.T) {
	b := broker.DomainBroker{}
	_, err := b.GetBinding(context.Background(), "", "")
	assert.NotNil(t, err)
}

func TestLastBindingOperation(t *testing.T) {
	b := broker.DomainBroker{}
	_, err := b.LastBindingOperation(context.Background(), "", "", brokerapi.PollDetails{})
	assert.NotNil(t, err)
}