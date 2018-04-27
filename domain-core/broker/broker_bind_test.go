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
	_, err := b.Bind(context.Background(), "", "", brokerapi.BindDetails{})
	assert.NotNil(t, err)
}

func TestUnbind(t *testing.T) {
	b := broker.DomainBroker{}
	err := b.Unbind(context.Background(), "", "", brokerapi.UnbindDetails{})
	assert.NotNil(t, err)
}
