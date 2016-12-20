package mocks

import mock "github.com/stretchr/testify/mock"
import models "github.com/18F/cf-cdn-service-broker/models"

// RouteManagerIface is an autogenerated mock type for the RouteManagerIface type
type RouteManagerIface struct {
	mock.Mock
}

// Create provides a mock function with given fields: instanceId, domain, origin, path, insecureOrigin, tags
func (_m *RouteManagerIface) Create(instanceId string, domain string, origin string, path string, insecureOrigin bool, tags map[string]string) (models.Route, error) {
	ret := _m.Called(instanceId, domain, origin, path, insecureOrigin, tags)

	var r0 models.Route
	if rf, ok := ret.Get(0).(func(string, string, string, string, bool, map[string]string) models.Route); ok {
		r0 = rf(instanceId, domain, origin, path, insecureOrigin, tags)
	} else {
		r0 = ret.Get(0).(models.Route)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string, string, bool, map[string]string) error); ok {
		r1 = rf(instanceId, domain, origin, path, insecureOrigin, tags)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Disable provides a mock function with given fields: route
func (_m *RouteManagerIface) Disable(route models.Route) error {
	ret := _m.Called(route)

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: instanceId
func (_m *RouteManagerIface) Get(instanceId string) (models.Route, error) {
	ret := _m.Called(instanceId)

	var r0 models.Route
	if rf, ok := ret.Get(0).(func(string) models.Route); ok {
		r0 = rf(instanceId)
	} else {
		r0 = ret.Get(0).(models.Route)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(instanceId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Renew provides a mock function with given fields: route
func (_m *RouteManagerIface) Renew(route models.Route) error {
	ret := _m.Called(route)

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RenewAll provides a mock function with given fields:
func (_m *RouteManagerIface) RenewAll() {
	_m.Called()
}

// Update provides a mock function with given fields: route
func (_m *RouteManagerIface) Update(route models.Route) error {
	ret := _m.Called(route)

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

var _ models.RouteManagerIface = (*RouteManagerIface)(nil)
