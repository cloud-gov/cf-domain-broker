package managers

import (
	"errors"
	"os"
	"testing"

	"code.cloudfoundry.org/lager"
	"github.com/go-pg/pg/v9"
	"github.com/go-pg/pg/v9/orm"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/suite"
)

type StateManagerSuite struct {
	suite.Suite
	stateManager *StateManager
	db           *pg.DB
}

func TestStateManagerSuite(t *testing.T) {
	suite.Run(t, new(StateManagerSuite))
}

func (s *StateManagerSuite) SetupTest() {
	logger := lager.NewLogger("state-manager-test")
	logger.RegisterSink(lager.NewPrettySink(os.Stdout, lager.DEBUG))

	s.db = pg.Connect(&pg.Options{Addr: "127.0.0.1:5432", User: "test", Password: "testpass"})
	s.db.AddQueryHook(dbTestlogger{
		logger: logger.Session("db-logger"),
	})

	var err error
	s.stateManager, err = NewStateManager(&StateManagerSettings{
		Autostart: false,
		AutoPoll:  false,
		Db:        s.db,
		Logger:    logger,
	})
	if err != nil {
		s.T().Error(err)
		s.T().FailNow()
	}
}

func (s *StateManagerSuite) TearDownTest() {

	// clean up the table
	if err := s.stateManager.db.DropTable(&StateModel{}, &orm.DropTableOptions{Cascade: true}); err != nil {
		s.T().Error(err)
		s.T().FailNow()
	}

	// close the connection.
	if err := s.stateManager.db.Close(); err != nil {
		s.T().Error(err)
		s.T().FailNow()
	}
}

func (s *StateManagerSuite) TestStateRequest() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(New),
		PreviousState: float64(Unknown),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&expected); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateResponse, 1)
	testRequest := StateRequest{
		InstanceId: serviceInstanceId,
		Response:   respc,
	}
	// make the request.
	s.stateManager.stateRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when querying for state")
	s.Require().Equal(expected, resp.Model, "the models should be equal")
}

func (s *StateManagerSuite) TestNewStateModel() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: New,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(New),
		PreviousState: float64(Unknown),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromNew() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: New,
		DesiredState: PreOrder,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from new to a state other than provisioning"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestNewStateToProvisioningStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(New),
		PreviousState: float64(Unknown),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: Provisioning,
		CurrentState: New,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Provisioning),
		PreviousState: float64(New),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromProvisioning() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: Provisioning,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from provisioning to a state other than preorder"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestProvisioningStateToPreOrderStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Provisioning),
		PreviousState: float64(New),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: PreOrder,
		CurrentState: Provisioning,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PreOrder),
		PreviousState: float64(Provisioning),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromPreOrder() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: PreOrder,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from preorder to a state other than authorized"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestPreOrderStateToAuthorizedStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PreOrder),
		PreviousState: float64(Provisioning),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: Authorized,
		CurrentState: PreOrder,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Authorized),
		PreviousState: float64(PreOrder),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromAuthorized() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: Authorized,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from authorized to a state other than presolve"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestAuthorizedStateToPreSolveStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Authorized),
		PreviousState: float64(PreOrder),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: PreSolve,
		CurrentState: Authorized,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PreSolve),
		PreviousState: float64(Authorized),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromPreSolve() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: PreSolve,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from presolve to a state other than postsolve"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestPreSolveStateToPostSolveStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PreSolve),
		PreviousState: float64(Authorized),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: PostSolve,
		CurrentState: PreSolve,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PostSolve),
		PreviousState: float64(PreSolve),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromPostSolve() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: PostSolve,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from postsolve to a state other than finalized"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}

func (s *StateManagerSuite) TestPostSolveStateToFinalizedStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(PostSolve),
		PreviousState: float64(PreSolve),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: Finalized,
		CurrentState: PostSolve,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Finalized),
		PreviousState: float64(PostSolve),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}

func (s *StateManagerSuite) TestInvalidStateTransitionFromFinalized() {
	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	respc := make(chan StateTransitionResponse, 1)
	invalidTestRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		CurrentState: Finalized,
		DesiredState: New,
		Response:     respc,
	}
	s.stateManager.stateTransitionRequester <- invalidTestRequest
	resp := <-respc

	s.Require().Error(resp.Error, errors.New("cannot change from finalized to a state other than certificate ready"))
	s.Require().Equal(Error, resp.NewCurrentState, "state must be error")
}


func (s *StateManagerSuite) TestFinalizedStateToCertificateReadyStateChange() {

	s.stateManager.Run()

	serviceInstanceId := uuid.New()

	prepared := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(Finalized),
		PreviousState: float64(PostSolve),
		ErrorMessage:  "",
	}

	if err := s.db.Insert(&prepared); err != nil {
		s.Require().NoError(err, "there should be no error preparing a state model")
	}

	respc := make(chan StateTransitionResponse, 1)
	testRequest := StateTransitionRequest{
		InstanceId:   serviceInstanceId,
		DesiredState: CertificateReady,
		CurrentState: Finalized,
		Response:     respc,
	}

	// make the request.
	s.stateManager.stateTransitionRequester <- testRequest
	resp := <-respc

	s.Require().NoError(resp.Error, "there should be no error when creating a new state.")

	expected := StateModel{
		InstanceId:    serviceInstanceId,
		CurrentState:  float64(CertificateReady),
		PreviousState: float64(Finalized),
		ErrorMessage:  "",
	}

	dbStateModel := StateModel{InstanceId: serviceInstanceId}
	if err := s.db.Model(&dbStateModel).Where("instance_id = ?", serviceInstanceId).First(); err != nil {
		s.Require().NoError(err, "there should be no error querying for the new state model")
	}

	s.Require().Equal(expected.InstanceId, dbStateModel.InstanceId, "the instance ids should be equal")
	s.Require().Equal(expected.CurrentState, dbStateModel.CurrentState, "the current state values should be equal")
	s.Require().Equal(expected.PreviousState, dbStateModel.PreviousState, "the previous state values should be equal")
	s.Require().Equal(expected.ErrorMessage, dbStateModel.ErrorMessage, "the error message values should be empty and equal")
}
