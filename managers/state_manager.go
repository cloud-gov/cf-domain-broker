package managers

import (
	"context"
	"errors"

	"code.cloudfoundry.org/lager"
	"github.com/jinzhu/gorm"
)

type StateManagerSettings struct {
	Autostart bool
	Db        *gorm.DB
	Logger    lager.Logger
}

type StateManager struct {
	db                       *gorm.DB
	RequestRouter            chan interface{}
	Running                  bool
	globalQueueManagerChan   chan ManagerRequest
	logger                   lager.Logger
	stateRequester           chan StateRequest
	stateTransitionRequester chan StateTransitionRequest
}

func NewStateManager(settings *StateManagerSettings) (*StateManager, error) {
	s := &StateManager{
		db:                       settings.Db,
		RequestRouter:            make(chan interface{}, 150),
		logger:                   settings.Logger.Session("state-manager"),
		stateRequester:           make(chan StateRequest, 150),
		stateTransitionRequester: make(chan StateTransitionRequest, 150),
	}

	if err := s.db.AutoMigrate(&StateModel{}).Error; err != nil {
		return &StateManager{}, err
	}

	if settings.Autostart {
		s.Run()
		s.Running = true
	} else {
		s.Running = false
	}

	return s, nil
}

type StateRequest struct {
	Context    context.Context
	InstanceId string
	Response   chan StateResponse
}

type StateResponse struct {
	InstanceId   string
	Error        error
	CurrentState State
}

type StateModel struct {
	gorm.Model
	InstanceId    string `gorm:"not null;unique_index;primary_key"`
	CurrentState  State
	PreviousState State
	ErrorMessage  string
}

type StateTransitionRequest struct {
	Context      context.Context
	InstanceId   string
	CurrentState State
	DesiredState State
	ErrorMessage string
	Response     chan StateTransitionResponse
}

type StateTransitionResponse struct {
	InstanceId      string
	NewCurrentState State
	Error           error
	Ok              bool
}

// todo (mxplusb): figure out how to stop this.
// todo (mxplusb): figure out how to pass a context around.
func (s *StateManager) Run() {
	go func() {
		for {
			msg := <-s.RequestRouter
			switch msg.(type) {
			case StateRequest:
				s.stateRequester <- msg.(StateRequest)
			}
		}
	}()

	s.stateRequesterRunner()
	s.stateTransitionRequestRunner()
}

func (s *StateManager) stateRequesterRunner() {
	go func() {
		for {
			msg := <-s.stateRequester
			go s.stateRequest(msg)
		}
	}()
}

func (s *StateManager) stateRequest(request StateRequest) {
	var stateModel StateModel
	results := s.db.Where("instance_id = ?", request.InstanceId).Find(&stateModel)
	request.Response <- StateResponse{
		InstanceId:   request.InstanceId,
		Error:        results.Error,
		CurrentState: stateModel.CurrentState,
	}
}

func (s *StateManager) stateTransitionRequestRunner() {
	go func() {
		msg := <-s.stateTransitionRequester
		go s.stateTransition(msg)
	}()
}

// Transition from one state to another.
func (s *StateManager) stateTransition(request StateTransitionRequest) {
	lsession := s.logger.Session("state-transition", lager.Data{
		"instance-id": request.InstanceId,
	})
	var stateModel StateModel

	if request.CurrentState == New {
		lsession.Info("create-new-service-instance-state")
		stateModel = StateModel{
			InstanceId:    request.InstanceId,
			CurrentState:  New,
			PreviousState: Unknown,
		}
		tx := s.db.Begin()
		results := tx.Create(stateModel)
		if results.Error != nil {
			lsession.Error("cannot-create-new-service-instance-state", results.Error)
			tx.Rollback()
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           results.Error,
				Ok:              false,
			}
			return
		}
		tx.Commit()
		return
	}

	results := s.db.Where("instance_id = ?", request.InstanceId).Find(&stateModel)
	if results.RecordNotFound() {
		lsession.Error("service-instance-state-not-found", results.Error)
		request.Response <- StateTransitionResponse{
			InstanceId:      request.InstanceId,
			NewCurrentState: Error,
			Error:           nil,
			Ok:              false,
		}
		return
	} else if results.Error != nil {
		lsession.Error("service-instance-state-find-error", results.Error)
		request.Response <- StateTransitionResponse{
			InstanceId:      request.InstanceId,
			NewCurrentState: Error,
			Error:           results.Error,
			Ok:              false,
		}
		return
	}

	// here is where our core logic gets a little overloaded, because we have to do state validation.
	// the goal here is to break out of this control structure, because we only want to transition properly.
	// we'll return if there is a provisioning error.
	// this exists mostly as a developer-focused workflow check more than anything else due to the complexity of this
	// workflow.
	var err error
	if request.CurrentState == New && request.DesiredState != Provisioning {
		err = errors.New("cannot change from new to a state other than provisioning")
	} else if request.CurrentState == Provisioning && request.DesiredState != PreOrder {
		err = errors.New("cannot change from provisioning to a state other than preorder")
	} else if request.CurrentState == PreOrder && request.DesiredState != Authorized {
		err = errors.New("cannot change from preorder to a state other than authorized")
	} else if request.CurrentState == Authorized && request.DesiredState != PreSolve {
		err = errors.New("cannot change from authorized to a state other than presolve")
	} else if request.CurrentState == PreSolve && request.DesiredState != PostSolve {
		err = errors.New("cannot change from presolve to a state other than postsolve")
	} else if request.CurrentState == PostSolve && request.DesiredState != Finalized {
		err = errors.New("cannot change from postsolve to a state other than finalized")
	} else if request.CurrentState == Finalized && request.DesiredState != CertificateReady {
		err = errors.New("cannot change from finalized to a state other than certificate ready")
	}

	if err != nil {
		lsession.Error("invalid-state-change", err, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		request.Response <- StateTransitionResponse{
			InstanceId:      request.InstanceId,
			NewCurrentState: Error,
			Error:           err,
			Ok:              false,
		}
		return
	}

	stateModel.PreviousState = stateModel.CurrentState
	stateModel.CurrentState = request.DesiredState
	stateModel.ErrorMessage = request.ErrorMessage

	// try to update the state. if there are any errors, return them if the response channel is not nil.
	tx := s.db.Begin()
	results = tx.Update(stateModel)
	if results.Error != nil {
		if results.RecordNotFound() {
			lsession.Error("cannot-update-state-because-record-not-found", results.Error, lager.Data{
				"current-state": request.CurrentState,
				"desired-state": request.DesiredState,
			})
			if request.Response != nil {
				request.Response <- StateTransitionResponse{
					InstanceId:      request.InstanceId,
					NewCurrentState: Error,
					Error:           results.Error,
					Ok:              false,
				}
			}
			tx.Rollback()
			return
		}
		lsession.Error("cannot-update-state", results.Error, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           results.Error,
				Ok:              false,
			}
		}
		tx.Rollback()
		return
	}
	tx.Commit()
}
