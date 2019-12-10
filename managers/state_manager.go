package managers

import (
	"context"
	"errors"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/go-pg/pg/v9"
	"github.com/go-pg/pg/v9/orm"
	"github.com/pivotal-cf/brokerapi/domain"
)

type StateManagerSettings struct {
	Autostart bool
	AutoPoll  bool
	Db        *pg.DB
	Logger    lager.Logger
}

type StateManager struct {
	db                       *pg.DB
	RequestRouter            chan interface{}
	Running                  bool
	PollRunning              bool
	autoPoll                 bool
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

	if err := s.db.CreateTable(&StateModel{}, &orm.CreateTableOptions{
		Varchar:       255,
		Temp:          false,
		IfNotExists:   true,
		FKConstraints: false,
	}); err != nil {
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

// todo (mxplusb): figure out how to stop this.
// todo (mxplusb): figure out how to pass a context around.
func (s *StateManager) Run() {
	go func() {
		for {
			msg := <-s.RequestRouter
			switch msg.(type) {
			case StateRequest:
				s.stateRequester <- msg.(StateRequest)
			case StateTransitionRequest:
				s.stateTransitionRequester <- msg.(StateTransitionRequest)
			}
		}
	}()

	s.stateRequesterRunner()
	s.stateTransitionRequestRunner()

	if s.autoPoll {
		s.pollRunner()
		s.PollRunning = true
	} else {
		s.PollRunning = false
	}
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
	Model        StateModel
}

type StateModel struct {
	InstanceId    string  `pg:",pk"`
	CurrentState  float64 `pg:",notnull"`
	PreviousState float64 `pg:",notnull"`
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
	s.logger.Session("state-request").Debug("querying-for-state", lager.Data{
		"instance-id": request.InstanceId,
	})
	if err := s.db.Model(&stateModel).Where("instance_id = ?", request.InstanceId).First(); err != nil {
		request.Response <- StateResponse{
			InstanceId: request.InstanceId,
			Error:      err,
			Model:      stateModel,
		}
	}
	request.Response <- StateResponse{
		InstanceId: request.InstanceId,
		Error:      nil,
		Model:      stateModel,
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

	// here is where our core logic gets a little overloaded, because we have to do state validation.
	// the goal here is to break out of this control structure, because we only want to transition properly.
	// we'll return if there is a provisioning error.
	// this exists mostly as a developer-focused workflow check more than anything else due to the complexity of this
	// workflow.
	// todo (mxplusb): pull into variables.
	var err error
	if request.DesiredState == New && request.CurrentState == 0 {
		goto stateVerified
	} else if request.CurrentState == New && request.DesiredState != Provisioning {
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

stateVerified:

	if err != nil {
		lsession.Error("invalid-state-change", err, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           err,
				Ok:              false,
			}
			return
		}
		return
	}

	// our db reference.
	var stateModel StateModel

	if request.DesiredState == New {
		lsession.Info("create-new-service-instance-state")
		stateModel = StateModel{
			InstanceId:    request.InstanceId,
			CurrentState:  float64(New),
			PreviousState: float64(Unknown),
		}
		tx, err := s.db.Begin()
		if err != nil {
			lsession.Error("cannot-create-new-state-transaction", err)
			if request.Response != nil {
				request.Response <- StateTransitionResponse{
					InstanceId:      request.InstanceId,
					NewCurrentState: Error,
					Error:           err,
					Ok:              false,
				}
			}
			return
		}
		if err := tx.Insert(&stateModel); err != nil {
			lsession.Error("cannot-create-new-service-instance-state", err)
			tx.Rollback()
			if request.Response != nil {
				request.Response <- StateTransitionResponse{
					InstanceId:      request.InstanceId,
					NewCurrentState: Error,
					Error:           err,
					Ok:              false,
				}
			}
			return
		}
		if err := tx.Commit(); err != nil {
			tx.Rollback()
			if request.Response != nil {
				request.Response <- StateTransitionResponse{
					InstanceId:      request.InstanceId,
					NewCurrentState: Error,
					Error:           err,
					Ok:              false,
				}
			}
			return
		}
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Provisioning,
				Error:           err,
				Ok:              true,
			}
		}
		return
	}

	if err := s.db.Model(&stateModel).Where("instance_id = ?", request.InstanceId).First(); err != nil {
		lsession.Error("service-instance-state-find-error", err)
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           err,
				Ok:              false,
			}
		}
		return
	}

	stateModel.PreviousState = stateModel.CurrentState
	stateModel.CurrentState = float64(request.DesiredState)
	stateModel.ErrorMessage = request.ErrorMessage

	// try to update the state. if there are any errors, return them if the response channel is not nil.
	tx, err := s.db.Begin()
	if err != nil {
		lsession.Error("cannot-create-state-update-transaction", err, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           err,
				Ok:              false,
			}
		}
		tx.Rollback()
		return
	}
	lsession.Debug("beginning-transaction")

	err = tx.Update(&stateModel)
	if err != nil {
		lsession.Error("cannot-update-state", err, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           err,
				Ok:              false,
			}
		}
		tx.Rollback()
		return
	}
	lsession.Info("updated-state")

	err = tx.Commit()
	if err != nil {
		lsession.Error("cannot-commit-state-update", err, lager.Data{
			"current-state": request.CurrentState,
			"desired-state": request.DesiredState,
		})
		if request.Response != nil {
			request.Response <- StateTransitionResponse{
				InstanceId:      request.InstanceId,
				NewCurrentState: Error,
				Error:           err,
				Ok:              false,
			}
		}
		tx.Rollback()
		return
	}
	lsession.Debug("state-committed")

	request.Response <- StateTransitionResponse{
		InstanceId:      request.InstanceId,
		NewCurrentState: request.DesiredState,
		Error:           nil,
		Ok:              true,
	}
}

// This function just polls for the last operation so the workflow will continue to move state.
func (s *StateManager) pollRunner() {
	go func() {

		lsession := s.logger.Session("poll-runner")

		tick := time.Millisecond * 10000
		failTime := tick - 100

		ticker := time.NewTicker(tick)
		for ; true; <-ticker.C {

			lsession.Info("tick")

			// todo (mxplusb): figure out how to implement canceling.
			ctx := context.TODO()

			var localDomainRoutes []StateModel
			if err := s.db.Model(&localDomainRoutes).Where("current_state < ?", Provisioned).Select(); err != nil {
				lsession.Error("error-finding-currently-provisioning-records", err)
				continue
			}

			lsession.Debug("state-models", lager.Data{
				"models": localDomainRoutes,
			})

			respc := make(chan LastOperationResponse, len(localDomainRoutes))

			for idx := range localDomainRoutes {
				if localDomainRoutes[idx].ErrorMessage == "" {
					s.globalQueueManagerChan <- ManagerRequest{
						InstanceId: localDomainRoutes[idx].InstanceId,
						Type:       WorkerManagerType,
						Payload: LastOperationRequest{
							Context:    ctx,
							InstanceId: localDomainRoutes[idx].InstanceId,
							Details:    domain.PollDetails{},
							Response:   respc,
						},
					}
				}
			}

			// sleep for a bit, then close.
			time.Sleep(failTime)
			close(respc)
		}
	}()
}
