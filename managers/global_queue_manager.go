package managers

type GlobalQueueManagerSettings struct {
	// Autostart all the workers, this should be true.
	Autostart                 bool
	QueueDepth                int
	*ObtainmentManagerSettings
	*StateManagerSettings
	*WorkerManagerSettings
}

type GlobalQueueManager struct {
	Queue             chan ManagerRequest
	Running           bool
	workerManager     *WorkerManager
	obtainmentManager *ObtainmentManager
	stateManager      *StateManager
}

func NewGlobalQueueManager(settings *GlobalQueueManagerSettings) (*GlobalQueueManager, error) {
	g := &GlobalQueueManager{
		Queue: make(chan ManagerRequest, settings.QueueDepth),
	}

	wm, err := NewWorkerManager(settings.WorkerManagerSettings)
	if err != nil {
		return &GlobalQueueManager{}, nil
	}
	wm.globalQueueManagerChan = g.Queue
	g.workerManager = wm

	om, err := NewObtainmentManager(settings.ObtainmentManagerSettings)
	if err != nil {
		return &GlobalQueueManager{}, err
	}
	om.globalQueueManagerChan = g.Queue
	g.obtainmentManager = om

	sm, err := NewStateManager(settings.StateManagerSettings)
	if err != nil {
		return &GlobalQueueManager{}, err
	}
	sm.globalQueueManagerChan = g.Queue
	g.stateManager = sm

	if settings.Autostart {
		g.Run()
		g.Running = true
	} else {
		g.Running = false
	}

	return g, nil
}

func (g *GlobalQueueManager) Run() {
	g.routerRunner()
}

type ManagerRequest struct {
	InstanceId string
	Type       QueueType
	Payload    interface{}
}

func (g *GlobalQueueManager) routerRunner() {
	go func() {
		for {
			msg := <-g.Queue
			switch msg.Type {
			case StateManagerType:
				g.stateManager.RequestRouter <- msg.Payload
			case ObtainmentManagerType:
				g.obtainmentManager.RequestRouter <- msg.Payload
			case WorkerManagerType:
				g.workerManager.RequestRouter <- msg.Payload
			}
		}
	}()
}
