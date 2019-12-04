package managers

// State references.
type State float64

const (
	Unknown                State = -2
	Error                  State = -1
	New                    State = 0
	Provisioning           State = 1
	PreOrder               State = 1.1
	Ordered                State = 1.2
	Authorized             State = 1.3
	PreSolve               State = 1.4
	PostSolve              State = 1.5
	Finalized              State = 1.6
	CertificateReady       State = 1.7
	IamCertificateUploaded State = 1.8
	ElbAssigned            State = 1.9
	Provisioned            State = 2
	// todo (mxplusb): there should be more states than this but I don't know what they would be just yet.
	Deprovisioning State = 3
	Deprovisioned  State = 4
)

// Load and Store things!
type Op string

const (
	Store Op = "store"
	Load  Op = "load"
)

type QueueType string

const (
	StateManagerType      QueueType = "state"
	ObtainmentManagerType QueueType = "obtain"
	WorkerManagerType     QueueType = "worker"
)

const (
	AcmeRateLimit = 18
)
