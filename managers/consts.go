package managers

// State references.
type State float64

const (
	Unknown                State = -2
	Error                  State = -1
	New                    State = 1 // starts at 1 because 0 is considered null.
	Provisioning           State = 2
	PreOrder               State = 2.1
	Ordered                State = 2.2
	Authorized             State = 2.3
	PreSolve               State = 2.4
	PostSolve              State = 2.5
	Finalized              State = 2.6
	CertificateReady       State = 2.7
	IamCertificateUploaded State = 2.8
	ElbAssigned            State = 2.9
	Provisioned            State = 3
	// todo (mxplusb): there should be more states than this but I don't know what they would be just yet.
	Deprovisioning State = 4
	Deprovisioned  State = 5
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

const (
	errNotFound = "no rows in result set"
)
