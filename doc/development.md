# Development

## Running Tests

In order to run the tests, you must have a local postgresql instance running.  In MacOS, you'd run the following:

``` console
$ brew install postgresql
$ createuser test
```

### ACME Mocking

We use an [integration ACME tool called Gravel](https://github.com/18f/gravel),
which allows us to locally fake the LE ACME server implementation.  One benefit
is the ability to simulate slow DNS propagation, which helps test our
`preCheck` algorithm.

### Units

Just run `go test -v ./...`

> **TODO**: Currently one of the tests fail as Gravel somehow attempts to spin
> up two DNS servers on `:5454` (this is my best guess).

### Acceptance Tests

TODO

### CI

TODO

## Architecture

### Startup

The main entry point is `main()` in the [`cmd/main.go`](/cmd/main.go) package.

This sets up the usual boilerplate:

* Configures itself via the environment
* Initializes logging
* Runs DB migrations
* Connects to AWS
* Launches the http listener using the cf broker library
* Starts the `GlobalQueueManager`

The `GlobalQueueManager` is where things get interesting...

### Managers

The managers perform the bulk of the processing, and are implemented as
[virtual actors](https://blog.r3t.io/virtual-actors-in-go/).  Each manager runs
as a go-routine, and listens on a channel for requests.

The `GlobalQueueManager` is started first, which listens on the main channel,
and routes requests to the other managers.  Requests are routed based on their
`Type` field.

Here's an example of how to post such a request (this is the virtual actor
equivalent of making an asynchronous function call):

``` go
responseChannel := make(chan StateTransitionResponse, 1)
w.globalQueueManagerChan <- ManagerRequest{
    InstanceId: request.InstanceId,
    Type:       StateManagerType,
    Payload: StateTransitionRequest{
        InstanceId:   request.InstanceId,
        DesiredState: New,
        Response:     responseChannel,
    },
}
response := <-responseChannel
close(responseChannel)

if !response.Ok {
    // ...
}
```

Currently, the three managers the `GlobalQueueManager` routes to are:

* [`StateManager`](/managers/state_manager.go): Moves objects through state transitions, recording state in the DB.
* [`ObtainmentManager`](/managers/obtainment_manager.go): Implements an async version of the ACME protocol.
* [`WorkerManager`](/managers/worker_manager.go): Uploads certs to AWS, assigns ELBs,

Each of these managers in turn spawns their own go-routines, and has internal
dispatching via internal channels to route their requests to them.

### Why We Save State

As mentioned in [the `README`](/README.md#lets-encrypt-challenge-challenges),
we must use an unusual ACME challenge process with Let's Encrypt when creating
a certificate.

The canonical ACME implementation in Go is `lego`, which implements the
challenge as a monolithic and _non_-idempotent [`Obtain()`
function](https://godoc.org/github.com/go-acme/lego/certificate#Certifier.Obtain).
`Obtain()`:

1. initiates the DNS01 challenge
2. hands the TXT record to the cloud provider (in our case, a human)
3. waits for the record to be set
4. finalizes the challenge

This isn't idempotent because step 1 always results in a new validation token,
which changes the DNS TXT record that must be set.  This can happen if the
broker is redeployed while in an `Obtain()` call, interrupting that flow and
restarting the challenge when the new broker process starts up.

To avoid this, we re-implement `Obtain()` inside the `ObtainmentManager` so
that it first reads and checkpoints the state of the service instance to
Postgresql.  If the instance is in the middle of waiting for DNS resolution, we
don't request a new token and instead pick up where we left off by waiting for
DNS resolution.

This checkpointing and state transition logic is managed by the `StateManager`.

#### Trade-offs

All of the complexity above (the virtual actor pattern, the constant management
of state, and the re-implementation of `lego`) is to lessen the impact on users
when we re-deploy or restart the broker.

It's worth discussing whether this is worth the complexity.  How many certs do
we expect to be in the middle of obtainment at any given moment?  How much of
an impact on the end user would it be to simply change the token and present
new DNS instructions?  Could this be mitigated by documentation and/or
hand-holding by the operations team?

### The Broker

TODO

### Post-ACME progression

TODO
