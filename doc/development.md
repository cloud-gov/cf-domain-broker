# Development

## Architecture

## Testing

We use an [integration ACME tool called Gravel](https://github.com/18f/gravel),
which allows us to locally fake the LE ACME server implementation.  One benefit
is the ability to simulate slow DNS propagation, which helps test our
`preCheck` algorithm.
