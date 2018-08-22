# Architecture Design Record: SS🐙 Authenticator Circuit Breaker

> Gracefully handle provider-side faults and failures.

__Status:__ Implemented

#### Context
SS🐙 fundamentally relies on a third-party provider service to authenticate requests (e.g. OAuth2
via Google). The provider may experience transient faults for any number of reasons - perhaps the
provider is experiencing a transient outage, or our traffic has been temporarily rate limited. We
wanted to build SS🐙 to anticipate and handle the presence of faults during communication with
authentication providers, no matter the underlying cause.

#### Decision
We implemented a generic `circuit.Breaker` type, which implements the "Circuit Breaker" design
pattern made popular by Michael T. Nygard's book, ["Release It!"](
https://pragprog.com/book/mnee/release-it). All requests to the provider service are issued through
a stateful `circuit.Breaker` instance, which tracks the frequency of request failures. When the
`Breaker` sees that enough requests are failing, it temporarily suspends all outgoing traffic to the
provider (i.e. "enters `Open` state). After some time, the `Breaker` transitions to a `HalfOpen`
state, in which a limited number of outbound requests are allowed. If failures persist, then the
`Breaker` will once again suspend outbound traffic, re-enter `Open` state, and typically will wait
for a longer interval of time before trying again. If instead the `Breaker` observes that requests
are consistently succeeding, then it will resume all outbound traffic (i.e. enter `Closed` state).

The SS🐙 [`docs`](/docs/) directory contains a [Circuit Breaker](
/docs/architecture/circuit-breaker.md) document with more details. The implementation can be found
in [`breaker.go`](/internal/auth/circuit/breaker.go)

#### Consequences
SS🐙 now utilizes a robust and generic strategy for handling faults originating from the upstream
authentication provider service.
