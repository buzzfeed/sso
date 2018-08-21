Package Circuit
===============

> Handle faults that might take a variable amount of time to recover from,
when connecting to a remote service or resource. This can be due to either network
failures (dns, tcp timeouts/errors), application errors (service is down), or service quality
load shedding (you as a client are making too many requests and are getting ratelimited).

# Background
The Circuit Breaker pattern, popularized by Michael Nygard in his book, Release It!,
can prevent an application from repeatedly trying to execute an operation that's likely to fail.
The Circuit Breaker pattern also enables an application to detect whether the fault has been resolved.
If the problem appears to have been fixed, the application can try to invoke the operation.

# State Machine
The Circuit Breaker pattern is often implemented by a state machine with three states,
*Closed*, *Open* and *Half Open*

```
                           ┌────────────────┐                          
                           │                │                          
                           │ Initialization │                          
                           │                │                          
                           │                │                          
                           └────────────────┘                          
                                    │                                  
                                    │                                  
                                    ▼                                  
                         ┌────────────────────┐                        
                         │                    │                        
                         │                    │                        
        Success          │       Closed       │        Failure         
       Threshold ───────▶│    (Allow All)     │───────Threshold        
        Reached          │                    │        Reached         
           │             │                    │             │          
           │             │                    │             │          
           │             └────────────────────┘             │          
           │                                                │          
           │                                                │          
           │                                                ▼          
┌────────────────────┐                           ┌────────────────────┐
│                    │                           │                    │
│                    │                           │                    │
│     Half-Open      │       Backoff             │        Open        │
│    (Allow Some)    │◀──────Expired─────────────│     (Deny All)     │
│                    │                           │                    │
│                    │                           │                    │
│                    │                           │                    │
└────────────────────┘                           └────────────────────┘
           │                                                ▲          
           │                                                │          
           └─────────────────Failures───────────────────────┘          
```

## Closed
The request from the application is routed to the operation. The circuit breaker
maintains a count of the number of recent successes and failures and increments
them based on the respective outcome of the operation.

If the number of recent failures exceeds a specified threshold or rate, the circuit is
triggered and is placed into the Open State.

## Open
The request from the application fails immediately and an error is returned to the application.
 At this point, the circuit breaker calculates an exponentionally increasing backoff (by default)
timeout timer. When this timer expires, the circuit breaker is placed into the Half-Open state.

> The purpose of this timeout is allow the operation to fix the problem, whatever it maybe.
After all, time heals all wounds.


## Half Open
A limited number of requests from the application are allowed to pass through and invoke the operation.
If these requests are successful, it's assumed that the fault that was previously causing the
failure has been fixed and the circuit breaker switches to the Closed state (the failure counter is reset).
If any request fails, the circuit breaker assumes that the fault is still present
so it reverts back to the Open state and continues the backoff.

# Generations

We mark state changes with a generation number and maintain that through the request
life-cycle. This is done to prevent successful requests that were issued before
the circuit was tripped to be used to reset the circuit or vice-versa.

In this contrived example, we consider the following requests A, B and Breaker options
with a low trip threshold (one failed request), low reset treshold (one successful request)
and a low backoff duration.

```
(Time increases ->)

    Req A───────Rec'd By ───────────────────Server ───────────────────────Response    
                 Server                   Doing Work                       Rev'd      
                                                                            200       
          Req B────────Rec'd by ────Rejected ─────Response                            
                        Server     by Server       Rec'd                              
                                                    429                               
                                                                                      
 Circuit ──────────────────────────────────────────Circuit ─────Circuit──────Circuit  
  Closed                                             Open      Half Open   **Remains Half Open***
```

Above, Req A is issued before Req B but Req A receives it's response _well after_
Req B. While Req A is outstanding, the circuit breaker is tripped to Open, then to
Half-Open. When Req A gets a successful response, that response should not be eligible
to reset the circuit, since it originated before the circuit trip occurred.

We accomplish this by giving each request a generation number of when the request was
made and increase that generation number each time the circuit state changes.

So in the example above, both req A and B would be in generation 0. The circuit then trips
into the Open state, and the genration number is incremented to 1. The state then advances
to the Half Open state, and the generation number is incremented to 2. When req A response is received,
it's generation number is compared to the current generation number, 0 to 2 respectively.
Since they are not equal, we discard the request as being an elible statistic for the state machine.
