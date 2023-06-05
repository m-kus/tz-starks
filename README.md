# STARK101 on Tezos

This is a PoC implementation of a STARK verifier for the Fibonacci-Square sequence calculation proof.  
The original proved statement and prover code taken from the [STARK101](https://github.com/starkware-industries/stark101) repository by StarkWare.

### Implementation notes

* A flat list of byte strings is used for the channel queue (it might be beneficial to use structured data)
* Merkle proofs are serialized in the reversed order (to simplify verification)
* Channel state is initialized with an empty byte string `0x` (a hash of some public input should be used)
* Single random query is sampled (should be multiple)
* Some values that do not depend on the channel state are pre-calculated and hardcoded in the contract code

### Deployment

The verifier contract is deployed in [Ghostnet](https://better-call.dev/ghostnet/KT1QvgguUftZsJ82Wy2LZ6tfgTzBGkNrk2bx/operations):
* Allocated storage: 3663 bytes (~1 tez)
* Verifier gas consumption (single query): 4256 (~0.01 tez) 

### Videos

* STARK101 tutorial https://starkware.co/stark-101/
* Basecamp STARK math https://www.youtube.com/watch?v=jg9KSNOO2XY