#include "verifier.mligo"

type storage = unit

type parameter = 
    Verify of bytes list

let main (action, store : parameter * storage) : operation list * storage =
    ([] : operation list),
    (match action with
        Verify (proof) -> verify proof)
 