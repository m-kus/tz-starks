#include "channel.mligo"

let test_decommitment =
    let queue : Channel.t_queue = [ FieldElement 42n ; MerkleProof [0xdeadbeef] ] in
    let ((felt, auth), queue) : (nat * bytes list) * Channel.t_queue = Channel.read_decommitment (queue) in
    if felt <> 42n || (List.length auth) <> 1n || (List.length queue <> 0n)
        then failwith ("Invalid decommitment", felt, auth, queue)
        else ()
