#include "field.mligo"

module Channel = struct
    type t_queue = bytes list
    type t = bytes * t_queue

    let read_hash (state, queue: t) : bytes * t = 
        match queue with
            | (hash :: tail) -> 
                if 32n <> Bytes.length hash
                    then failwith ("CHANNEL_INVALID_HASH", hash)
                    else hash, (Crypto.sha256 (Bytes.concat state hash), tail)
            | _ -> failwith "CHANNEL_QUEUE_EMPTY"

    let read_felt (state, queue: t) : nat * t =
        match queue with
            | (data :: tail) ->
                let felt : nat = nat data in
                if felt >= Field.k_modulus
                    then failwith ("CHANNEL_INVALID_FELT", data)
                    else felt, (Crypto.sha256 (Bytes.concat state data), tail)
            | _ -> failwith "CHANNEL_QUEUE_EMPTY"

    let read_hash_pure (queue: t_queue) : bytes * t_queue = 
        match queue with
            | (hash :: tail) -> 
                if 32n <> Bytes.length hash
                    then failwith ("CHANNEL_INVALID_HASH", hash)
                    else hash, tail
            | _ -> failwith "CHANNEL_QUEUE_EMPTY"

    let read_felt_pure (queue: t_queue) : nat * t_queue =
        match queue with
            | (data :: tail) ->
                let felt : nat = nat data in
                if felt >= Field.k_modulus
                    then failwith ("CHANNEL_INVALID_FELT", data)
                    else felt, tail
            | _ -> failwith "CHANNEL_QUEUE_EMPTY"

    let send_random_nat (state, upper_bound: bytes * nat) : nat * bytes =
        (nat state) mod (upper_bound + 1n), Crypto.sha256 state

    let send_random_felt (state: bytes) : nat * bytes =
        send_random_nat (state, abs (Field.k_modulus - 1n))
end
