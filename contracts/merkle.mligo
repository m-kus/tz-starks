module Merkle = struct
    // accumulator = (current_hash, current_path)
    type auth_acc = bytes * nat

    let verify_decommitment ((felt, auth), leaf_idx, root : (nat * bytes list) * nat * bytes) =
        let num_leaves : nat = Bitwise.shift_left 1n (List.length auth) in
        let init : auth_acc = (Crypto.sha256 (bytes felt)), (num_leaves + leaf_idx) in
        let (res_root, res_path) : auth_acc = List.fold_right
            (fun (sis, (hash, path): bytes * auth_acc) ->            
                let payload = if 0n = Bitwise.and path 1n
                    then Bytes.concat hash sis
                    else Bytes.concat sis hash
                in
                (Crypto.sha256 payload), (Bitwise.shift_right path 1n)
            )
            auth
            init
        in
        let () = assert_with_error (res_root = root) "MERKLE_ROOT_MISMATCH" in
        let () = assert_with_error (res_path = 1n) "MERKLE_UNEXPECTED_PATH" in
        ()
end
