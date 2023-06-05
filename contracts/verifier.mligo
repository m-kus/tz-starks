#include "channel.mligo"
#include "field.mligo"

// Pre-calculated values
let num_fri_layers : int = 11  // log2(1024) + 1 
let domain_ex_size : nat = 8192n
// let mult_sub_gen : nat = 1855261384n  // field_gen ^ (3 * 2^30 / 1024)
let coset_gen : nat = 1734477367n  // field_gen ^ (3 * 2^30 / 8192))
let mult_sub_1021 : nat = 2342081930n
let mult_sub_1022 : nat = 2450347685n
let mult_sub_1023 : nat = 532203874n
let fib_sq_1022 : nat = 2338775057n

type fri_commit = bytes * nat  // (merkle root, beta)
type nat3 = nat * nat * nat
// FRI accumulator = (queue, leaf idx, x elt, composition poly eval, domain size)
type fri_acc = Channel.t_queue * nat * nat * nat * nat

let rec read_cp_alpha (state: bytes) : nat3 * bytes =
    let (alpha0, state) : nat * bytes = Channel.send_random_felt state in
    let (alpha1, state) : nat * bytes = Channel.send_random_felt state in
    let (alpha2, state) : nat * bytes = Channel.send_random_felt state in
    (alpha0, alpha1, alpha2), state

let rec read_fri_commitments ((state, queue), count, commitments: Channel.t * int * fri_commit list) : fri_commit list * Channel.t =
    let (cp_mt_root, (state, queue)) : bytes * Channel.t = Channel.read_hash (state, queue) in
    let (cp_beta, (state, queue)) : nat * Channel.t = if count > 1
        then
            let (beta, state) : nat * bytes = Channel.send_random_felt state in
            beta, (state, queue)
        else Channel.read_felt (state, queue)  // last fri polynomial free term
    in
    let commitments = (cp_mt_root, cp_beta) :: commitments in
    if count = 1
        then commitments, (state, queue)
        else read_fri_commitments ((state, queue), count - 1, commitments)

let rec read_decommitment (queue, hash, path: Channel.t_queue * bytes * nat) : bytes * Channel.t_queue =
    let (sis, queue) : bytes * Channel.t_queue = Channel.read_hash_pure queue in
    let payload = if 0n = Bitwise.and path 1n
        then Bytes.concat hash sis
        else Bytes.concat sis hash
    in
    let hash : bytes = Crypto.sha256 payload in
    let path : nat = Bitwise.shift_right path 1n in
    if path = 1n
        then hash, queue
        else read_decommitment (queue, hash, path)

let read_verify_felt (queue, idx, domain_size, mt_root: Channel.t_queue * nat * nat * bytes) : nat * Channel.t_queue =
    let (felt, queue) : nat * Channel.t_queue = Channel.read_felt_pure queue in
    let hash : bytes = Crypto.sha256 (bytes felt) in
    let (auth_root, queue) : bytes * Channel.t_queue = read_decommitment (queue, hash, domain_size + idx) in
    if auth_root <> mt_root
        then failwith ("MERKLE_ROOT_MISMATCH", mt_root, auth_root)
        else felt, queue

let read_verify_p_eval (queue, idx, mt_root: Channel.t_queue * nat * bytes) : nat3 * Channel.t_queue =
    let (f_x, queue) : nat * Channel.t_queue = read_verify_felt (queue, idx, domain_ex_size, mt_root) in
    let (f_gx, queue) : nat * Channel.t_queue = read_verify_felt (queue, idx + 8n, domain_ex_size, mt_root) in
    let (f_ggx, queue) : nat * Channel.t_queue = read_verify_felt (queue, idx + 16n, domain_ex_size, mt_root) in
    (f_x, f_gx, f_ggx), queue

let calc_x_cp0 (idx, (a0, a1, a2), (f_x, f_gx, f_ggx): nat * nat3 * nat3) : nat * nat =
    let x : nat = Field.mul (Field.generator, Field.pow (coset_gen, idx)) in
    let p0 : nat = Field.div (Field.sub (f_x, 1n), Field.sub (x, 1n)) in
    let p1 : nat = Field.div (Field.sub (f_x, fib_sq_1022), Field.sub (x, mult_sub_1022)) in
    let p2_num0 : nat = Field.sub (Field.sub (f_ggx, Field.mul (f_gx, f_gx)), Field.mul (f_x, f_x)) in
    let p2_num1 : nat = Field.mul (Field.sub (x, mult_sub_1021), Field.sub (x, mult_sub_1022)) in
    let p2_num : nat = Field.mul (p2_num0, Field.mul (p2_num1, Field.sub (x, mult_sub_1023))) in
    let p2 : nat = Field.div (p2_num, Field.sub (Field.pow (x, 1024n), 1n)) in
    let cp0 : nat = Field.add (Field.mul (a0, p0), Field.add (Field.mul (a1, p1), Field.mul (a2, p2))) in
    x, cp0

let read_verify_fri_layer (queue, idx, domain_size, mt_root: Channel.t_queue * nat * nat * bytes) : (nat * nat) * Channel.t_queue =
    let fri_idx : nat = idx mod domain_size in
    let (cp, queue): nat * Channel.t_queue = read_verify_felt (queue, fri_idx, domain_size, mt_root) in
    let sib_idx : nat = (idx + domain_size / 2n) mod domain_size in
    let (cp_sib, queue): nat * Channel.t_queue = read_verify_felt (queue, sib_idx, domain_size, mt_root) in
    (cp, cp_sib), queue

let calc_next_fri_cp (cpa, cpb, x, beta: nat * nat * nat * nat) : nat =
    let op1 : nat = Field.div (Field.add (cpa, cpb), 2n) in
    let op2 : nat = Field.div (Field.sub (cpa, cpb), Field.mul (2n, x)) in
    Field.add (op1, Field.mul (beta, op2))

let verify_fri (queue, idx, x0, cp0, commitments: Channel.t_queue * nat * nat * nat * fri_commit list) : Channel.t_queue =
    // Note that FRI commitments are in the reversed order, so folding right
    let init : fri_acc = (queue, idx, x0, cp0, domain_ex_size) in
    let (queue, _, _, _, _) : fri_acc = List.fold_right
        (fun ((mt_root, beta), (queue, idx, x, cp, domain_size): fri_commit * fri_acc) ->
            if domain_size = 8n  // 8192 / 1024
                then
                    let (cp_last, queue): nat * Channel.t_queue = Channel.read_felt_pure queue in
                    let () = assert_with_error (cp = cp_last) "FRI_INVALID_CP_EVAL_LAST" in
                    queue, 0n, 0n, 0n, 0n 
                else
                    let ((cpa, cpb), queue): (nat * nat) * Channel.t_queue = read_verify_fri_layer (queue, idx, domain_size, mt_root) in
                    let () = assert_with_error (cp = cpa) "FRI_INVALID_CP_EVAL" in
                    let cp_next : nat = calc_next_fri_cp (cpa, cpb, x, beta) in
                    queue, idx, Field.mul (x, x), cp_next, (Bitwise.shift_right domain_size 1n)
        )
        commitments
        init
    in
    queue

let verify (queue : Channel.t_queue) =
    // Merkle root of the trace polynomial evaluation on extended domain
    let (p_mt_root, (state, queue)) : bytes * Channel.t = Channel.read_hash (0x, queue) in
    // Composition polynomial coefficients
    let (cp_alpha, state) : nat3 * bytes = read_cp_alpha (state) in
    // FRI commitments include beta coefficients and merkle roots of CP_i evaluation on the according FRI domain
    let (fri_commitments, (state, queue)) : fri_commit list * Channel.t = read_fri_commitments ((state, queue), num_fri_layers, []) in
    // Random query (should be multiple queries)
    let (idx, _) : nat * bytes = Channel.send_random_nat (state, domain_ex_size) in
    // Evaluate trace polynomial in specified points
    let (p_eval, queue) : nat3 * Channel.t_queue = read_verify_p_eval (queue, idx, p_mt_root) in
    // Reconstruct composition polynomial
    let (x, cp0): nat * nat = calc_x_cp0 (idx, cp_alpha, p_eval) in
    // Verify FRI layers
    let queue : Channel.t_queue = verify_fri (queue, idx, x, cp0, fri_commitments) in
    let () = assert_with_error (0n = List.length queue) "CHANNEL_QUEUE_NOT_EMPTY" in
    ()
