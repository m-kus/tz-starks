module Field = struct
    let k_modulus : nat = 3221225473n  // 3 * 2^30 + 1
    let generator : nat = 5n

    let add (lhs, rhs: nat * nat) : nat = 
        (lhs + rhs) mod k_modulus

    let sub (lhs, rhs: nat * nat) : nat =
        if rhs > lhs
            then abs ((lhs + k_modulus) - rhs)
            else abs (lhs - rhs)

    let mul (lhs, rhs: nat * nat) : nat =
        (lhs * rhs) mod k_modulus

    let rec ee_step (t, r, new_t, new_r: int * int * int * int) : int * int * int * int =
        if new_r <> 0
            then
                let q : int = r / new_r in
                let (t, new_t) : int * int = (new_t, t - q * new_t) in
                let (r, new_r) : int * int = (new_r, r - q * new_r) in
                ee_step (t, r, new_t, new_r)
            else
                t, r, new_t, new_r

    let div (lhs, rhs: nat * nat) : nat =
        let (t, r, _, _) : int * int * int * int = ee_step (0, (int k_modulus), 1, (int rhs)) in
        let () = assert_with_error (r = 1) "FELT_NOT_INVERTIBLE" in
        let rhs_inv : nat = if t < 0
            then abs (t + k_modulus)
            else abs (t)
        in
        mul (lhs, rhs_inv)

    let rec pow (lhs, rhs: nat * nat) : nat =
        if rhs = 0n
            then 1n
            else
                let squared : nat = pow (mul (lhs, lhs), Bitwise.shift_right rhs 1n) in
                if rhs mod 2n = 0n
                    then squared
                    else mul (lhs, squared)
end 
