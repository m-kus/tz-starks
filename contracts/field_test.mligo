#include "field.mligo"

let test_zero_elt =
    let f0 : nat = Field.add (Field.mul (3n, Field.pow (2n, 30n)), 1n) in
    if f0 <> 0n
        then failwith ("Expected 0", f0)
        else ()

let test_division =
    let (a, b) : nat * nat = (124245436n, 980943291n) in
    let q : nat = Field.div (a, b) in
    if Field.mul (q, b) <> a
        then failwith ("Expected to be equal", a, b, q)
        else ()
