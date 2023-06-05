#include "merkle.mligo"

let test =
    let felt : nat = 2915689030n in
    let auth : bytes list = [
        0x7df684aedf82b8c82d917b4478d6286a0eeadce71e6631989c116f54a5a04364 ;
        0x97a9e1f7d545dc7d71893f4128b64c98a6dd5f3364d748cec2430cb575df2c2a ;
        0x5d860ee4ec8d7ce9c229c3fcd6aefe4aa8ad7ba3449607cefeb77b13c6358106 ;
        0xd1ad91883aa7458eda55146c74c8b8052a5b99acf8cec14ec7339cf86f050c1a ;
        0x4340668c64a5ef413649583fad31f4cc4340556bf84c3141839652b3205597a3 ;
        0xde3c030814f68bcb8c81645140fec0db12f44ab2d76dc59fbf4de37aeaf37fff ;
        0x5ddbaae5b236ff9ee820c5a3c41a0135ff19b70bcaac15ef79bee1fbd9647251 ;
        0xbe426a44a7e746a080cf0236a6b621401abfe6d5c2ebad3c4031e2e1b9f49ed5 ;
        0xaf24050a4f278e4540d5992832a3a9389d1a2f9a73bbc7a2a4a92f5bda02e671 ;
        0x85dfba1e44c4567e570e17c6f69e6cd3465aaaa24ba919c5e4803bbc2ecafac1 ;
        0x6216f1400e1cfc2e747c3391fa8575f98dffae5e533cf3bfe13096cd407c2241 ;
        0x96d8d725074e0127bf9111800eb0ff5a23c3552ad2705fc23b0b4f790343e12c ;
        0x5870e2a3a3e1eda5fd4c6f19333d853bf58feffd41ee3577e805d5aaa6fad8f5
    ] in
    let idx : nat = 365n in
    let root : bytes = 0xe7090678303730d51aee399664256de5f6476ec86fb4d45fbf0556535fb09f48 in
    let () = Merkle.verify_decommitment ((felt, auth), idx, root) in
    ()
