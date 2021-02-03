:- use_module(library(clpfd)).

% Basic bounds enforced on kernel-provided variables due to their intrinsic storage size (see struct seccomp_data definition)
valid(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) :-
    Nr #>= 0, Nr #=< 0xffffffff,
    Arch #>= 0, Arch #=< 0xffffffff,
    Rip #>= 0, Rip #=< 0xffffffffffffffff,
    Arg1 #>= 0, Arg1 #=< 0xffffffffffffffff,
    Arg2 #>= 0, Arg2 #=< 0xffffffffffffffff,
    Arg3 #>= 0, Arg3 #=< 0xffffffffffffffff,
    Arg4 #>= 0, Arg4 #=< 0xffffffffffffffff,
    Arg5 #>= 0, Arg5 #=< 0xffffffffffffffff,
    Arg6 #>= 0, Arg6 #=< 0xffffffffffffffff.

% 16 memory slots can be read using an index in the [0;15] range
read_mem(M0, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 0, M0).
read_mem(_, M1, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 1, M1).
read_mem(_, _, M2, _, _, _, _, _, _, _, _, _, _, _, _, _, 2, M2).
read_mem(_, _, _, M3, _, _, _, _, _, _, _, _, _, _, _, _, 3, M3).
read_mem(_, _, _, _, M4, _, _, _, _, _, _, _, _, _, _, _, 4, M4).
read_mem(_, _, _, _, _, M5, _, _, _, _, _, _, _, _, _, _, 5, M5).
read_mem(_, _, _, _, _, _, M6, _, _, _, _, _, _, _, _, _, 6, M6).
read_mem(_, _, _, _, _, _, _, M7, _, _, _, _, _, _, _, _, 7, M7).
read_mem(_, _, _, _, _, _, _, _, M8, _, _, _, _, _, _, _, 8, M8).
read_mem(_, _, _, _, _, _, _, _, _, M9, _, _, _, _, _, _, 9, M9).
read_mem(_, _, _, _, _, _, _, _, _, _, M10, _, _, _, _, _, 10, M10).
read_mem(_, _, _, _, _, _, _, _, _, _, _, M11, _, _, _, _, 11, M11).
read_mem(_, _, _, _, _, _, _, _, _, _, _, _, M12, _, _, _, 12, M12).
read_mem(_, _, _, _, _, _, _, _, _, _, _, _, _, M13, _, _, 13, M13).
read_mem(_, _, _, _, _, _, _, _, _, _, _, _, _, _, M14, _, 14, M14).
read_mem(_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, M15, 15, M15).

% The same 16 memory slots can be written to, which preserves all slots except the one indexed
write_mem(_, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, NewVal, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 0, NewVal).
write_mem(M0, _, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, NewVal, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 1, NewVal).
write_mem(M0, M1, _, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, NewVal, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 2, NewVal).
write_mem(M0, M1, M2, _, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, NewVal, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 3, NewVal).
write_mem(M0, M1, M2, M3, _, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, NewVal, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 4, NewVal).
write_mem(M0, M1, M2, M3, M4, _, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, NewVal, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, 5, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, _, M7, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, NewVal, M7, M8, M9, M10, M11, M12, M13, M14, M15, 6, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, _, M8, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, NewVal, M8, M9, M10, M11, M12, M13, M14, M15, 7, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, _, M9, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, NewVal, M9, M10, M11, M12, M13, M14, M15, 8, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, _, M10, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, NewVal, M10, M11, M12, M13, M14, M15, 9, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, _, M11, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, NewVal, M11, M12, M13, M14, M15, 10, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, _, M12, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, NewVal, M12, M13, M14, M15, 11, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, _, M13, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, NewVal, M13, M14, M15, 12, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, _, M14, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, NewVal, M14, M15, 13, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, _, M15, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, NewVal, M15, 14, NewVal).
write_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, _, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, NewVal, 15, NewVal).

% Reading from the struct seccomp_data (reads must be 4-byte aligned)
raw_read_w(Nr, _, _, _, _, _, _, _, _, 0, Nr).
raw_read_w(_, Arch, _, _, _, _, _, _, _, 4, Arch).
raw_read_w(_, _, RIP, _, _, _, _, _, _, 8, ReadResult) :- ReadResult #= RIP /\ 0xFFFFFFFF.
raw_read_w(_, _, RIP, _, _, _, _, _, _, 12, ReadResult) :- HighPart #= RIP /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, Arg1, _, _, _, _, _, 16, ReadResult) :- ReadResult #= Arg1 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, Arg1, _, _, _, _, _, 20, ReadResult) :- HighPart #= Arg1 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, _, Arg2, _, _, _, _, 24, ReadResult) :- ReadResult #= Arg2 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, _, Arg2, _, _, _, _, 28, ReadResult) :- HighPart #= Arg2 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, _, _, Arg3, _, _, _, 32, ReadResult) :- ReadResult #= Arg3 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, _, _, Arg3, _, _, _, 36, ReadResult) :- HighPart #= Arg3 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, _, _, _, Arg4, _, _, 40, ReadResult) :- ReadResult #= Arg4 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, _, _, _, Arg4, _, _, 44, ReadResult) :- HighPart #= Arg4 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, _, _, _, _, Arg5, _, 48, ReadResult) :- ReadResult #= Arg5 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, _, _, _, _, Arg5, _, 52, ReadResult) :- HighPart #= Arg5 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.
raw_read_w(_, _, _, _, _, _, _, _, Arg6, 56, ReadResult) :- ReadResult #= Arg6 /\ 0xFFFFFFFF.
raw_read_w(_, _, _, _, _, _, _, _, Arg6, 60, ReadResult) :- HighPart #= Arg6 /\ 0xFFFFFFFF00000000, ReadResult #= HighPart >> 32.

% One-instruction sized paths
path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
    Ninit, Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
    Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f) :-
        transition_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
            Ninit,  Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
            Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f).
% Generalize paths to any length without jumps or with a jump not taken
path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
    Ninit, Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
    Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f) :-
        Nnext #= Ninit + 1,
        Nnext #< Nfinal,
        transition_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
            Ninit, Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
            Nnext, An, Xn, M0n, M1n, M2n, M3n, M4n, M5n, M6n, M7n, M8n, M9n, M10n, M11n, M12n, M13n, M14n, M15n),
        path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
            Nnext, An, Xn, M0n, M1n, M2n, M3n, M4n, M5n, M6n, M7n, M8n, M9n, M10n, M11n, M12n, M13n, M14n, M15n,
            Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f).
% Generalize to paths of any length starting with a jump taken
path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
    Ninit, Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
    Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f) :-
        Nnext #>= Ninit+2,
        Nnext #< Nfinal,
        transition_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
            Ninit, Ai, Xi, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
            Nnext, An, Xn, M0n, M1n, M2n, M3n, M4n, M5n, M6n, M7n, M8n, M9n, M10n, M11n, M12n, M13n, M14n, M15n),
        path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
            Nnext, An, Xn, M0n, M1n, M2n, M3n, M4n, M5n, M6n, M7n, M8n, M9n, M10n, M11n, M12n, M13n, M14n, M15n,
            Nfinal, Af, Xf, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f).

% Actual BPF operations (one-step paths)
% (see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/seccomp.c)

% BPF_LD | BPF_W | BPF_ABS
transition_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, ReadResult, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ld_w_abs, _, _, K),
    Nnextstep #= Nstep + 1,
    raw_read_w(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, K, ReadResult).

% BPF_LD | BPF_W | BPF_LEN
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, 64, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ld_w_len, _, _, _),
    Nnextstep #= Nstep + 1.

% BPF_LD | BPF_W | BPF_MEM
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, ReadResult, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ld_mem, _, _, K),
    Nnextstep #= Nstep + 1,
    read_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, K, ReadResult).

% BPF_LDX | BPF_W | BPF_MEM
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, _, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, ReadResult, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ldx_mem, _, _, K),
    Nnextstep #= Nstep + 1,
    read_mem(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, K, ReadResult).

% BPF_LDX | BPF_W | BPF_LEN
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, _, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, 64, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ldx_w_len, _, _, _),
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_ADD | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_add_k, _, _, K),
    Anext #= (A + K) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_ADD | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_add_x, _, _, _),
    Anext #= (A + X) mod 4294967296 ,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_SUB | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_sub_k, _, _, K),
    Anext #= (A - K) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_SUB | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_sub_x, _, _, _),
    Anext #= (A - X) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_MUL | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_mul_k, _, _, K),
    Anext #= (A * K) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_MUL | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_mul_x, _, _, _),
    Anext #= (A * X) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_DIV | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_div_k, _, _, K),
    Anext #= A / K,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_DIV | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_div_x, _, _, _),
    Anext #= A / X,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_AND | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_and_k, _, _, K),
    Anext #= A /\ K,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_AND | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_and_x, _, _, _),
    Anext #= A /\ X,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_OR | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_or_k, _, _, K),
    Anext #= A \/ K,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_OR | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_or_x, _, _, _),
    Anext #= A \/ X,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_XOR | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_xor_k, _, _, K),
    Anext #= A xor K,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_XOR | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_xor_x, _, _, _),
    Anext #= A xor X,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_LSH | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_lsh_k, _, _, K),
    Anext #= (A << K) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_LSH | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_lsh_x, _, _, _),
    Anext #= (A << X) mod 4294967296,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_RSH | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_rsh_k, _, _, K),
    Anext #= A >> K,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_RSH | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_rsh_x, _, _, _),
    Anext #= A >> X,
    Nnextstep #= Nstep + 1.

% BPF_ALU | BPF_NEG
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_alu_neg, _, _, _),
    Anext #= \ A,
    Nnextstep #= Nstep + 1.

% BPF_LD | BPF_IMM
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ld_imm, _, _, K),
    Anext #= K,
    Nnextstep #= Nstep + 1.

% BPF_LDX | BPF_IMM
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_ldx_imm, _, _, _),
    Anext #= X,
    Nnextstep #= Nstep + 1.

% BPF_MISC | BPF_TAX
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, _, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, Xnext, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_misc_tax, _, _, _),
    Xnext #= A,
    Nnextstep #= Nstep + 1.

% BPF_MISC | BPF_TXA
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, _, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, Anext, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_misc_tax, _, _, _),
    Anext #= X,
    Nnextstep #= Nstep + 1.

% BPF_ST
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
    Nnextstep, A, X, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f) :-
    bpf_op(Nstep, bpf_st, _, _, K),
    Nnextstep #= Nstep + 1,
    write_mem(M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
        M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f,
        K, A).

% BPF_STX
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
    Nnextstep, A, X, M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f) :-
    bpf_op(Nstep, bpf_stx, _, _, K),
    Nnextstep #= Nstep + 1,
    write_mem(M0i, M1i, M2i, M3i, M4i, M5i, M6i, M7i, M8i, M9i, M10i, M11i, M12i, M13i, M14i, M15i,
        M0f, M1f, M2f, M3f, M4f, M5f, M6f, M7f, M8f, M9f, M10f, M11f, M12f, M13f, M14f, M15f,
        K, X).

% BPF_JMP | BPF_JA
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_ja, _, _, K),
    Nnextstep #= Nstep + K + 1.

% BPF_JMP | BPF_JEQ | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep,     A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jeq_k, Jt, _, K),
    A #= K,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep,     A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jeq_k, _, Jf, K),
    A #\= K,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JEQ | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jeq_x, Jt, _, _),
    A #= X,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jeq_x, _, Jf, _),
    A #\= X,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JGE | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jge_k, Jt, _, K),
    A #>= K,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jge_k, _, Jf, K),
    A #< K,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JGE | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jge_k, Jt, _, _),
    A #>= X,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jge_k, _, Jf, _),
    A #< X,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JGT | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jgt_k, Jt, _, K),
    A #> K,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jgt_k, _, Jf, K),
    A #=< K,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JGT | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jgt_x, Jt, _, _),
    A #> X, Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jgt_x, _, Jf, _),
    A #=< X,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JSET | BPF_K
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jset_k, Jt, _, K),
    A /\ K #\= 0,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jset_k, _, Jf, K),
    A /\ K #= 0,
    Nnextstep #= Nstep + Jf + 1.

% BPF_JMP | BPF_JSET | BPF_X
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jset_x, Jt, _, _),
    A /\ X #\= 0,
    Nnextstep #= Nstep + Jt + 1.
transition_exists(_, _, _, _, _, _, _, _, _,
    Nstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15,
    Nnextstep, A, X, M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15) :-
    bpf_op(Nstep, bpf_jmp_jset_x, _, Jf, _),
    A /\ X #= 0,
    Nnextstep #= Nstep + Jf + 1.

% Define all possible accepting final operations (the states we want to go to)
step_accepts(Nstep, _) :- bpf_op(Nstep, bpf_ret_k, _, _, 0x7fff0000). % SECCOMP_RET_ALLOW
step_accepts(Nstep, A) :- bpf_op(Nstep, bpf_ret_a, _, _, _), A #= 0x7fff0000.
step_accepts(Nstep, _) :- bpf_op(Nstep, bpf_ret_k, _, _, 0x7ffc0000). % SECCOMP_RET_LOG
step_accepts(Nstep, A) :- bpf_op(Nstep, bpf_ret_a, _, _, _), A #= 0x7ffc0000.

% Accepting paths are paths that leads to a final state
filter_accepts(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) :-
    valid(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6),
    step_accepts(Nfinal, A),
    path_exists(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6,
        0,      _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _,
        Nfinal, A, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _).
% Or paths that just begin in a final state (e.g. first and only instruction is a return allow)
filter_accepts(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) :-
    valid(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6),
    step_accepts(0, _).

%bpf_op(0, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_jmp_ja, 0, 0, 1).
%bpf_op(2, bpf_ret_k, 0, 0, 0).
%bpf_op(3, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_jmp_jeq_k, 4, 0, 4).
%bpf_op(2, bpf_jmp_jeq_k, 3, 0, 8).
%bpf_op(3, bpf_jmp_jeq_k, 2, 0, 15).
%bpf_op(4, bpf_jmp_jeq_k, 1, 0, 16).
%bpf_op(5, bpf_ret_k, 0, 0, 0).
%bpf_op(6, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_st, 0, 0, 7).
%bpf_op(2, bpf_ld_w_abs, 0, 0, 4).
%bpf_op(3, bpf_ld_mem, 0, 0, 7).
%bpf_op(4, bpf_jmp_jeq_k, 4, 0, 4).
%bpf_op(5, bpf_jmp_jeq_k, 3, 0, 8).
%bpf_op(6, bpf_jmp_jeq_k, 2, 0, 15).
%bpf_op(7, bpf_jmp_jeq_k, 1, 0, 16).
%bpf_op(8, bpf_ret_k, 0, 0, 0).
%bpf_op(9, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_jmp_jeq_k, 1, 0, 13).
%bpf_op(2, bpf_jmp_jeq_k, 0, 99, 12).
%bpf_op(3, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_alu_add_k, 0, 0, 1).
%bpf_op(2, bpf_jmp_jeq_k, 0, 99, 12).
%bpf_op(3, bpf_ret_k, 0, 0, 0x7fff0000).

%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_alu_add_k, 0, 0, 1).
%bpf_op(2, bpf_jmp_jeq_k, 1, 0, 16).
%bpf_op(3, bpf_ret_k, 0, 0, 0).
%bpf_op(4, bpf_ret_k, 0, 0, 0x7fff0000).

% Modular arithmetics is hard...
%bpf_op(0, bpf_ld_w_abs, 0, 0, 0).
%bpf_op(1, bpf_alu_add_k, 0, 0, 42).
%bpf_op(2, bpf_ret_k, 0, 0, 0x7fff0000).
