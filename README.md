# seccomp-prolog

A simple seccomp BPF filter verifier written in Prolog. Who doesn't love Prolog?

I will push the filter dump source code as soon as it is  enough.

## Usage

To use this analyzer, you need SWI-Prolog. You then need to `git clone` this repository, and load a filter along the lines of:

	$ swipl ./seccomp.pl
	?- [my_dumped_filter].

You can then start querying whether particular syscalls are allowed, and if so with which arguments:

	?- filter_accepts(175, 3221225534, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6).
	false.

That previous query basically asked "are there any arguments I can use to call `init_module()` on an `x86_64` architecture? (and thankfully the answer was no.)

You can also decide to exhaustively list all syscalls allowed in any way:

	?- filter_accepts(Nr, Arch, Rip, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6), write('Nr='), write(Nr), write(' Arch='), write(Arch), write('\n'), fail.
	Nr=66 Arch=1073741827
	Nr=70 Arch=1073741827
	Nr=71 Arch=1073741827
	Nr=75 Arch=1073741827
	Nr=76 Arch=1073741827
	Nr=77 Arch=1073741827
	[...]

## Future work

This project is a proof of concept. It still needs to support syscall and architecture number resolution, and simpler predicates to query.

I plan to integrate it into a larger project, integrating seccomp filters in a "you don't have to apt install Prolog" into a much larger framework including capabilities and other isolation mechanisms.
