# FlexAEAD cryptanalysis

This repository contains code from the following paper:

> *Practical Key Recovery Attacks on FlexAEAD*  
> Orr Dunkelman, Maria Eichlseder, Daniel Kales, Nathan Keller, Gaëtan Leurent, Markus Schofnegger  
> Designs, Codes and Cryptography

There are two different attacks included:

1. The directory `key_recovery` contains a key-recovery attack against
   FlexAEAD-64 with an expected complexity 2^30 (Section 4.1 of the paper).

2. The directory `key_recovery_alt` contains an alternative attack
   against FlexAEAD-64, with an expected complexity of 2^48 (Section
   6.1 of the paper).  This variant can also be used against FlexAEAD's
   predecessor, FlexAE.

The implementation of the attacks uses the reference implementation
of FlexAEAD submitted to NIST.  As explained in the paper (Section 4.2),
it does not match the description given in the specification, but our
techniques apply similarly to both versions.

The Makefile should be sufficient to compile the code (just run `make`).
If you use an old version of `gcc`, you might need to add `-std=c++11` into `CXXFLAGS`.

The main attack should run in a few minutes using 12GB of memory.

The alternative attack uses the [STXXL](http://stxxl.org/) library,
and requires a large temporary space to store an 8TB file.
You can change the location of the temporary file using the `DIR` constant.
STXXL is availble in Debian-based distributions (`apt install libstxxl-dev`),
but you should also [configure](http://stxxl.org/tags/master/install_config.html)
it to use a disk with a large space available.
