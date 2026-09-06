+++
title = "Cookbook"
description = "Compiled, runnable recipes for dlms-cosem-rs: read a register, open a ciphered association, decrypt a push, read a load profile, host a meter, parse a P1 telegram."
weight = 20

[extra]
include = "includes/cookbook.md"
+++

Short answers to the things people actually want to do.

**Every snippet on this page is a doctest.** It is compiled — and, where it does not need
a socket, run — as part of the crate's test suite, so a recipe that stops working fails the
build rather than quietly misleading somebody. That is the reason this page and the crate
documentation cannot disagree: they are the same file.
