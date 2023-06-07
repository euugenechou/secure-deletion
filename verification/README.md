## Verification & Modeling Utilities

This directory contains work on modeling the Holepunch system and specifying properties to verify against it.

### Spin

The Spin model checker can verify multi-threaded software with the models defined in Promela.
Properties in Spin are in LTL. Using LTL, we can encode properties about the future states on paths.

**LTL Syntax**
TODO: not sure if I'll include a description of this yet.

### NuXmv

NuXmv is a model checker based on BDDs. Properties are specified in LTL or CTL which is a branching-time logic.
Typical properties to define in CTL are _safety_ and _liveness_.

**CTL Syntax**
TODO: not sure if I"ll include a description of this yet.


