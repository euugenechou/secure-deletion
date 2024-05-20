# Secure Deletion from Puncturable Pseudorandom Functions
Secure data deletion ensures that **deleted files are irrecoverable by an adversary that later obtains physical access to the underlying storage medium**. In this work, we present an novel method for provably secure deletion of files. First, we bootstrap secure deletion by using an external computing resource that the user controls (e.g., a TPM or SmartCard) to store a master key that never persists to disk. Second, we use a *puncturable pseudorandom function* (PPRF) to  generate per-file encryption keys on-the-fly. File access requires only a very efficient PPRF evaluation per file key retrieval and a single disk IO operation. File deletion is also fast, consisting only of an efficient *puncture* operation on the PPRF key and a constant number of symmetric encryptions. As a result, our techniques greatly minimize the disk IO overhead associated with prior approaches to secure deletion. This results in a significant performance improvement in practice. 

## References
[G05] Garfinkel, S. (2005). Design principles and patterns for computer systems that are simultaneously secure and usable (Doctoral dissertation, Massachusetts Institute of Technology).

[GGM86] Goldreich, O., Goldwasser, S., & Micali, S. (1986). How to construct random functions. Journal of the ACM (JACM), 33(4), 792-807.

[ORK18] Onarlioglu, K., Robertson, W., & Kirda, E. (2018, April). Eraser: Your Data Won't Be Back. In 2018 IEEE European Symposium on Security and Privacy (EuroS&P) (pp. 153-166). IEEE.

[RBC13] Reardon, J., Basin, D., & Capkun, S. (2013, May). Sok: Secure data deletion. In 2013 IEEE symposium on security and privacy (pp. 301-315). IEEE.
