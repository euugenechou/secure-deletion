# Secure Deletion from Puncturable Pseudorandom Functions
Secure data deletion ensures that **deleted files are irrecoverable by an adversary that later obtains physical access to the underlying storage medium**. In this work, we present an novel method for provably secure deletion of files. First, we bootstrap secure deletion by using an external computing resource that the user controls (e.g., a TPM or SmartCard) to store a master key that never persists to disk. Second, we use a *puncturable pseudorandom function* (PPRF) to  generate per-file encryption keys on-the-fly. File access requires only a very efficient PPRF evaluation per file key retrieval and a single disk IO operation. File deletion is also fast, consisting only of an efficient *puncture* operation on the PPRF key and a constant number of symmetric encryptions. As a result, our techniques greatly minimize the disk IO overhead associated with prior approaches to secure deletion. This results in a significant performance improvement in practice. 

## Puncturable Pseudorandom Functions (PPRF)
A core ingredient of our techniques is the ability to efficiently generate per-file encryption keys on the fly using a **puncturable pseudorandom function (PPRF)**. Recall that a *pseudorandom function* (PRF) <img src="https://render.githubusercontent.com/render/math?math=F"> is a function that "looks random" to any computationally bounded adversary that is given polynomially many evaluations of <img src="https://render.githubusercontent.com/render/math?math=F_k(\cdot)"> when <img src="https://render.githubusercontent.com/render/math?math=k"> is chosen uniformly at random.

A puncturable PRF is a pseudorandom function with an additional *puncture* operation defined as:

- <img src="https://render.githubusercontent.com/render/math?math=\text{puncture}(k, x) \rightarrow k^*">, where <img src="https://render.githubusercontent.com/render/math?math=k^*"> is a new *punctured* key for <img src="https://render.githubusercontent.com/render/math?math=F"> such that <img src="https://render.githubusercontent.com/render/math?math=F_{k^*}(x') = F_k(x')"> for all <img src="https://render.githubusercontent.com/render/math?math=x' \ne x">

Additionally, it follows that for any computationally bounded adversary with access to a punctured key <img src="https://render.githubusercontent.com/render/math?math=k^*">, the value <img src="https://render.githubusercontent.com/render/math?math=F_k(x)"> is computationally indistinguishable from random.

## Benchmarking
The following table shows the average PPRF evaluation and puncturing times across **0 - N** puncturing operations for our reference PPRF implementation in `pprf.py`. In each test, the PPRF is initialized and then random points are punctured one at a time up to **N**. 

|                           |  0 - 100 |  0 - 500 | 0 - 1,000 | 0 - 2,500 | 0 - 5,000 | 0 - 10,000 |
|---------------------------|:------:|:------:|:------:|:------:|:------:|:-------:|
|     Avg. Eval Time (s)    | 0.0132 | 0.0129 | 0.0128 | 0.0127 | 0.0126 | 0.0125  |
|    Avg. Delete Time (s)   | 0.0133 | 0.0131 | 0.013  | 0.0129 | 0.013  | 0.0133  |
| Avg. Key Size (#sub-keys) | 12,050  | 59,079  | 117,150 | 289,568 | 574,109 | 1,138,264 |

Our preliminary results show that evaluation and puncturing times are essentially constant across the number of punctures. Unsurprisingly, the punctured key size grows linearly with the number of punctures. However, **our experimental results showed that only ~5% of the punctured key is needed in order to evaluate 99% of the PPRF points**. In practice, this means that only a small portion of the PPRF key is needed in memory. 

## References
[G05] Garfinkel, S. (2005). Design principles and patterns for computer systems that are simultaneously secure and usable (Doctoral dissertation, Massachusetts Institute of Technology).

[GGM86] Goldreich, O., Goldwasser, S., & Micali, S. (1986). How to construct random functions. Journal of the ACM (JACM), 33(4), 792-807.

[ORK18] Onarlioglu, K., Robertson, W., & Kirda, E. (2018, April). Eraser: Your Data Won't Be Back. In 2018 IEEE European Symposium on Security and Privacy (EuroS&P) (pp. 153-166). IEEE.

[RBC13] Reardon, J., Basin, D., & Capkun, S. (2013, May). Sok: Secure data deletion. In 2013 IEEE symposium on security and privacy (pp. 301-315). IEEE.
