# Secure Deletion from Puncturable Pseudorandom Functions
File system with provably secure deletion using cryptographic erasure

# Benchmarking
The following table shows the average PPRF evaluation and puncturing times across 0 - N puncturing operations. In each test, the PPRF is initialized and then random points are punctured one at a time up to `N`. 

|                       |   0 - 100  |   0 - 500  |  0 - 1,000  |  0 - 2,500  |  0 - 5,000  |  0-10,000 |
|-----------------------|:--------:|:--------:|:--------:|:--------:|:--------:|:--------:|
|   Avg. Eval Time (s)  | 0.013084 | 0.012938 | 0.012767 | 0.012617 | 0.012538 | 0.012424 |
|  Avg. Delete Time (s) | 0.013532 |  0.01436 | 0.015317 |  0.0189  | 0.025072 | 0.037303 |
| Avg. Key Size (bytes) |   98616  |  514560  |  1043552 |  2380480 |  4826304 |  9784688 |
