from pprf import PPRF
import random
import secrets
import statistics
import sys
import time

cycles = 20

num_deletions = [100, 500, 1000, 2500, 5000, 10000]


for d in num_deletions:
    mean_key_sizes = []
    mean_delete_times = []
    mean_eval_times = []

    for i in range(0, cycles):
        delete_times = []
        eval_times = []
        pprf_key = secrets.token_bytes(16)
        pprf = PPRF(pprf_key)
        for z in range(0, 100):
            start = time.perf_counter()
            pprf.puncture(random.getrandbits(128))
            delete_times.append(time.perf_counter() - start)
            start = time.perf_counter()
            pprf.eval(random.getrandbits(128))
            eval_times.append(time.perf_counter() - start)

        print(f"========= (Cycle {i + 1}/{cycles}) 0 to {d} deletions =========")
        mean_eval_times.append(statistics.fmean(eval_times))
        mean_delete_times.append(statistics.fmean(delete_times))
        mean_key_sizes.append(sys.getsizeof(pprf.key))

    print(f"(0 to {d} Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
    print(f"(0 to {d} Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
    print(f"(0 to {d} Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

