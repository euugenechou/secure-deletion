from pprf import PPRF
import random
import secrets
import statistics
import time

cycles = 10
num_deletions = [100, 500, 1000, 2500, 5000, 10000]

PPRF_DOMAIN_SIZE = 64

for d in num_deletions:
    mean_key_sizes = []
    mean_delete_times = []
    mean_eval_times = []
    mean_subkey_sizes = []

    for i in range(0, cycles):
        delete_times = []
        eval_times = []
        pprf_key = secrets.token_bytes(16)
        pprf = PPRF(pprf_key, PPRF_DOMAIN_SIZE)
        for z in range(0, d):
            start = time.perf_counter()
            pprf.puncture(random.getrandbits(PPRF_DOMAIN_SIZE))
            delete_times.append(time.perf_counter() - start)
            start = time.perf_counter()
            pprf.eval(random.getrandbits(PPRF_DOMAIN_SIZE))
            eval_times.append(time.perf_counter() - start)

        print(f"========= (Cycle {i + 1}/{cycles}) 0 to {d} deletions =========")
        mean_eval_times.append(statistics.fmean(eval_times))
        mean_delete_times.append(statistics.fmean(delete_times))
        mean_key_sizes.append(len(pprf.key))

        pprf.key.sort(key=lambda l: l[1])
        support = 0
        key_count = 0
        while (support / 2 ** PPRF_DOMAIN_SIZE) < 0.99:
            support += 2 ** (PPRF_DOMAIN_SIZE - pprf.key[key_count][1])
            key_count += 1

        mean_subkey_sizes.append(key_count)

    print(f"(0 to {d} Deletions): Average Evaluation Time (s): {statistics.fmean(mean_eval_times):.4f} with stddev: {statistics.pstdev(mean_eval_times):.4f}")
    print(f"(0 to {d} Deletions): Average Deletion Time (s): {statistics.fmean(mean_delete_times):.4f} with stddev: {statistics.pstdev(mean_delete_times):.4f}")
    print(f"(0 to {d} Deletions): Average Key Size (# sub-keys): {statistics.fmean(mean_key_sizes):.0f} with stddev: {statistics.pstdev(mean_key_sizes):.0f}")
    print(f"(0 to {d} Deletions): Average # of sub-keys needed to evaluate 99% of points: {statistics.fmean(mean_subkey_sizes):.0f} with stddev: {statistics.pstdev(mean_subkey_sizes):.0f}")
    print(f"(0 to {d} Deletions): On average, only need {(100 * statistics.fmean(mean_subkey_sizes) / statistics.fmean(mean_key_sizes)):.2f}% of sub-keys to evaluate 99% of points")
