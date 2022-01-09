from pprf import PPRF
import random
import secrets
import statistics
import sys
import time

cycles = 20

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

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 100 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 100 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 100 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 100 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

mean_key_sizes = []
mean_delete_times = []
mean_eval_times = []

for i in range(0, cycles):
    delete_times = []
    eval_times = []
    pprf_key = secrets.token_bytes(16)
    pprf = PPRF(pprf_key)
    for z in range(0, 500):
        start = time.perf_counter()
        pprf.puncture(random.getrandbits(128))
        delete_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        pprf.eval(random.getrandbits(128))
        eval_times.append(time.perf_counter() - start)

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 500 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 500 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 500 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 500 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

mean_key_sizes = []
mean_delete_times = []
mean_eval_times = []

for i in range(0, cycles):
    delete_times = []
    eval_times = []
    pprf_key = secrets.token_bytes(16)
    pprf = PPRF(pprf_key)
    for z in range(0, 1000):
        start = time.perf_counter()
        pprf.puncture(random.getrandbits(128))
        delete_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        pprf.eval(random.getrandbits(128))
        eval_times.append(time.perf_counter() - start)

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 1000 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 1000 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 1000 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 1000 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

mean_key_sizes = []
mean_delete_times = []
mean_eval_times = []

for i in range(0, cycles):
    delete_times = []
    eval_times = []
    pprf_key = secrets.token_bytes(16)
    pprf = PPRF(pprf_key)
    for z in range(0, 2500):
        start = time.perf_counter()
        pprf.puncture(random.getrandbits(128))
        delete_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        pprf.eval(random.getrandbits(128))
        eval_times.append(time.perf_counter() - start)

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 2500 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 2500 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 2500 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 2500 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

mean_key_sizes = []
mean_delete_times = []
mean_eval_times = []

for i in range(0, cycles):
    delete_times = []
    eval_times = []
    pprf_key = secrets.token_bytes(16)
    pprf = PPRF(pprf_key)
    for z in range(0, 5000):
        start = time.perf_counter()
        pprf.puncture(random.getrandbits(128))
        delete_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        pprf.eval(random.getrandbits(128))
        eval_times.append(time.perf_counter() - start)

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 5000 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 5000 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 5000 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 5000 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")

mean_key_sizes = []
mean_delete_times = []
mean_eval_times = []

for i in range(0, cycles):
    delete_times = []
    eval_times = []
    pprf_key = secrets.token_bytes(16)
    pprf = PPRF(pprf_key)
    for z in range(0, 10000):
        start = time.perf_counter()
        pprf.puncture(random.getrandbits(128))
        delete_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        pprf.eval(random.getrandbits(128))
        eval_times.append(time.perf_counter() - start)

    print(f"========= (Cycle {i + 1}/{cycles}) 0 to 10000 deletions =========")
    mean_eval_times.append(statistics.fmean(eval_times))
    mean_delete_times.append(statistics.fmean(delete_times))
    mean_key_sizes.append(sys.getsizeof(pprf.key))

print(f"(0 to 10000 Deletions): Average Evaluation Time: {statistics.fmean(mean_eval_times)} with stddev: {statistics.pstdev(mean_eval_times)}")
print(f"(0 to 10000 Deletions): Average Deletion Time: {statistics.fmean(mean_delete_times)} with stddev: {statistics.pstdev(mean_delete_times)}")
print(f"(0 to 10000 Deletions): Average Key Size (bytes): {statistics.fmean(mean_key_sizes)} with stddev: {statistics.pstdev(mean_key_sizes)}")


