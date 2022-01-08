from pprf import PPRF
import random
import secrets
import sys
import time

delete_times = []
eval_times = []

prf_key = secrets.token_bytes(16)
prf = PPRF(prf_key)

for i in range(0, 2000):
    start = time.perf_counter()
    prf.puncture(random.getrandbits(128))
    delete_times.append(time.perf_counter() - start)
    start = time.perf_counter()
    prf.eval(random.getrandbits(128))
    eval_times.append(time.perf_counter() - start)

print(f"Key size (bytes): {sys.getsizeof(prf.key)}")
print(f"Average Eval Time (s): {sum(eval_times) / len(eval_times)}")
print(f"Average Delete Time (s): {sum(delete_times) / len(delete_times)}")
