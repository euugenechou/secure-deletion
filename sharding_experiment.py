#!/usr/bin/env python3

from pprf import PPRF
import secrets
import random
import statistics

SHARDS = 4
PUNCTURES = 5000
TESTS = 10
DOMAIN_BITS = 32

f_key_size = []
fs_key_size = []

for test in range(0, TESTS):

    # holds the sharded PPRFs
    fs = []

    # single PPRF
    f = PPRF(secrets.token_bytes(16), DOMAIN_BITS)

    for j in range(0, SHARDS):
        fs.append(PPRF(secrets.token_bytes(16), DOMAIN_BITS))

    for i in range(0, PUNCTURES):
        f.puncture(random.getrandbits(DOMAIN_BITS))

    for i in range(0, PUNCTURES):
        idx = int(random.uniform(0,SHARDS))
        fs[idx].puncture(random.getrandbits(DOMAIN_BITS))

    f_key_size.append(len(f.key))
    total_len = 0
    for j in range(0, SHARDS):
        total_len += len(fs[j].key)

    fs_key_size.append(total_len)

print(f"({TESTS} tests) Average # of sub-keys for single PPRF key with {PUNCTURES} punctures: {statistics.fmean(f_key_size):.2f} with stddev: {statistics.pstdev(f_key_size):.2f}")
print(f"({TESTS} tests) Average # of sub-keys for {SHARDS} separate PPRF keys with {PUNCTURES} punctures distributed uniformly: {statistics.fmean(fs_key_size):.2f} with stddev: {statistics.pstdev(fs_key_size):.2f}")

