import bisect, pyaes, secrets

KEY_PREFIX = 0
KEY_DEPTH = 1
KEY_VALUE = 2

class PPRF:

    def __init__(self, key):
        self.iv = secrets.randbits(128)
        self.key = [(0, 0, key)]
        # Used for length-doubling PRG
        self.inputs = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
        self.inputs += b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'

    # Length Doubling PRG
    # Expands 128-bit seed to 256-bit pseudorandom output
    # Uses AES-CTR-128 as a PRF
    def prg(self, seed):
        aes = pyaes.AESModeOfOperationCTR(seed, pyaes.Counter(self.iv))
        ciphertext = aes.encrypt(self.inputs)
        return ciphertext

    # Punctures the PRF at a point x and returns a new punctured key
    def puncture(self, x):
        key = self.get_longest_matching_prefix(x)
        seed = key[KEY_VALUE]
        check_val = key[KEY_PREFIX]
        prefix = key[KEY_PREFIX]
        self.key.remove(key)
        for i in range(key[KEY_DEPTH], 128):
            prg_output = self.prg(seed)
            bit = x >> (127 - i) & 1
            prefix_add = (1 - bit) * (2 ** (127 - i))
            if bit:
                seed = prg_output[16:]
                bisect.insort(self.key, (prefix + prefix_add, i + 1, prg_output[:16]))
            else:
                seed = prg_output[:16]
                bisect.insort(self.key, (prefix + prefix_add, i + 1, prg_output[16:]))

            prefix += bit * (2 ** (127 - i))

        return self.key

    # Get key that can evaluate the point x
    def get_longest_matching_prefix(self, x):
        i = bisect.bisect_left(self.key, (x, 2 ** 128, 2 ** 128))

        if i == len(self.key):
            return self.key[i - 1]
        elif self.key[i] == x:
            return self.key[i]

        return self.key[i - 1]

    # Evaluate the PPRF at a point x
    def eval(self, x):
        key = self.get_longest_matching_prefix(x)
        seed = key[KEY_VALUE]
        check_val = key[KEY_PREFIX]

        for i in range(key[KEY_DEPTH], 128):
            prg_output = self.prg(seed)
            if x >> (127 - i) & 1:
                seed = prg_output[16:]
                check_val += (2 ** (127 - i))
            else:
                seed = prg_output[:16]

        # value already punctured
        if check_val != x:
            seed = None

        return seed

