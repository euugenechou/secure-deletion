import pyaes, binascii, secrets

class GGM_PRF:

    def __init__(self, key):
        self.iv = secrets.randbits(128)
        self.key = key
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

    # Evalutates the GGM'86 PRF at a point x
    def eval(self, x):
        seed = self.key
        for i in range(0, 128):
            prg_output = self.prg(seed)
            if x >> i & 1:
                seed = prg_output[16:]
            else:
                seed = prg_output[0:16]

        return seed


prf_key = secrets.token_bytes(16)
prf = GGM_PRF(prf_key)
print(binascii.hexlify(prf.eval(0)))
print(binascii.hexlify(prf.eval(0)))
print(binascii.hexlify(prf.eval(1)))
