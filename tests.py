from pprf import PPRF
import random
import secrets
import unittest

class TestPPRF(unittest.TestCase):
    def test_positive(self):
        pprf_key = secrets.token_bytes(16)
        pprf = PPRF(pprf_key)
        print(f'Running tests for puncturable PRF with key {pprf_key.hex()}')

        evals = []
        for i in range(0, 1000):
            x = random.getrandbits(128)
            evals.append((x, pprf.eval(x)))

        deletions = []
        for i in range(0, 1000):
            x = random.getrandbits(128)
            pprf.puncture(x)
            deletions.append(x)

        for (x,y)in evals:
            self.assertEqual(y, pprf.eval(x), f'PPRF Evaluation incorrect at point {x}') 

        for x in deletions:
            y = pprf.eval(x)
            self.assertEqual(None, y, f'PPRF Evaluation at deleted point {x} returned {y}')

if __name__ == '__main__':
    unittest.main()

