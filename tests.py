from pprf import PPRF
import random
import secrets
import unittest

class TestPPRF(unittest.TestCase):
    def test_positive(self):
        pprf_key = secrets.token_bytes(16)
        pprf = PPRF(pprf_key, 32)
        print(f'Running tests for puncturable PRF with key {pprf_key.hex()}')

        evals = []
        for i in range(0, 1000):
            x = random.getrandbits(32)
            evals.append((x, pprf.eval(x)))

        deletions = []
        for i in range(0, 1000):
            x = random.getrandbits(32)
            pprf.puncture(x)
            deletions.append(x)

        for (x,y) in evals:
            self.assertEqual(y, pprf.eval(x), f'PPRF Evaluation incorrect at point {x}') 

        for x in deletions:
            y = pprf.eval(x)
            self.assertEqual(None, y, f'PPRF Evaluation at deleted point {x} returned {y}')

        pprf_key = b'DEADBEEFDEADBEEF'
        pprf = PPRF(pprf_key, 3, 0)
        evals = ['647bb9854aba65d4723f96c1e3fecbf4', 'f56bbe6df5f1d329a2c3b395d033199d',
                 '3898be4958b02e2147311c565d84c594', '87179a7ea0dc45df5bf498479dd9cb01',
                 '47376e86315f2d103765f5387fde02d3', 'd08c01e189c1aa14325d870481c6045e',
                 'fe4a07c0ff739645e61d599c0afd8a5f', 'af63442c53c3ac25b9cdbeddbcc20e2f'
                ]

        for x in range(0, 2 ** 3):
            self.assertEqual(evals[x], pprf.eval(x).hex(), f'PPRF Evaluation incorrect at point {x}')

        pprf.puncture(1)
        pprf.puncture(6)
        self.assertEqual(None, pprf.eval(1), f'PPRF Evaluation at deleted point 1 returned {pprf.eval(1)}')
        self.assertEqual(None, pprf.eval(6), f'PPRF Evaluation at deleted point 6 returned {pprf.eval(6)}')
        self.assertEqual(evals[0], pprf.eval(0).hex(), f'PPRF Evaluation incorrect after puncturing at point 0')
        self.assertEqual(evals[2], pprf.eval(2).hex(), f'PPRF Evaluation incorrect after puncturing at point 2')
        self.assertEqual(evals[3], pprf.eval(3).hex(), f'PPRF Evaluation incorrect after puncturing at point 3')
        self.assertEqual(evals[4], pprf.eval(4).hex(), f'PPRF Evaluation incorrect after puncturing at point 4')
        self.assertEqual(evals[5], pprf.eval(5).hex(), f'PPRF Evaluation incorrect after puncturing at point 5')
        self.assertEqual(evals[7], pprf.eval(7).hex(), f'PPRF Evaluation incorrect after puncturing at point 7')

        self.assertEqual(len(pprf.key), 4, f'Expected PPRF key size of 4 but got {len(pprf.key)}')

        k1 = pprf.key
        pprf.puncture(6)
        pprf.puncture(1)
        k2 = pprf.key
        self.assertEqual(k1, k2, f'PPRF key was mangled after repeated puncturing of a point')

if __name__ == '__main__':
    unittest.main()

