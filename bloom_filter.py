import math
import murmurhash as mh
import bitarray
from binascii import hexlify

def optimal_km(n, p):
  ln2 = math.log(2)
  lnp = math.log(p)
  k = -lnp/ln2
  m = -n*lnp/((ln2)**2)
  return int(math.ceil(k)), int(math.ceil(m))

def add_to_bloomFilter(listofdata, bfilter):
    for data in listofdata:
        bfilter.add(data)
    return bfilter


class BloomFilter:
    def __init__(self, m, k, ntweak = 0x00000005, seed = 0xFBA4C795):
        self.m = m
        self.k = k
        self.ntweak = ntweak
        self.seed = seed
        self.bits = m*8*bitarray.bitarray('0',endian='little')

    def hash(self, i, seed, ntweak, data):
        hseed = (i*seed + ntweak) & 0xffffffff
        hs = mh.hash(data, hseed)
        return hs % len(self.bits)

    def add(self, data):
        for i in range(self.k):
            self.bits[self.hash(i, self.seed, self.ntweak, data)] = 1
    
    def contains(self, data):
        for i in range(self.k):
            if self.bits[self.hash(i, self.seed, self.ntweak, data)] == 0:
                return False
        return True
    def bfilter(self):
        return self.bits.tobytes()
    