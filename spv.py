import secrets as sc
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib as hs
from Crypto.Hash import RIPEMD160
from Crypto.Util.asn1 import DerOctetString
import base58 , socket, time, struct
from binascii import hexlify, unhexlify
from hexdump import hexdump
from bloom_filter import BloomFilter, optimal_km, add_to_bloomFilter
from bitarray import bitarray


magic =  0x0709110B

block_hash = '00000000000000f0b33ef78a67d69e83f8ed23f07176c686566610c7d1d5736d'

def makeMessage(magic, command, payload):
    checksum = hs.sha256(hs.sha256(payload).digest()).digest()[0:4]
    return(
        struct.pack('L12sL4s', magic, command, len(payload), checksum) + payload
    )

def versionMessage():
    version = 70015
    services = 0
    timestamp = int(time.time())

    addrU = b"127.0.0.1"
    serviceU= 0
    portU= 18333

    addrMe = b"127.0.0.1"
    serviceMe= 0
    portMe= 18333


    nonce = 0
    height = 0
    user_agent_bytes = 0
    relay= 1

    payload = b""
    payload += struct.pack("i",version)
    payload += struct.pack("Q",services)
    payload += struct.pack("q",timestamp)
    payload += struct.pack("Q",serviceU)
    payload += struct.pack(">16s",addrU)
    payload += struct.pack(">H",portU)
    payload += struct.pack("Q",serviceMe)
    payload += struct.pack(">16s",addrMe)
    payload += struct.pack(">H",portMe)
    payload += struct.pack("Q",nonce)
    payload += struct.pack("B",user_agent_bytes)
    payload += struct.pack("i",height)
    payload += struct.pack("B",relay)


    return makeMessage(magic, b'version', payload)

def txMessage(payload):
    return makeMessage(magic, b'tx', payload)

def verackMessage():
    return makeMessage(magic, b"verack", b"\x00\x00\x00\x00")

def filterloadMessage(payload):
    bitarr = payload.bfilter()
    inv = str(payload.m).encode('utf-8') + bitarr + struct.pack('<IIh', payload.k, payload.ntweak, 1)
    return makeMessage(magic, b"filterload", inv)

def mempoolMessage():
    return makeMessage(magic, b"mempool", b"\x00\x00\x00\x00")

def getHeadersMessage(hash):
    version = 70015
    return makeMessage(magic, b"getheaders", struct.pack('<ih32s32s', version, 1, unhexlify(hash), b'\x00'))

k, m = optimal_km(1, 0.001)

bfilter = BloomFilter(m, k)

data_to_hash = unhexlify("n4ewvXymapgcMARgjMNPvYy2BnCji95SMz")

bfilter.add(data_to_hash)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(("116.203.72.215", 18333))

sock.send(versionMessage())

a = sock.recv(24*8) # receive version
b = sock.recv(1000)

sock.send(verackMessage())

c = sock.recv(1000) # receive verack

sock.send(filterloadMessage(bfilter))

d = sock.recv(1000) #receive filterloadheader

sock.send(getHeadersMessage(block_hash))

e = sock.recv(1000)
f = sock.recv(1000)

print(hexdump(a))
print(hexdump(b))
print(hexdump(c))
print(hexdump(d))
print(hexdump(e))
print(hexdump(f))

sock.close()