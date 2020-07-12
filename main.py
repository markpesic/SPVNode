import secrets as sc
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib as hs
from Crypto.Hash import RIPEMD160
from Crypto.Util.asn1 import DerOctetString
import base58 , socket, time, struct
from binascii import hexlify, unhexlify
from hexdump import hexdump


def ripemd160(shvk):
    rip = RIPEMD160.new()
    rip.update(shvk)
    return rip.digest()

def Generate_private_Key(nbytes=32):
    if nbytes>=32:
        x1 = sc.token_bytes(nbytes)
    return x1

def Generate_public_Key(prK):
    sk = SigningKey.from_string(prK, curve=SECP256k1)
    vk= sk.get_verifying_key()
    return(b'\x04'+vk.to_string())

def Generate_address(pk):
    pk1 = ripemd160(hs.sha256(pk).digest())
    pk1_extended = b'\x6F'+pk1
    shapk1 = hs.sha256(hs.sha256(pk1_extended).digest()).digest()
    final_pk1 = pk1_extended+shapk1[0:4]
    return base58.b58encode(final_pk1)

def WIF_private_key(sk):
    return base58.b58encode(b'\x80'+sk)


sk = Generate_private_Key()

try:
    f = open("Keys.txt", "x")
except :
    pass
finally:
    f = open("Keys.txt", "r")
    data = f.read()
    if(len(data) == 0 ):
        f.close()
        f = open("Keys.txt", "w")
        f.write(sk.hex())
        f.close()
    else:
        sk = unhexlify(data)
        f.close()

pk = Generate_public_Key(sk)

print("Publick Key :",pk)

pk1 = Generate_address(pk)

print("The address: ",pk1)

input1 = ["01", b';L\xc6\x02\xe5\xb4\x05\xde\x94\xa2\xc5\x14G\xd7\x9fW\x13\xe8\xe5X\x86g\x1a9\xd6ON-S\xed\xf0\xea', "00000000", "ffffffff"]
output1 = ["01", b"\x80\x00\x00\x00\x00\x00\x00\x00", "1e", b"v\xa9\x14o\xfd\xcd\xe97\xf9H\\\xac\x92T\x9f\x0c\xd4)\xf6\xb87\xdd\xa2\xc5B\xfeT\x05\x88\xac"]

def CreateTxDict(input=input1, output=output1):
    k = 0
    Tx = {
        "input":[],
        "output":[]
    }
    for i in range(int(input[0])):
        Tx["input"].append({})
        if(k == 0):
            Tx["input"][i].update(nInputs= input[k])
            k += 1
        for j in range(3):
            if( j == 0):
                Tx["input"][i].update(PrevInOutHash =  input[k][::-1].hex())
            if( j == 1):
                Tx["input"][i].update(PrevOutIndex= input[k])
            else:
                Tx["input"][i].update(sequence = input[k])
            k += 1
    k = 0
    for i in range(int(output[0])):
        Tx["output"].append({})
        if(k == 0):
            Tx["output"][i].update(nOutputs= output[k])
            k += 1
        
        for j in range(3):
            if(j == 0):
                Tx["output"][i].update(value = output[k][::-1].hex())
            if( j == 1):
                Tx["output"][i].update(SizePubKey =  output[k])
            if( j == 2):
                Tx["output"][i].update(PubKeyScript= output[k][::-1].hex())
            k += 1
        
    return Tx

def MakeStrTxs(word, Tx):
    strValue = ''
    for i in range(len(Tx[word])):
        lists = list(Tx[word][i].values())
        for j in range(len(lists)):
            strValue += lists[j]
    return strValue

def MakeRawTransaction(Tx, scriptLen='20', scriptSign=b'\xdf.\x8bR+\xa8Z\xd2\xee\x00\x16I\x15\x81%\xc1n7\xff\xceo\xc7\x05G^\xb0\xa2:4\xfak\xd5'):
    version = '02000000'
    lockTime = '00000000'
    strInput = MakeStrTxs('input', Tx)
    strOutput = MakeStrTxs('output', Tx)
    hashtype = '01000000'
    
    return(

        version +
        strInput +
        scriptLen+
        scriptSign[::-1].hex() +
        strOutput +
        lockTime +
        hashtype
    )

def SignTransaction(UnsignedTx, prK):
    h = hs.sha256(hs.sha256(UnsignedTx.encode('utf-8')).digest()).digest()
    sk = SigningKey.from_string(prK, curve=SECP256k1)
    sig = sk.sign(h)
    derSig = DerOctetString(sig)
    return(derSig.encode())

def scriptSignBuilder(sign, pubK):
    return(
        str("%02x" % len(sign + b'\x01')) +
        (sign + b'\x01').hex() +
        str("%02x" % len(pubK)) +
        pubK.hex()
    )

def substituteScriptSign(scriptSign, falseScriptSign, tx):
    final_tx = tx.replace(falseScriptSign, scriptSign)
    final_tx = final_tx.replace('01000000', '')
    return final_tx
    
Tx = CreateTxDict()

tx = MakeRawTransaction(Tx)
unhexlify(tx)
print("The old transaction: ",tx)
h = SignTransaction(tx, sk)

scriptSign = scriptSignBuilder(h, pk)

lenscrpt = "%02x" % len(unhexlify(scriptSign))

scriptSign = lenscrpt + scriptSign

print("lengths: ",len(tx),len(scriptSign))

oldStr = ('20' + (b'\xdf.\x8bR+\xa8Z\xd2\xee\x00\x16I\x15\x81%\xc1n7\xff\xceo\xc7\x05G^\xb0\xa2:4\xfak\xd5'[::-1]).hex())

print(len(oldStr))

final_tx = substituteScriptSign(scriptSign, oldStr, tx)

print("The transaction", final_tx, len(final_tx))

def deserializeTx(tx):
    pass

MAGIC_TESTNET3 =  0x0709110B

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


    return makeMessage(MAGIC_TESTNET3, b'version', payload)

def txMessage(payload):
    return makeMessage(MAGIC_TESTNET3, b'tx', payload)

def verackMessage():
    return makeMessage(MAGIC_TESTNET3, b"verack", b"\x00\x00\x00\x00")

def readHeader(s):
    header = s.recv(24)
    magic, command, payloadLen, checksumPayload = struct.unpack('L12sL4s', header)
    assert( magic == MAGIC_TESTNET3)
    print("Header")
    hexdump(header)
    return payloadLen, checksumPayload, command

def readPayload(s, sizePayload, checksumP):
    payload = s.recv(sizePayload)
    checksum = hs.sha256(hs.sha256(payload).digest()).digest()[0:4]
    assert(checksum == checksumP)
    return payload
    
def readMessage(s):
    lenPayload, chcksm, command = readHeader(s)
    print(lenPayload)
    payload =  readPayload(s, lenPayload, chcksm)
    print(command)
    hexdump(payload)

versionMsg = versionMessage()

tx = txMessage(unhexlify(final_tx))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(("138.201.214.71", 18333))

print("My Version Message:")
hexdump(versionMsg)

sock.send(versionMsg)

readMessage(sock) # receive version

sock.send(verackMessage())

readMessage(sock)# receive verack

sock.send(tx)

readMessage(sock)

sock.close()