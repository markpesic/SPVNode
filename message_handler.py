import struct, socket, time
import hashlib as hs
from hexdump import hexdump
import secrets as sc
from binascii import unhexlify, hexlify 
from bloom_filter import BloomFilter, optimal_km, add_to_bloomFilter
from utility_bitcoin import compactSize

#COSTANTS

LENGTH_HEADER_PAYLOAD = 24# number of bytes
MAGIC = 0x0709110B

#TODOs:
#reorganize message handler better not with redundant methods maybe
#bloomfilter message doesn't work properly , try to find a way to make it work
#ES. when you send the blomfilter message the node begins to send you empty messages

listofCommands = [
    b'version',
    b'verack',
    b'sendcmpct',
    b'ping',
    b'addr',
    b'feefilter',
    b'sendheaders',
    b'inv',
    b'pong',
    b'headers'
]

InvTypeMessage = {
    0:'ERROR',
    1:'MSG_TX',
    2:'MSG_BLOCK',
    3:'MSG_FILTERED_BLOCK',
    4:'MSG_CMPCT_BLOCK'
}

nonces = []

var_ints = {
    0xFD:('H', 2),
    0xFE:('I', 4),
    0xFF:('Q', 8),
}



service = {
    0x00:'Not known',
    0x01:'NODE_NETWORK',
    0x02:'NODE_GETUTXO',
    0x04:'NODE_BLOOM',
    0x08:'NODE_WITNESS',
    0x10:'NODE_XTHIN',
    0x0400:'NODENETWORK:LIMITED'
}

Addresses = []

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

#Program

class Address:
    def __init__(self, t, s, ip, port):
        self.t = t
        self.s = s
        self.ip = ip
        self.port = port

class MessageHandler:
    def __init__(self):
        self.command = b''
        self.lenPayload = -1


    def messagelist(self, msg, sock):
        foundCommand = False
        magicS, self.command, self.lenPayload, _ = struct.unpack('L12sL4s', msg)

        if magicS != MAGIC: return sock.close()
        
        for command in listofCommands:
            if command in self.command:
                foundCommand = True
                self.command = command

        print(self.command,self.lenPayload)

        if self.lenPayload <=0: return

        if self.lenPayload <= 1024:
            payload = sock.recv(self.lenPayload)

        if foundCommand == False: 
            print('NOT FOUND COMMAND')
            return 

        if(self.command == b'version'):
            flag = False
            ver, srvc, _, _ = struct.unpack('<iQqQ', payload[:28])
            _, _ = struct.unpack('>16sH', payload[28:46])
            _  = struct.unpack('<Q', payload[46:54])
            _, _ = struct.unpack('>16sH', payload[54:72])
            nnc = struct.unpack('<Q', payload[72:80])
            length = payload[80]
            for lens in var_ints.keys():
                if(lens == payload[80]):
                    length = struct.unpack('<'+ var_ints[lens][0], payload[80+ var_ints[lens][1]])
            userAgentBytes = struct.unpack(str(length)+'s', payload[81:81+length])
            h, r = struct.unpack('<i?', payload[81+length:])
            nonces.append(nnc)
            if ver < version:
                return sock.close()
            for s in service.keys():
                if s == srvc:
                    flag = True
                    print(service[s])
            if flag == False: print('some other type of services')
            print(h)
            if r == True:print('you can send transaactions')
            else: print("you can't send new transactions")
            finalMsg = self.messageMaker(b'verack')
            print(finalMsg)
            sock.send(finalMsg)
            return


        if self.command == b'verack':
            print('The handshake protocol ended')
            return


        if self.command == b'addr':
            length = payload[0]

            offset = 1
            for lens in var_ints.keys():
                if(lens == payload[0]):
                    length = struct.unpack('<'+ var_ints[lens][0], payload[1:var_ints[lens][1]]+1)
                    offset = var_ints[lens][1]
            start = offset
            end = 30 + offset
            for _ in range(length):
                t, s= struct.unpack('<iQ', payload[start:start+12])
                ip, p = struct.unpack('>16sH', payload[start+12:end])
                start = end
                end += end
                Addresses.append(Address(t,s,ip,p))
            return

        if self.command == b'sendheaders':
            print("Send only new Headers, not new blocks")
            return
        
        if self.command == b'sendcmpct':
            return
        
        if self.command == b'feefilter':
            feerate = struct.unpack('<Q', payload)
            satoshis = feerate[0]/1000
            print('You can send ',satoshis,'per 1000 bytes')
            return

        if self.command == b'ping':
            pong = self.messageMaker(b'pong', info = payload)
            sock.send(pong)
            return
        
        if self.command == b'inv':
            length = payload[0]
            offset = 1
            for lens in var_ints.keys():
                if lens == length:
                    length = payload[1:1+var_ints[lens][1]]
                    offset = 1+var_ints[lens][1]
            for _ in range(length):
                typeMsg, content = struct.unpack('<I32s', payload[offset:offset+36])
                offset += 36
                print(typeMsg)
                print(InvTypeMessage[typeMsg])
                print(content)
                return
        
        if self.command == b'headers':
            length = sock.recv(1)
            print(length)
            for lens in var_ints.keys():
                if lens in length:
                    length = sock.recv(var_ints[lens][1])
                    print(length)
                    length = struct.unpack('<'+var_ints[lens][0], length)
                    print(length)
            for i in range(length[0]):
                payload = sock.recv(80)
                hexdump(payload)
                v, ph, hr, t, nb, nnc = struct.unpack('<i32s32sIII', payload)
                sock.recv(1)
                print(i, length[0])
                return
            
        else:
            print('not supported message')
    
    def initialize_handshake(self):
        return(self.messageMaker(b'version'))
    
    def messageMaker(self, command, info = None):
        if(command == b'version'):

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
            return self.msgHeader(payload, command)
        if(command == b'verack'):
             return self.msgHeader(b"\x00\x00\x00\x00", b'verack')
        
        if command == b'pong':
            print(info, command)
            return self.msgHeader(info, command)
        
        if command == b'ping':
            return self.msgHeader(sc.token_bytes(8),b'ping')
        
        if command == b'filterload':
            bitarr = info.bfilter()
            size = compactSize(info.m)
            inv = size[0] + struct.pack('<'+size[1], info.m) + bitarr + struct.pack('<II', info.k, info.ntweak) + 0x00
            print(inv)
            return self.msgHeader(inv, b'filterload')
        
        if command == b'getheaders':
            bhash = b'00000000000000f0b33ef78a67d69e83f8ed23f07176c686566610c7d1d5736d'[::-1]
            inv = struct.pack('<ih32s32s', version, 1, unhexlify(bhash), b'\x00')
            return self.msgHeader(inv, b'getheaders')
    
    def msgHeader(self, payload, command):
        checksum = hs.sha256(hs.sha256(payload).digest()).digest()[0:4]
        return (struct.pack('L12sL4s', MAGIC, command, len(payload), checksum) + payload)



msgHandler = MessageHandler()

k, m = optimal_km(2, 0.01)

bfilter = BloomFilter(m, k)

data_to_hash = "n4ewvXymapgcMARgjMNPvYy2BnCji95SMz"

data_to_hash1 = b"\x040M]\xda\xf6'\xbb\xa4\xb2 \xf30o\x15\x8c\x17\x16\xectg\x8cL\xdc\x97\x1d7\xca\xdd\xba\xe0N\xfd\xcfl\xbdr\xfck\x7f\xd6p\x01x\xce\xab\xa9\xe5\xca\x14\xf2\x13\x10v`k\x1b\x90\x01\x14EHK\x83\xff"

bfilter.add(data_to_hash)
bfilter.add(data_to_hash1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.settimeout(6.0)

sock.connect(("49.4.68.109", 18333))

vrs = msgHandler.initialize_handshake()

sock.send(vrs)

ping = msgHandler.messageMaker(b'ping')
bloomfilter = msgHandler.messageMaker(b'filterload', info = bfilter)
getheaders = msgHandler.messageMaker(b'getheaders')

syncProcess = [ping, bloomfilter, getheaders]

i = 0

f = False

while True:
    try:
        data = sock.recv(LENGTH_HEADER_PAYLOAD) 
    except socket.timeout:
        if i < 3:
            sock.send(syncProcess[i])
            print(syncProcess[i])
        i+= 1
        continue
    if data == b'':continue
    if (not data): break
    hexdump(data)
    msgHandler.messagelist(data, sock)

