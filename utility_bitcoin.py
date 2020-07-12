def compactSize(n):
    if n >= 0 and n<= 252:
        return (b'','H')
    if n >= 253 and n<= 0xffff:
        return (b'\0xFD','i')
    if n >= 0x100000 and n <= 0xffffffff:
        return (b'\0xFE','I')
    if n >= 0x100000000 and n <= 0xffffffffffffffff:
        return (b'\0xFF', 'Q')