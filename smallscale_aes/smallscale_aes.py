#!/usr/bin/python

import copy


class SmallScaleAES:
    """
    SmallScaleAES implementation
    c.f.: https://www.iacr.org/archive/fse2005/35570143/35570143.pdf
    """
    def __init__(self, n, r, c, e):
        assert n in range(1, 11), "only n in [1, ..., 10] is allowed"
        assert r in [1, 2, 4], "only r in [1, 2, 4] is allowed"
        assert c in [1, 2, 4], "only c in [1, 2, 4] is allowed"
        assert e in [4, 8], "only e in [4, 8] is allowed"
        self.n = n
        self.r = r
        self.c = c
        self.e = e
        self.state = None
        self.mod = 0x13 if e == 4 else 0x11b

    def __str__(self):
        if self.state is not None:
            strrepr = "State: "
            for c in range(self.c):
                for r in range(self.r):
                    if self.e == 4:
                        strrepr += "%x " % (self.state[r][c])
                    elif self.e == 8:
                        strrepr += "%2x " % (self.state[r][c])
        else:
            strrepr = "SR(%d, %d, %d, %d)" % (self.n, self.r, self.c, self.e)
        return strrepr

    def __getitem__(self, key):
        return self.state[key]

    def SubBytes(self):
        for i in range(self.r):
            for j in range(self.c):
                self.state[i][j] = sbox(self.state[i][j], size=self.e)

    def ShiftRows(self):
        for i in range(self.r):
            row = self.state[i]
            rotated = row[i:] + row[0:i]
            self.state[i] = rotated

    def MixColumns(self):
        if self.r == 1:
            mds = [[1]]
        elif self.r == 2:
            mds = [[3, 2],
                   [2, 3]]
        elif self.r == 4:
            mds = [[2, 3, 1, 1],
                   [1, 2, 3, 1],
                   [1, 1, 2, 3],
                   [3, 1, 1, 2]]

        newstate = [[0]*self.r for _ in range(self.c)]
        for i in range(self.r):
            for j in range(self.c):
                for k in range(self.r):
                    newstate[i][j] ^= gf_mult(mds[i][k], self.state[k][j],
                                              self.mod)

        for i in range(self.r):
            for j in range(self.c):
                self.state[i][j] = newstate[i][j]

    def AddRoundKey(self, key):
        for i in range(self.r):
            for j in range(self.c):
                self.state[i][j] ^= key[i][j]

    def KeySchedule(self, key):
        def g(rcon, col, e):
            col = col[1:] + [col[0]]
            col = [sbox(i, e) for i in col]
            col[0] ^= rcon
            return col

        keys = [copy.deepcopy(key)]
        rcon = 1
        for _ in range(self.n):

            rkey = copy.deepcopy(keys[-1])
            col = [rkey[r][-1] for r in range(self.r)]
            if self.c == 1:
                rkey[0] = g(rcon, col, self.e)
            else:
                col = g(rcon, col, self.e)
                for r in range(self.r):
                    rkey[r][0] ^= col[r]
                for r in range(self.r):
                    for c in range(1, self.c):
                        rkey[r][c] ^= rkey[r][c-1]

            keys.append(rkey)
            rcon <<= 1
            if rcon >= 1 << self.e:
                rcon ^= self.mod
        return keys

    def enc(self, plain, key):
        plain = [[plain[i*self.c + j]
                 for i in range(self.r)]
                 for j in range(self.c)]
        key = [[key[i*self.c + j]
               for i in range(self.r)]
               for j in range(self.c)]
        keys = self.KeySchedule(key)

        self.state = plain
        self.AddRoundKey(keys[0])
        for i in range(1, self.n):
            self.SubBytes()
            self.ShiftRows()
            self.MixColumns()
            self.AddRoundKey(keys[i])
        self.SubBytes()
        self.ShiftRows()
        self.AddRoundKey(keys[self.n])

        cipher = []
        for c in range(self.c):
            for r in range(self.r):
                cipher.append(self.state[r][c])
        return cipher


def sbox(i, size=4):
    assert size in [4, 8], "not supported sbox size %d" % (size)
    if size == 4:
        table = [6, 11, 5, 4, 2, 14, 7, 10,
                 9, 13, 15, 12, 3, 1, 9, 8]
    elif size == 8:
        table = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
                 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
                 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
                 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
                 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
                 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
                 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
                 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
                 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
                 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
                 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
                 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
                 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
                 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
                 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
                 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
    return table[i]


def inverse(sbox, domain):
    return [sbox(i) for i in range(domain)].index


def isbox(i, size=4):
    return inverse(lambda x: sbox(x, size), 2**size)(i)


def gf_mult(a, b, mod):
    e = len(bin(mod)[2:]) - 1
    if a == 1:
        return b
    elif a == 2:
        c = b << 1
        if c >= 1 << e:
            c ^= mod
    elif a == 3:
        c = b ^ (b << 1)
        if c >= 1 << e:
            c ^= mod
    return c


def state2str(state):
    strrepr = ""
    for j in range(len(state[0])):
        for i in range(len(state)):
            strrepr += ("%02x " % state[i][j])
    return strrepr


def list2str(ls):
    strrepr = ""
    for i in ls:
        strrepr += ("%02x " % i)
    return strrepr

if __name__ == "__main__":
    # small scale parameters, s.t. SR(n,r,c,e) == AES128
    n, r, c, e = 10, 4, 4, 8
    aes = SmallScaleAES(n, r, c, e)

    # testvectors:
    # http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf Appendix B
    p0 = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    c0 = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]
    c_ = aes.enc(p0, key)
    print("p0: %s" % (list2str(p0)))
    print("c0: %s" % (list2str(c_)))
    print("tv: %s" % (list2str(c0)))
