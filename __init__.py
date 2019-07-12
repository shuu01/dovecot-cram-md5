# -*- coding: utf-8 -*-
#
# Copyright (C) 2009  Asad Saeed (http://www.acidseed.com/)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# $Id$

"""
HMAC-MD5/CRAM-MD5 Hash Generator for Dovecot

This generates the hash used for CRAM-MD5 authentication on
the Dovecot IMAP/POP3 server.  Use dovecotpw('password') to
recieve the hash in the proper format

   '{HMAC-MD5}e02d374fde0dc75a17a557039a3a5338c7743304777dccd376f332bee68d2cf6'

Pure Python MD5 implementation borrowed from Dinu C. Gherman
http://python.net/~gherman/
"""

import struct, hashlib, array, binascii
from itertools import zip_longest

def _bytelist2long(lst):
    "Transform a list of characters into a list of longs."

    imax = len(lst)//4
    hl = [0] * imax

    j = 0
    i = 0
    while i < imax:
        b0 = int(lst[j])
        b1 = (int(lst[j+1])) << 8
        b2 = (int(lst[j+2])) << 16
        b3 = (int(lst[j+3])) << 24
        hl[i] = b0 | b1 |b2 | b3
        i = i+1
        j = j+4

    return hl


def _rotateLeft(x, n):
    "Rotate x (32 bit) left n bits circularly."

    return (x << n) | (x >> (32-n))


# ======================================================================
# The real MD5 meat...
#
#   Implemented after "Applied Cryptography", 2nd ed., 1996,
#   pp. 436-441 by Bruce Schneier.
# ======================================================================

# F, G, H and I are basic MD5 functions.

def F(x, y, z):
    return (x & y) | ((~x) & z)

def G(x, y, z):
    return (x & z) | (y & (~z))

def H(x, y, z):
    return x ^ y ^ z

def I(x, y, z):
    return y ^ (x | (~z))


def XX(func, a, b, c, d, x, s, ac):
    """Wrapper for call distribution to functions F, G, H and I.

    This replaces functions FF, GG, HH and II from "Appl. Crypto.
    Rotation is separate from addition to prevent recomputation
    (now summed-up in one function).
    """

    res = 0
    res = res + a + func(b, c, d)
    res = res + x
    res = res + ac
    res = res & 0xffffffff
    res = _rotateLeft(res, s)
    res = res & 0xffffffff
    res = res + b

    return res & 0xffffffff


class MD5:
    "An implementation of the MD5 hash function in pure Python."

    def __init__(self):
        "Initialisation."

        # Initial 128 bit message digest (4 times 32 bit).
        self.A = 0
        self.B = 0
        self.C = 0
        self.D = 0

        # Initial message length in bits(!).
        self.length = 0
        self.count = [0, 0]

        # Initial empty message as a sequence of bytes (8 bit characters).
        self.input = []

        # Length of the final hash (in bytes).
        self.HASH_LENGTH = 16

        # Length of a block (the number of bytes hashed in every transform).
        self.DATA_LENGTH = 64

        # Call a separate init function, that can be used repeatedly
        # to start from scratch on the same object.
        self.init()


    def init(self):
        "Initialize the message-digest and set all fields to zero."

        self.length = 0
        self.input = []

        # Load magic initialization constants.
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476


    def _transform(self, inp):
        """Basic MD5 step transforming the digest based on the input.

        Note that if the Mysterious Constants are arranged backwards
        in little-endian order and decrypted with the DES they produce
        OCCULT MESSAGES!
        """

        a, b, c, d = A, B, C, D = self.A, self.B, self.C, self.D

        # Round 1.

        S11, S12, S13, S14 = 7, 12, 17, 22

        a = XX(F, a, b, c, d, inp[ 0], S11, 0xD76AA478) # 1
        d = XX(F, d, a, b, c, inp[ 1], S12, 0xE8C7B756) # 2
        c = XX(F, c, d, a, b, inp[ 2], S13, 0x242070DB) # 3
        b = XX(F, b, c, d, a, inp[ 3], S14, 0xC1BDCEEE) # 4
        a = XX(F, a, b, c, d, inp[ 4], S11, 0xF57C0FAF) # 5
        d = XX(F, d, a, b, c, inp[ 5], S12, 0x4787C62A) # 6
        c = XX(F, c, d, a, b, inp[ 6], S13, 0xA8304613) # 7
        b = XX(F, b, c, d, a, inp[ 7], S14, 0xFD469501) # 8
        a = XX(F, a, b, c, d, inp[ 8], S11, 0x698098D8) # 9
        d = XX(F, d, a, b, c, inp[ 9], S12, 0x8B44F7AF) # 10
        c = XX(F, c, d, a, b, inp[10], S13, 0xFFFF5BB1) # 11
        b = XX(F, b, c, d, a, inp[11], S14, 0x895CD7BE) # 12
        a = XX(F, a, b, c, d, inp[12], S11, 0x6B901122) # 13
        d = XX(F, d, a, b, c, inp[13], S12, 0xFD987193) # 14
        c = XX(F, c, d, a, b, inp[14], S13, 0xA679438E) # 15
        b = XX(F, b, c, d, a, inp[15], S14, 0x49B40821) # 16

        # Round 2.

        S21, S22, S23, S24 = 5, 9, 14, 20

        a = XX(G, a, b, c, d, inp[ 1], S21, 0xF61E2562) # 17
        d = XX(G, d, a, b, c, inp[ 6], S22, 0xC040B340) # 18
        c = XX(G, c, d, a, b, inp[11], S23, 0x265E5A51) # 19
        b = XX(G, b, c, d, a, inp[ 0], S24, 0xE9B6C7AA) # 20
        a = XX(G, a, b, c, d, inp[ 5], S21, 0xD62F105D) # 21
        d = XX(G, d, a, b, c, inp[10], S22, 0x02441453) # 22
        c = XX(G, c, d, a, b, inp[15], S23, 0xD8A1E681) # 23
        b = XX(G, b, c, d, a, inp[ 4], S24, 0xE7D3FBC8) # 24
        a = XX(G, a, b, c, d, inp[ 9], S21, 0x21E1CDE6) # 25
        d = XX(G, d, a, b, c, inp[14], S22, 0xC33707D6) # 26
        c = XX(G, c, d, a, b, inp[ 3], S23, 0xF4D50D87) # 27
        b = XX(G, b, c, d, a, inp[ 8], S24, 0x455A14ED) # 28
        a = XX(G, a, b, c, d, inp[13], S21, 0xA9E3E905) # 29
        d = XX(G, d, a, b, c, inp[ 2], S22, 0xFCEFA3F8) # 30
        c = XX(G, c, d, a, b, inp[ 7], S23, 0x676F02D9) # 31
        b = XX(G, b, c, d, a, inp[12], S24, 0x8D2A4C8A) # 32

        # Round 3.

        S31, S32, S33, S34 = 4, 11, 16, 23

        a = XX(H, a, b, c, d, inp[ 5], S31, 0xFFFA3942) # 33
        d = XX(H, d, a, b, c, inp[ 8], S32, 0x8771F681) # 34
        c = XX(H, c, d, a, b, inp[11], S33, 0x6D9D6122) # 35
        b = XX(H, b, c, d, a, inp[14], S34, 0xFDE5380C) # 36
        a = XX(H, a, b, c, d, inp[ 1], S31, 0xA4BEEA44) # 37
        d = XX(H, d, a, b, c, inp[ 4], S32, 0x4BDECFA9) # 38
        c = XX(H, c, d, a, b, inp[ 7], S33, 0xF6BB4B60) # 39
        b = XX(H, b, c, d, a, inp[10], S34, 0xBEBFBC70) # 40
        a = XX(H, a, b, c, d, inp[13], S31, 0x289B7EC6) # 41
        d = XX(H, d, a, b, c, inp[ 0], S32, 0xEAA127FA) # 42
        c = XX(H, c, d, a, b, inp[ 3], S33, 0xD4EF3085) # 43
        b = XX(H, b, c, d, a, inp[ 6], S34, 0x04881D05) # 44
        a = XX(H, a, b, c, d, inp[ 9], S31, 0xD9D4D039) # 45
        d = XX(H, d, a, b, c, inp[12], S32, 0xE6DB99E5) # 46
        c = XX(H, c, d, a, b, inp[15], S33, 0x1FA27CF8) # 47
        b = XX(H, b, c, d, a, inp[ 2], S34, 0xC4AC5665) # 48

        # Round 4.

        S41, S42, S43, S44 = 6, 10, 15, 21

        a = XX(I, a, b, c, d, inp[ 0], S41, 0xF4292244) # 49
        d = XX(I, d, a, b, c, inp[ 7], S42, 0x432AFF97) # 50
        c = XX(I, c, d, a, b, inp[14], S43, 0xAB9423A7) # 51
        b = XX(I, b, c, d, a, inp[ 5], S44, 0xFC93A039) # 52
        a = XX(I, a, b, c, d, inp[12], S41, 0x655B59C3) # 53
        d = XX(I, d, a, b, c, inp[ 3], S42, 0x8F0CCC92) # 54
        c = XX(I, c, d, a, b, inp[10], S43, 0xFFEFF47D) # 55
        b = XX(I, b, c, d, a, inp[ 1], S44, 0x85845DD1) # 56
        a = XX(I, a, b, c, d, inp[ 8], S41, 0x6FA87E4F) # 57
        d = XX(I, d, a, b, c, inp[15], S42, 0xFE2CE6E0) # 58
        c = XX(I, c, d, a, b, inp[ 6], S43, 0xA3014314) # 59
        b = XX(I, b, c, d, a, inp[13], S44, 0x4E0811A1) # 60
        a = XX(I, a, b, c, d, inp[ 4], S41, 0xF7537E82) # 61
        d = XX(I, d, a, b, c, inp[11], S42, 0xBD3AF235) # 62
        c = XX(I, c, d, a, b, inp[ 2], S43, 0x2AD7D2BB) # 63
        b = XX(I, b, c, d, a, inp[ 9], S44, 0xEB86D391) # 64

        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff

        self.A, self.B, self.C, self.D = A, B, C, D


    # Down from here all methods follow the Python Standard Library
    # API of the md5 module.

    def update(self, inBuf):
        """Add to the current message.

        Update the md5 object with the string arg. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments, i.e. m.update(a); m.update(b) is equivalent
        to m.update(a+b).
        """

        leninBuf = int(len(inBuf))

        # Compute number of bytes mod 64.
        index = (self.count[0] >> 3) & 0x3F

        # Update number of bits.
        self.count[0] = self.count[0] + (leninBuf << 3)
        if self.count[0] < (leninBuf << 3):
            self.count[1] = self.count[1] + 1
        self.count[1] = self.count[1] + (leninBuf >> 29)

        partLen = 64 - index

        if leninBuf >= partLen:
            #self.input[index:] = map(None, inBuf[:partLen])
            self.input[index:] = inBuf[:partLen]
            self._transform(_bytelist2long(self.input))
            i = partLen
            while i + 63 < leninBuf:
                #self._transform(_bytelist2long(map(None, inBuf[i:i+64])))
                self._transform(_bytelist2long(inBuf[i:i+64]))
                i = i + 64
            else:
                #self.input = map(None, inBuf[i:leninBuf])
                self.input = inBuf[i:leninBuf]
        else:
            i = 0
            #self.input = self.input + map(None, inBuf)
            self.input += inBuf

def generate_cram_hash(password):
    """Return a CRAM-MD5 hash for dovecot
    """

    if len(password) > 64:
        password = hashlib.md5(password).digest()

    ipad = array.array("B", [0x36] * 64)
    opad = array.array("B", [0x5C] * 64)
    for i in range(len(password)):
        ipad[i] = ipad[i] ^ ord(password[i])
        opad[i] = opad[i] ^ ord(password[i])

    inner = MD5()
    inner.update(ipad.tostring())
    outer = MD5()
    outer.update(opad.tostring())

    hash = struct.pack('<LLLL', outer.A, outer.B, outer.C, outer.D) + struct.pack('<LLLL', inner.A, inner.B, inner.C, inner.D)

    return '{CRAM-MD5}' + hash.hex()

def dovecotpw(password):
    return generate_cram_hash(password)
