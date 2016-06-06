import struct
import os
import ctypes
import socket
class icmp():
    def checksum(self, data_B):
        if len(data_B)/2:
            data_B + '\x00'

        data_H = struct.unpack("!%sH" % (len(data_B)/2), data_B)
        _sum = 0

        for data in data_H:
          
            _sum += data

        _sum = (_sum >> 16) + (_sum&0xffff)
        _sum += (_sum >> 16)
    
        return ctypes.c_ushort(~_sum).value
    
    def create(self, _type, code, cksum, iden, seqNO, data):

        pktfmt = "!BBHHH%ss" % len(data)
        args = [_type, code, cksum, iden, seqNO, data]
        args[2] = self.checksum(struct.pack(pktfmt, *args))
        return struct.pack(pktfmt, *args)

    def parse(self, data):
        pktfmt = "!BBHHH%ss" % len(data[8:])

        self._type, self.code, self.cksum, self.iden, self.NO, self.info = \
                struct.unpack(pktfmt, data)

        #print self._type, self.code, self.cksum, self.iden, self.NO, self.info

        return data[28:]

class ip():

    def parse(self, data):
	
	head_len = struct.unpack("B",data[0])

        head_len >>= 4
        head_len *= 4

        self.hlen = head_len
        self.datalen = len(data) - head_len

	src, dst = data[12: 16], data[16: 20]
        self.src = socket.inet_ntoa(self.src)
        self.dst = socket.inet_ntoa(self.dst)
        return data[head_len: ]
