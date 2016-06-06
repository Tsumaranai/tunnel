import socket
import os
import pkt
import struct
import time
import fcntl
import select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IP = "10.10.10.10"
DEV = "eth0"
MTU = 1000
MAGIC = "zby"
REQ = 8
RPY = 0
SER_IP = "0.0.0.0"
TIME_OUT = 120

class tun():

    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifname = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN))
        self.name = ifname[:16].strip("\x00")

    def config(self):
        self.ip = IP
        self.tunip = "10.0.0.1"
        os.system("ifconfig %s  %s pointopoint %s up" % (self.name, self.ip, self.tunip))
        os.system("ip link set %s mtu %s" % (self.name, MTU))
    def ping_reply(self, iden, seqNO, data):        
        buf = pkt.create(0, 0, 0, iden, seqNO, data)
        return buf

    def close(self):
        os.close(self.tfd)
        exit()


class tun_c(tun):

    def send(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        icmpkt = pkt.icmp()
        data = "nihao" * 10
        data = struct.pack("!d50s", time.time(),data)
        data = icmpkt.create(8, 0, 0, 0x1234, 1, data)
        self.icmpfd.sendto(data, ("10.13.28.161", 2))

    def set_rule(self):
        os.system("ip addr add %s dev %s" % (self.ip, self.name))
        os.system("route add default dev %s" % (self.name))
        #not implentemt add a route to server only
        #os.system("iptables -t nat -A PREROUTING -i %s -p icmp  -j DNAT --to-destination %s"% (DEV, self.tunip))

    def start(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

        rst = select.select([self.icmpfd, self.tfd], [], [], TIME_OUT)[0]
        seqNO = 1
        iden = 0x1234

        while True:

            for fd in rst:

                if fd == self.icmpfd:
                    #reply data from the server
                    buf = os.read(fd, 1500)

                    ipkt = pkt.ip()
                    data = ipkt.parse(buf)
                    
                    icmpkt = pkt.icmp()
                    buf = icmpkt.parse(data)

                    if icmpkt._type == 0 and buf[:3] == MAGIC:
                        #this is our packet
                        os.write(self.tfd, buf[3:])
                    else:
                        pass

                elif fd == self.tfd:
                    #this is from our system kernel
                    data = os.read(fd, MTU)
                    buf = icmpkt.create(RPY, 0, 0, iden, seqNO, MAGIC + data)
                    self.icmpfd(buf, (SER_IP, 0))
                    seqNO += 1

                else:
                    #select time out do nothing
                    pass

    def end(self):
        os.system("route del default")
        #os.system("route add default dev eth0")
        #os.system("iptables -t nat -D PREROUTING -i %s -p icmp  -j DNAT --to-destination  %s"% (DEV, self.tunip))
        #os.close(self.fd)
        #exit()


class tun_s(tun):

    def set_rule(self):
        os.system("iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o %s -j MASQUERADE"% DEV)
        #os.system("iptables -t nat -A PREROUTING -i %s -p icmp -j DNAT --to-destination %s", (DEV, self.tunip))

    def end(self):
        os.system("iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o %s -j MASQUERADE"% DEV)
        #os.system("iptables -t nat -D PREROUTING -i %s -p icmp -j DNAT --to-destination %s", (DEV, self.tunip))
        #os.close(self.fd)

    def start(self):

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.client = {}
        #this place should set a while to infinite loop
        rst = select.select([self.icmpfd, self.tfd], [], [], TIME_OUT)[0]

        while True:

            for fd in rst:

                if fd == self.tfd:
                    #this message from a webip
                    data = os.read(fd, MTU)
                    appkt = pkt.ip()
                    appkt.parse(data)
                    for t_id in client:
                        
                        if client[t_id]["appsip"] == appkt.dst:
                            #find which clinet requested this message
                            icmpkt = pkt.icmp()
                            buf = icmpkt.create(RPY, 0, 0, client[t_ip]["iden"], client[t_ip]["seq"], MAGIC+data)
                            self.icmpfd.sendto(buf, (client[t_ip]["ip"], 0))
                            break
                            
                elif fd == self.icmpfd:
                    #this message from a client
                    
                    data = os.read(fd, MTU)
                    
                    ipkt = pkt.ip()
                    buf = ipkt.parse(data)
                    
                    icmpkt = pkt.icmp()
                    buf = icmpkt.parse(buf)
                    
                    if icmpkt._type == RPY and buf[:3] == MAGIC:
                        #this is a tunnel request, 3 is the length of MAGIC
                        appkt = pkt.ip()
                        appkt.parse(buf[3:])
                        
                        ID = struct.pack("4sH",(ipkt.src, icmpkt.iden))
                        client[ID] = {"ip": ipkt.asrc, "iden": icmpkt.iden, "seq": icmpkt.seqNO, "appdip": appkt.dst, "appsip":appkt.src}
                        os.write(self.tfd, buf[3:])
                    else:
                        pass
                        #recieve but do nothing, flush the buf
                else:
                    #select time out not client connect. clear the data
                    client = {}

#icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
while True:
    try:
        #buf, add = icmpfd.recvfrom(MTU)
        #print buf
    except KeyboardInterrupt:
        t.end()
        t.close()
