import socket
import os
import pkt
import struct
import time
import fcntl
import select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI=0x0
IP = "10.10.10.10"
DEV = "ens33"
MTU = 1200
MAGIC = "zby"
REQ = 8
RPY = 0
SER_IP = "192.168.111.139"
TIME_OUT = 120

class tun():

    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifname = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN|IFF_NO_PI))
        self.name = ifname[:16].strip("\x00")

    def config(self):
        self.ip = IP
        self.tunip = "10.0.0.1"
        #os.system("ifconfig %s  %s pointopoint %s up" % (self.name, self.ip, self.tunip))
        os.system("ifconfig %s  %s up" % (self.name, self.ip))
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

        seqNO = 1
        iden = 0x1234

        while True:
            
            rst = select.select([self.icmpfd, self.tfd], [], [], TIME_OUT)[0]
            for fd in rst:

                if fd == self.icmpfd:
                    #reply data from the server
                    buf = self.icmpfd.recv(1500)

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
                    data = os.read(self.tfd, MTU)
                    icmpkt = pkt.icmp()
                    buf = icmpkt.create(RPY, 0, 0, iden, seqNO, MAGIC + data)
                    self.icmpfd.sendto(buf, (SER_IP, 0))
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
        os.system("route add -net 10.10.10.0/24 dev %s" % self.name)
        #os.system("ip link set %s mtu %s"%(DEV, MTU))
        os.system("iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o %s -j MASQUERADE"% DEV)
        #os.system("route add default gw 192.168.122.1 dev virbr0")
        #os.system("iptables -t nat -A PREROUTING -i %s -p icmp -j DNAT --to-destination %s", (DEV, self.tunip))
        pass
        
    def end(self): 
        os.system("route del -net 10.10.10.0/24 dev %s" % self.name)
        #os.system("ip link set %s mtu %s"%(DEV, 1500))
        os.system("iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o %s -j MASQUERADE"% DEV)
        #os.system("route del default")
        #os.system("iptables -t nat -D PREROUTING -i %s -p icmp -j DNAT --to-destination %s", (DEV, self.tunip))
        #os.close(self.fd)
        pass
        
    def start(self):

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        client = {}
        #this place should set a while to infinite loop
        while True:
            rst = select.select([self.icmpfd, self.tfd], [], [], TIME_OUT)[0]

        #while True:

            for fd in rst:

                if fd == self.tfd:
                    #this message from a webip
                    data = os.read(self.tfd, MTU)
                    appkt = pkt.ip()
                    appkt.parse(data[4:])
                    print client 
                    print (appkt.adst, appkt.asrc)
                    for t_id in client:
                        if client[t_id]["appsip"] == appkt.ndst:
                            #find which clinet requested this message
                            
                            icmpkt = pkt.icmp()
                            buf = icmpkt.create(RPY, 0, 0, client[t_id]["iden"], client[t_id]["seq"], MAGIC+data)
                            self.icmpfd.sendto(buf, (client[t_id]["ip"], 0))
                            break
                            
                elif fd == self.icmpfd:
                    #this message from a client
                    
                    data = self.icmpfd.recv(MTU)
                    
                    ipkt = pkt.ip()
                    buf = ipkt.parse(data)
                    
                    icmpkt = pkt.icmp()
                    buf = icmpkt.parse(buf)
                    #print icmpkt._type, buf[:3]
                    if icmpkt._type == RPY and buf[:3] == MAGIC:
                        #this is a tunnel request, 3 is the length of MAGIC
                        appkt = pkt.ip()
                        appkt.parse(buf[7:])
                        
                        ID = struct.pack("4sH",ipkt.nsrc, icmpkt.iden)
                        print appkt.asrc, appkt.adst
                        #print buf[3:]
                        print ipkt.asrc, ipkt.adst
                        client[ID] = {"ip": ipkt.asrc, "iden": icmpkt.iden, "seq": icmpkt.seqNO, "appdip": appkt.ndst, "appsip":appkt.nsrc}
                        os.write(self.tfd, buf[3:])
                    else:
                        pass
                        #recieve but do nothing, flush the buf
                else:
                    #select time out not client connect. clear the data
                    client = {}

#icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
t = tun_s()
t.create()
t.config()
t.set_rule()

try:
    t.start()
    
except KeyboardInterrupt:
    t.end()
    t.close()