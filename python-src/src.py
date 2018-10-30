# -*- coding: utf-8 -*-
from socket import *
import time
import sys
import os
import getopt

CACHE_FILE = 'dnsrelay.txt'
DEFAULT_PORT = 53
HOST = '0.0.0.0'
FRW_HOST = '10.3.9.113'
OUTER_DNS_PORT = 53
BUFSIZE = 4096

def usage():
    print("Usage: %s  [ -f|-p|-F ] [ options ]", sys.argv[0])

def decodePacket(pack):
    url = ''
    index = 0
    ch = pack[index]
    ch = ord(ch)
    while ch != 0:
        for i in range(ch):
            index += 1
            url += pack[index]
        index += 1
        ch = pack[index]
        ch = ord(ch)
        if ch != 0:
            url = url + '.'
    return url

def encodePackect(remoteIP, msg):
    packet = []
    for ch in msg:
        packet.append(ch)

    packet[4:12] = ['\x00','\x01','\x00','\x01','\x00','\x00','\x00','\x00']

    packet = packet + ['\xc0','\x0c','\x00','\x01','\x00','\x01','\x00','\x00','\x02','\x58','\x00','\x04']

    netIp = inet_aton(remoteIP)

    iplist = [];
    for ch in netIp:
        iplist.append(ch)

    packet = packet + iplist
    return ''.join(packet) # convert to string


def loadCache(filename):
    hostmap = {}
    try:
        infile = open(filename)
    except:
        print("ERROR: canot open file!");
        os._exit(0);
    for line in infile.readlines():
        pair = line.strip().split(' ')
        hostmap[pair[1]] = pair[0]
    infile.close()
    return hostmap


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:p:F:", ["help"]);
        for opt , arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit(1)
    except getopt.GetoptError:
        print("getopt error")

    try:
        udpSerSock = socket(AF_INET, SOCK_DGRAM)
        udpSerSock.bind((HOST, DEFAULT_PORT))
    except:
        print("Error: create and bind socket failed")
    ipDict = loadCache(CACHE_FILE)

    clientWait = [] #(fromIp)
    clientKeyDict = {}#(请求标识+fromIp , 系统当时时间)
    clientAddrDict = {}#(系统当时时间 , (fromIp,fromPort))

    while True:
        try:
            data, (fromClient, fromPort) = udpSerSock.recvfrom(BUFSIZE)
        except:
            udpSerSock.close()
            os._exit(1)

        requestList = list(data)
        url= decodePacket(requestList[12:])

        if fromPort == OUTER_DNS_PORT:
            showIp = inet_ntoa(data[-4:])
            index = 0
            for client in clientWait:
                id_client = str(requestList[0])+str(requestList[1])+str(client)
                if id_client not in clientKeyDict:
                    continue
                time_key = clientKeyDict[id_client]
                if time_key in clientAddrDict :
                    udpSerSock.sendto(data,clientAddrDict[time_key])

                    del clientWait[index]
                    del clientKeyDict[id_client]
                    del clientAddrDict[time_key]
                    break
                index += 1

        else:
            if url in ipDict:
                if ipDict[url] == '0.0.0.0':
                    answerMsg = encodePackect(ipDict[url], data)
                    udpSerSock.sendto(answerMsg, (fromClient, fromPort))
                else:
                    answerMsg = encodePackect(ipDict[url], data)
                    udpSerSock.sendto(answerMsg, (fromClient, fromPort))
            else:
                udpSerSock.sendto(data, (FRW_HOST, OUTER_DNS_PORT))
                time_key = time.strftime('%Y-%m-%d %H:%m:%s',time.localtime(time.time()))
                clientKeyDict[str(requestList[0])+str(requestList[1])+str(fromClient)] = time_key
                clientAddrDict[time_key] = (fromClient,fromPort)
                if fromClient not in clientWait:
                    clientWait.append(fromClient)

