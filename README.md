# DHCP

需要两台虚拟机分别运行客户端和服务器端，程序中具体的IP地址和网卡需根据实际情况自行修改。可以在ubuntu gcc下编译并运行，包含 DHCP 客户端和服务器端。程序比较简陋，有一些未完成的和处理不太合适的小地方。但其中程序的框架和所用到的数据结构有一定的参考意义。


## Overview

Dynamic Host Configuration Protocol (DHCP) is a client/server protocol that automatically provides an Internet Protocol (IP) host with its IP address and other related configuration information such as the subnet mask and default gateway. RFCs 2131 and 2132 define DHCP as an Internet Engineering Task Force (IETF) standard based on Bootstrap Protocol (BOOTP), a protocol with which DHCP shares many implementation details. DHCP allows hosts to obtain necessary TCP/IP configuration information from a DHCP server.

The goal of the project is to deeply understand the details of DHCP (Dynamic Host Configuration Protocol). And specific goal is as follows:
- Complete a DHCP server program and run it in one Ubuntu virtual machine.
- Complete a DHCP client program and run it in another Ubuntu virtual machine.

---

## Requirements Analysis

### Environmental Requirements

#### Operating System
Ubuntu 14.04.5 Server

#### Programming Language
Linux C language

#### Configuration Requirements
- For Client: Netcard “eth1” is for inter network, which does not has IP address.
- For Server: Netcard “eth1” is for inter network, which IP address is “192.168.0.1”. File “dhcp.config” saves available IP address in pool. “dhcp.lease” saves the IP lease data.

### Functional Requirements

- Support DHCP messages: 
DHCP operations fall into four phases: sever discovery, IP lease offer, IP lease request and IP lease acknowledgement. All these stages are completed through DHCP messages exchange. Supporting DHCP messages is the most basic requirements for this model.

- Support DHCP options: 
DHCP options are variable length octet strings. DHCP options contains special parameters closely related to  the process. A DHCP server can provide optional configuration parameters to the client, and a DHCP client can select, manipulate and overwrite these parameters.

- Four messages during address acquisition can be delivered on broadcast packets: 
DHCPDICOVER, DHCPOFFER, DHCPREQUEST and DHCPACK are used during address acquisition. Actually, DHCPOFFER and DHCPACK are delivered on unicast packets in usual case, but for simplicity, we assume all these packets are delivered through broadcast.

- Support DHCP procedures: 
All the operations in the program should follow the actual procedures in DHCP.

- DHCP Server functions: 
Listen to UDP port 67 . For first request, select free IP address from IP address pool and reply to client. For inform request, reply ACK with option value. IP range and value of option s are stored in IP address pool (dhcp.config file ) , Assigned IP, client mac address and time stamp are stored in IP lease pool (dhcp.lease file). Print log message DHCP client functionss.

- DHCP Client functions: 
Listen to UDP port 68 . User can specify command line arguments to con trol actions of client program. Print log messages.

---

## Module

- Client file : dhcpclient.c
- Server file : dhcpserver.c
- Common file: dhcp.h
- Configuration file: dhcp.lease, dhcp.config




