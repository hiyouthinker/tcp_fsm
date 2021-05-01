# tcp_fsm
TCP Finite State Machine
## 1 Introduction
```
This is a TCP FSM implemented based on Scapy
```
## 2 test
### 2.1 environment
```
   client    <-->   server
172.50.1.65       172.50.1.66

client
    None
server
    iptables -t filter -A INPUT -p tcp -m tcp --dport 80 -j DROP
```
### 2.2 start testing
```
server
    root@lab2:~/tcp_fsm# python main.py

client
    root@lab1:~# nc 172.50.1.66 80
```
### 2.3 results
```
root@lab2:~/tcp_fsm# python main.py
capture TCP packet of port 80 on eth1
[172.50.1.65:46114 => 172.50.1.66:80], flags: SYN (0x2)
receive SYN, will insert the key/value to sessions
[172.50.1.66:80 => 172.50.1.65:46114], flags: SYN + ACK (0x12)
[172.50.1.65:46114 => 172.50.1.66:80], flags: ACK (0x10)
current state of session: TCP_SYN_RECV
TCP 3-way handshake was completed successfully
session table: 1 item(s)
	[172.50.1.65:46114 => 172.50.1.66:80], state: TCP_ESTABLISHED
session table: 1 item(s)
	[172.50.1.65:46114 => 172.50.1.66:80], state: TCP_ESTABLISHED
```
