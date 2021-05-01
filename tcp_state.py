#! /usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''

tcp_flags_fin=0x01
tcp_flags_syn=0x02
tcp_flags_rst=0x04
tcp_flags_psh=0x08
tcp_flags_ack=0x10

tcp_flags_synack=(tcp_flags_syn|tcp_flags_ack)
tcp_flags_pshack=(tcp_flags_psh|tcp_flags_ack)
tcp_flags_finack=(tcp_flags_fin|tcp_flags_ack)
tcp_flags_rstack=(tcp_flags_rst|tcp_flags_ack)

TCP_SYN_SENT = 1
TCP_SYN_RECV = 2
TCP_ESTABLISHED = 3
TCP_FIN_WAIT = 4

# packet & direction
tcp_session_client_rst = 0x10
tcp_session_server_rst = 0x20
tcp_session_client_fin = 0x30
tcp_session_server_fin = 0x40

# recv fin -> send fin & ack
TCP_SESSION_SUBSTATE_LAST_ACK = 1
# recv ack
TCP_SESSION_SUBSTATE_CLOSED = 2
# send fin and wait ack
TCP_SESSION_SUBSTATE_FIN_WAIT1 = 3
# recv ack and wait fin
TCP_SESSION_SUBSTATE_FIN_WAIT2 = 4
# recv ack
TCP_SESSION_SUBSTATE_TIME_WAIT = 5

'''
	key
		sip, sport, dpi, dport
	value
		state, last seq, last ack, last TCP paylaod length, flags
'''
sessions = {}
tcp_pkt_flags = {0 : "No Flags", 1 : "SYN", 2 : "SYN + ACK", 3 : "PSH", 4 : "RST", 5 : "FIN", 6 : "ACK"}
tcp_session_states = {
	TCP_SYN_SENT : "TCP_SYN_SENT",
	TCP_SYN_RECV : "TCP_SYN_RECV",
	TCP_ESTABLISHED : "TCP_ESTABLISHED",
	TCP_FIN_WAIT : "TCP_FIN_WAIT",
}

tcp_session_substates = {
	TCP_SESSION_SUBSTATE_LAST_ACK : "LAST_ACK",
	TCP_SESSION_SUBSTATE_CLOSED : "CLOSED",
	TCP_SESSION_SUBSTATE_FIN_WAIT1 : "FIN_WAIT1",
	TCP_SESSION_SUBSTATE_FIN_WAIT2 : "FIN_WAIT2",
	TCP_SESSION_SUBSTATE_TIME_WAIT : "RIME_WAIT",
}

tcp_session_destroy_first_pkt_dir = {
	tcp_session_client_rst : "RST From Client",
	tcp_session_server_rst : "RST From Server",
	tcp_session_client_fin : "FIN From Client",
	tcp_session_server_fin : "FIN From server",
}

def tcp_flags_check(flags):
	if (flags & tcp_flags_syn):
		if (flags & tcp_flags_ack):
			return 2
		return 1
	elif (flags & tcp_flags_psh):
		return 3
	elif (flags & tcp_flags_rst):
		return 4
	elif (flags & tcp_flags_fin):
		return 5
	elif (flags & tcp_flags_ack):
		return 6
	else :
		return 0
