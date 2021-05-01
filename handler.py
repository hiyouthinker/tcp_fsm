#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''
from scapy.all import *

import tcp_state

def tcp_packet_handler(pkt):
	sip = pkt[IP].src
	dip = pkt[IP].dst
	sport = pkt[TCP].sport
	dport = pkt[TCP].dport
	flags = pkt[TCP].flags
	index = tcp_state.tcp_flags_check(flags)
	found = False

	print "[%s:%d => %s:%d], flags: %s (0x%x)" % (sip, sport, dip, dport, tcp_state.tcp_pkt_flags[index], flags)

	key = (sip, sport, dip, dport)

#	dict = tcp_state.sessions.get(key, False);
	if (tcp_state.sessions.has_key(key)) :
		found = True

	if (sport == 80 and dport != 80) :
		# This is packet from local host
		return

	# SYN
	if (index == 1):
		seq = random.randint(0, 4294967295)
		ack = pkt[TCP].seq + 1
		print "receive SYN, will insert the key/value to sessions"
		state = tcp_state.TCP_SYN_RECV
		value = (state, pkt[TCP].seq, 0, 0, 0)
		tcp_state.sessions.update({key : value})
		flags = tcp_state.tcp_flags_synack
	else :
		if (found == False) :
			print "Session was not found, receive non-SYN (%s), IGNORE" % tcp_state.tcp_pkt_flags[index]
			return
		else :
			value = tcp_state.sessions.get(key)
			state = value[0]
			if (state == tcp_state.TCP_FIN_WAIT):
				print "current state of session: %s/%s (first %s)" % (tcp_state.tcp_session_states[state]
					, tcp_state.tcp_session_substates[value[4] & 0x0f], tcp_state.tcp_session_destroy_first_pkt_dir[value[4] & 0xf0])
			else :
				print "current state of session: %s" % (tcp_state.tcp_session_states[state])
		# ACK
		if (index == 6):
			if (state == tcp_state.TCP_SYN_RECV):
				ip_hdr_len = pkt[IP].len - pkt[IP].ihl * 4
				tcp_hdr_len = pkt[TCP].dataofs * 4
				tcp_data_len = ip_hdr_len - tcp_hdr_len

				value = (tcp_state.TCP_ESTABLISHED, pkt[TCP].seq, pkt[TCP].ack, tcp_data_len)
				tcp_state.sessions.update({key : value})
				print "TCP 3-way handshake was completed successfully"
			return
		# PUSH or PUSH + ACK
		elif (index == 3):
			ip_hdr_len = pkt[IP].len - pkt[IP].ihl * 4
			tcp_hdr_len = pkt[TCP].dataofs * 4
			tcp_data_len = ip_hdr_len - tcp_hdr_len
			seq = pkt[TCP].ack
			ack = pkt[TCP].seq + tcp_data_len
			flags = tcp_state.tcp_flags_ack
			value = (value[0], pkt[TCP].seq, pkt[TCP].ack, tcp_data_len)
		# RST
		elif (index == 4):
			value = (tcp_state.TCP_FIN_WAIT, pkt[TCP].seq, pkt[TCP].ack, 0, tcp_state.TCP_SESSION_SUBSTATE_CLOSED | tcp_state.tcp_session_client_rst)
			tcp_state.sessions.update({key : value})
			return
		# FIN
		elif (index == 5):
			ip_hdr_len = pkt[IP].len - pkt[IP].ihl * 4
			tcp_hdr_len = pkt[TCP].dataofs * 4
			tcp_data_len = ip_hdr_len - tcp_hdr_len
			seq = pkt[TCP].ack
			# SYN or FIN need eat one sequence number
			ack = pkt[TCP].seq + tcp_data_len + 1
			flags = tcp_state.tcp_flags_finack
			value = (tcp_state.TCP_FIN_WAIT, pkt[TCP].seq, pkt[TCP].ack, tcp_data_len, tcp_state.TCP_SESSION_SUBSTATE_LAST_ACK | tcp_state.tcp_session_client_fin)
		else :
			print "Invalid Packet: %s/%d" % (tcp_state.tcp_pkt_flags[index], index)
			return

		# insert or update(seq, ack, state etc.)
		tcp_state.sessions.update({key : value})

	l3 = IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags=flags,seq=seq,ack=ack)
	send(l3, verbose=False)
