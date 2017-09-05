
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr

log = core.getLogger()

class RouterExercise(object):
	"""docstring for ClassName"""
	def __init__(self, connection):
		self.connection = connection
		connection.addListeners(self)
		self.mac_to_port = {}
		self.route_table = {
		'10.0.1.1' : ['00:00:00:00:00:11', '10.0.1.0/24', 'R', 3],
		'10.0.1.2' : ['00:00:00:00:00:01', '10.0.1.0/24', 'H', 1],
		'10.0.1.3' : ['00:00:00:00:00:02', '10.0.1.0/24', 'H', 2],
		'10.0.2.1' : ['00:00:00:00:00:22', '10.0.2.0/24', 'R', 1],
		'10.0.2.2' : ['00:00:00:00:00:03', '10.0.2.0/24', 'H', 2]}
		self.deny = [('00:00:00:00:00:11','00:00:00:00:00:01')]


	def send_Packet(self, frame, out_port):
				if (str(frame.src), str(frame.dst)) in self.deny:
						self.act_like_firewall(frame)
				else:
					msg = of.ofp_packet_out()
					msg.data = frame.pack()
					action = of.ofp_action_output(port = out_port)
					msg.actions.append(action)
					self.connection.send(msg)

	def ARP_Request_handler(self, packet, packet_in):

		ARP_Dst = self.route_table.get(str(packet.payload.protodst))
		#host -> host
		if ARP_Dst[2] == 'H':
			packet.dst = adr.EthAddr(ARP_Dst[0])
			self.send_Packet(frame = packet, out_port = ARP_Dst[3])
		#host -> router
		elif ARP_Dst[2] == 'R':
			if str(packet.payload.protodst) == '10.0.1.1':
				arp_reply = pkt.arp()
				arp_reply.hwsrc = adr.EthAddr('00:00:00:00:00:11')
				arp_reply.hwdst = packet.payload.hwsrc
				arp_reply.opcode = pkt.arp.REPLY
				arp_reply.protosrc = packet.payload.protodst
				arp_reply.protodst = packet.payload.protosrc
				#make ARP packet -> Frame
				ether = pkt.ethernet()
				ether.type = pkt.ethernet.ARP_TYPE
				ether.dst = packet.src
				ether.src = packet.dst
				ether.payload = arp_reply
				#send Frame
				self.send_Packet(frame = ether, out_port = packet_in.in_port)
			
			elif str(packet.payload.protodst) == '10.0.2.1':
				arp_reply = pkt.arp()
				arp_reply.hwsrc = adr.EthAddr('00:00:00:00:00:22')
				arp_reply.hwdst = packet.payload.hwsrc
				arp_reply.opcode = pkt.arp.REPLY
				arp_reply.protosrc = packet.payload.protodst
				arp_reply.protodst = packet.payload.protosrc
				#make ARP packet -> Frame
				ether = pkt.ethernet()
				ether.type = pkt.ethernet.ARP_TYPE
				ether.dst = packet.src
				ether.src = packet.dst
				ether.payload = arp_reply
				#send Frame
				self.send_Packet(frame = ether, out_port = packet_in.in_port)							

	def ARP_Reply_handler(self, packet, packet_in):
		#dstip_add
		ARP_Dst = self.route_table.get(str(packet.payload.protodst))
		if ARP_Dst[2] == 'H':
			packet.dst = adr.EthAddr(ARP_Dst[0])
			self.send_Packet(frame = packet, out_port = ARP_Dst[3])

	def ICMP_Request_handler(self, packet, packet_in):
		ip_packet = packet.payload
		icmp_segment = ip_packet.payload

		ipSrcAdd = self.route_table.get(str(ip_packet.srcip))
		ipDstAdd = self.route_table.get(str(ip_packet.dstip))
                
		if ipDstAdd != None:
			if str(packet.dst) == '00:00:00:00:00:11':
				if str(ip_packet.dstip) == '10.0.1.1':
					echo_segment = pkt.echo()
					echo_segment.seq = icmp_segment.payload.seq + 1
					echo_segment.id = icmp_segment.payload.id
					#icmp packt|echo
					icmp_reply = pkt.icmp()
					icmp_reply.type = pkt.TYPE_ECHO_REPLY
					icmp_reply.payload = echo_segment
					#ip packet|icmp|echo
					ip_pack = pkt.ipv4()
					ip_pack.srcip = ip_packet.dstip
					ip_pack.dstip = ip_packet.srcip
					ip_pack.protocol = pkt.ipv4.ICMP_PROTOCOL
					ip_pack.payload = icmp_reply
					#frame|ip|icmp|echo
					ether_pack = pkt.ethernet()
					ether_pack.dst = packet.src
					ether_pack.src = packet.dst
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.payload = ip_pack
					self.send_Packet(frame = ether_pack, out_port = packet_in.in_port)

				elif ipDstAdd[1] == '10.0.1.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr(ipDstAdd[0])
					ether_pack.payload = packet.payload
					self.send_Packet(frame = ether_pack, out_port = ipDstAdd[3])

				elif ipDstAdd[1] == '10.0.2.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr('00:00:00:00:00:22')
					ether_pack.payload = packet.payload
					self.send_Packet(frame = ether_pack, out_port = 3)

			elif str(packet.dst) == '00:00:00:00:00:22':
				#echo rely to source
				if str(ip_packet.dstip) == '10.0.2.1':
					echo_segment = pkt.echo()
					echo_segment.seq = icmp_segment.payload.seq + 1
					echo_segment.id = icmp_segment.payload.id
					#icmp packt|echo
					icmp_reply = pkt.icmp()
					icmp_reply.type = pkt.TYPE_ECHO_REPLY
					icmp_reply.payload = echo_segment
					#ip packet|icmp|echo
					ip_pack = pkt.ipv4()
					ip_pack.srcip = ip_packet.dstip
					ip_pack.dstip = ip_packet.srcip
					ip_pack.protocol = pkt.ipv4.ICMP_PROTOCOL
					ip_pack.payload = icmp_reply
					#frame|ip|icmp|echo
					ether_pack = pkt.ethernet()
					ether_pack.dst = packet.src
					ether_pack.src = packet.dst
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.payload = ip_pack
					self.send_Packet(frame = ether_pack, out_port = packet_in.in_port)
				
				elif ipDstAdd[1] == '10.0.2.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr(ipDstAdd[0])
					ether_pack.payload = packet.payload
					self.send_Packet(frame = ether_pack, out_port = ipDstAdd[3])
				
				elif ipDstAdd[1] == '10.0.1.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr('00:00:00:00:00:11')
					ether_pack.payload = packet.payload
					self.send_Packet(frame = ether_pack, out_port = 1)
			else:
				self.send_Packet(frame = packet, out_port = ipDstAdd[3])
		else:
			unreachPacket = pkt.unreach()
			unreachPacket.payload = packet.payload

			icmp_unreReply = pkt.icmp()
			icmp_unreReply.type = pkt.TYPE_DEST_UNREACH
			icmp_unreReply.payload = unreachPacket

			ip_unrePack = pkt.ipv4()
			ip_unrePack.srcip = ip_packet.dstip
			ip_unrePack.dstip = ip_packet.srcip
			ip_unrePack.protocol = pkt.ipv4.ICMP_PROTOCOL
			ip_unrePack.payload = icmp_unreReply

			ether_unrePack = pkt.ethernet()
			ether_unrePack.src = packet.dst
			ether_unrePack.dst = packet.src
			ether_unrePack.type = pkt.ethernet.IP_TYPE
			ether_unrePack.payload = ip_unrePack								

			self.send_Packet(frame = ether_unrePack, out_port = packet_in.in_port)

	def ICMP_Reply_handler(self, packet, packet_in):
		ip_packet = packet.payload
		ipSrcAdd = self.route_table.get(str(ip_packet.srcip))
		ipDstAdd = self.route_table.get(str(ip_packet.dstip))

		if str(packet.dst) == '00:00:00:00:00:11':
			if ipDstAdd[1] == '10.0.1.0/24':
				ether_pack = pkt.ethernet()
				ether_pack.type = pkt.ethernet.IP_TYPE
				ether_pack.src = packet.dst
				ether_pack.dst = adr.EthAddr(ipDstAdd[0])
				ether_pack.payload = packet.payload
				self.send_Packet(frame = ether_pack, out_port = ipDstAdd[3])

			elif ipDstAdd[1] == '10.0.2.0/24':
				ether_pack = pkt.ethernet()
				ether_pack.type = pkt.ethernet.IP_TYPE
				ether_pack.src = packet.dst
				ether_pack.dst = adr.EthAddr('00:00:00:00:00:22')
				ether_pack.payload = packet.payload
				self.send_Packet(frame = ether_pack, out_port = 3)
		elif str(packet.dst) == '00:00:00:00:00:22':
			if ipDstAdd[1] == '10.0.2.0/24':
				ether_pack = pkt.ethernet()
				ether_pack.type = pkt.ethernet.IP_TYPE
				ether_pack.src = packet.dst
				ether_pack.dst = adr.EthAddr(ipDstAdd[0])
				ether_pack.payload = packet.payload
				self.send_Packet(frame = ether_pack, out_port = ipDstAdd[3])
			elif ipDstAdd[1] == '10.0.1.0/24':
				ether_pack = pkt.ethernet()
				ether_pack.type = pkt.ethernet.IP_TYPE
				ether_pack.src = packet.dst
				ether_pack.dst = adr.EthAddr('00:00:00:00:00:11')
				ether_pack.payload = packet.payload
				self.send_Packet(frame = ether_pack, out_port = 1)
		else:
			self.send_Packet(frame = packet, out_port = ipDstAdd[3])

	def IP_handler(self, packet, packet_in):
		ip_packet = packet.payload
		ipSrcAdd = self.route_table.get(str(ip_packet.srcip))
		ipDstAdd = self.route_table.get(str(ip_packet.dstip))

		if (str(packet.src), str(packet.dst)) in self.deny:
			self.act_like_firewall(packet)
		else:
			if str(packet.dst) == '00:00:00:00:00:11':
				if ipDstAdd[1] == '10.0.1.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr(ipDstAdd[0])
					ether_pack.payload = packet.payload
					msg = of.ofp_flow_mod()
					msg.match.in_port = packet_in.in_port
					msg.match = of.ofp_match.from_packet(packet)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(ipDstAdd[0])))
					msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
					msg.actions.append(of.ofp_action_output( port = ipDstAdd[3]))
					self.connection.send(msg)

				elif ipDstAdd[1] == '10.0.2.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr('00:00:00:00:00:22')
					ether_pack.payload = packet.payload
					msg = of.ofp_flow_mod()
					msg.match.in_port = packet_in.in_port
					msg.match = of.ofp_match.from_packet(packet)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(ipDstAdd[0])))
					msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
					msg.actions.append(of.ofp_action_output( port = 3))
					self.connection.send(msg)
			elif str(packet.dst) == '00:00:00:00:00:22':
				if ipDstAdd[1] == '10.0.2.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr(ipDstAdd[0])
					ether_pack.payload = packet.payload
					msg = of.ofp_flow_mod()
					msg.match.in_port = packet_in.in_port
					msg.match = of.ofp_match.from_packet(packet)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(ipDstAdd[0])))
					msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
					msg.actions.append(of.ofp_action_output( port = ipDstAdd[3]))
					self.connection.send(msg)
				elif ipDstAdd[1] == '10.0.1.0/24':
					ether_pack = pkt.ethernet()
					ether_pack.type = pkt.ethernet.IP_TYPE
					ether_pack.src = packet.dst
					ether_pack.dst = adr.EthAddr('00:00:00:00:00:11')
					ether_pack.payload = packet.payload
					msg = of.ofp_flow_mod()
					msg.match.in_port = packet_in.in_port
					msg.match = of.ofp_match.from_packet(packet)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(ipDstAdd[0])))
					msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
					msg.actions.append(of.ofp_action_output( port = 1))
					self.connection.send(msg)
			else:
				msg = of.ofp_flow_mod()
				msg.match.in_port = packet_in.in_port
				msg.match = of.ofp_match.from_packet(packet)
				msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(ipDstAdd[0])))
				msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
				msg.actions.append(of.ofp_action_output( port = ipDstAdd[3]))
				self.connection.send(msg)

	def act_like_router(self, packet, packet_in):

		if packet.type == pkt.ethernet.ARP_TYPE:
			if packet.payload.opcode == pkt.arp.REQUEST:
				self.ARP_Request_handler(packet, packet_in)
			elif packet.payload.opcode == pkt.arp.REPLY:
				self.ARP_Reply_handler(packet, packet_in)
			else:
				log.debug("----------unknow ARP----------")
		elif packet.type == pkt.ethernet.IP_TYPE:
			ip_packet = packet.payload
			if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
				icmp_segment = ip_packet.payload
				if icmp_segment.type == pkt.TYPE_ECHO_REQUEST:
					self.ICMP_Request_handler(packet, packet_in)
				elif icmp_segment.type == pkt.TYPE_ECHO_REPLY:
					self.ICMP_Reply_handler(packet, packet_in)
			else:
				self.IP_handler(packet, packet_in)
		# else:
		# log.debug("----------unknow packet----------")

	def act_like_firewall(self, packet):
	       	match = of.ofp_match()
       		match.dl_src = packet.dst
		match.dl_dst = packet.src
		msg = of.ofp_flow_mod()
		msg.match = match
		self.connection.send(msg)
			
	def _handle_PacketIn(self, event):
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp
		self.act_like_router(packet, packet_in)

def launch():
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		RouterExercise(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
		

