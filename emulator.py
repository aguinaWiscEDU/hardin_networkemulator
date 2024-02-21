"""
emulator.py

Created on Sun 12 Nov 14:22:16



"""

#imports
import socket
import argparse
import struct
import sys
import datetime
import ipaddress
import queue
import time
import random


#GLOBAL LIST
# -- OUR IP VALUES --
myIpName = socket.gethostname() #Name of the machine : ie mumble01, royal-02, vm-instunix-15
myIpAddr = socket.gethostbyname(myIpName) #The ip address based upon name (in format 0.0.0.0)
myIpAddrLong = int(ipaddress.ip_address(myIpAddr)) #converted long of our ip address (used in pack)

class QObject:
	def __init__(self, nextIp, nextPort, packet, delay, losProb):
		self.nextIp = nextIp
		self.nextPort = nextPort
		self.packet = packet
		self.delay = delay
		self.losProb = losProb


class Emulator:

	def __init__(self, forwarding_table_file, queue_size, log):
		self.forwarding_table = self.read_table(forwarding_table_file)
		self.queue1 = queue.Queue(queue_size)
		self.queue2 = queue.Queue(queue_size)
		self.queue3 = queue.Queue(queue_size)
		self.MAX_QUEUE_SIZE = queue_size
		self.LOG_FILE = log
	
	def bind(self, ip_address, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((ip_address, port))
		
		return sock
		
	def read_table(self, filename):

		table = []
		
		with open(filename, 'r') as file:
			for line in file:
				emulator_hostname, emulator_port, dest_hostname, dest_port, nexthop_hostname, nexthop_port, delay, loss_prob = line.split()
				table.append(((emulator_hostname, emulator_port), (dest_hostname, dest_port), (nexthop_hostname, nexthop_port), int(delay), float(loss_prob)))
		
		print(table)		
		
		return table

	def create_packet(self, priority, src_ip, src_port, dest_ip, dest_port, p_type, seq_no, payload):
			
		length = len(payload)
		
		pack_help = str(length) + 's'
		
		p_type = p_type.encode()
		payload = payload.encode()
		seq_no = socket.htonl(seq_no)
		
		packed_src_ip = socket.inet_aton(src_ip)
		packed_dest_ip = socket.inet_aton(dest_ip)
		
		inner_packet = struct.pack("!cII{}" .format(pack_help), p_type, seq_no, length, payload)
		
		inner_packet_format = "!cII{}" .format(pack_help)
		inner_packet_length = struct.calcsize(inner_packet_format)

		outer_header = struct.pack("!B4sH4sHI", priority, packed_src_ip, src_port, packed_dest_ip, dest_port, inner_packet_length)
		
		full_packet = outer_header + inner_packet
		
		return full_packet
		
	
	def unpack_packet(self, full_packet):
		
		outer_header_format = "!B4sH4sHI"
		inner_header_format = "!cII"
		outer_header_size = struct.calcsize(outer_header_format)
		inner_header_size = struct.calcsize(inner_header_format)
		outer_header_values = struct.unpack(outer_header_format, full_packet[:outer_header_size])
		
		priority, packed_src_ip, src_port, packed_dest_ip, dest_port, inner_pack_length = outer_header_values
		
		#print(outer_header_size)
		
		src_ip = socket.inet_ntoa(packed_src_ip)
		dest_ip = socket.inet_ntoa(packed_dest_ip)
		
		#print("Outer Header Vals: ", priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length)
		
		p_type, seq_no, payload_len  = struct.unpack('!cII', full_packet[outer_header_size:(outer_header_size + inner_header_size)])
		
		p_type = p_type.decode()
		seq_no = socket.ntohl(seq_no)
		
		#print("Inner Header Values: ", p_type, seq_no, payload_len)
		
		return priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length, p_type, seq_no, payload_len

	def route_packet(self, priority, dest_address, packet, PORT):

		for entry in self.forwarding_table:
			#grab the entry values
			emIp, emPort = entry[0]

			emPort = int(emPort)


			#if the emulatorIp and emulatorPort do not match we go to the next entry
			if emIp != myIpName or emPort != PORT:
				print("not found in table")
				continue
			else:
				#print("found entry")
				desIp, desPort = entry[1]
				
				desIp = socket.gethostbyname(desIp)
				print(desIp)
				print(dest_address)

				hopIp, hopPort = entry[2]

				delay = entry[3]

				losProb = entry[4]

				#if the dest_address matches the desIp, we check the queue
				if dest_address == desIp:
					#print("destIPs match")

					myQ = self.findQ(priority)

					#if the queue is full, return
					if myQ.full():
						time = get_time()
						return False, 1, time

					#we can pack the queue
					#STEP 1 -> BUild the QObjet
					qObj = QObject(hopIp, hopPort, packet, delay, losProb)
						
					"""
					#test prints so we know we got the items
					print(qObj.nextIp)
					print(qObj.nextPort)
					print(qObj.packet)
					print(qObj.delay)
					print(qObj.losProb)
					"""
					#check queue
					#print(myQ.empty())

					#next, we enqueue the qObj to its respective queue
					myQ.put(qObj)

					#print to check
					#print(myQ)

					#print(myQ.empty())

					#since we've successfully enqueued, return true
					return True, -1, get_time()
					

		#if we've reached the end, dest has not been found. return False so we can log
		time = get_time()
		return False, 0, time

	"""
	fucntion to send the packet. It will first check the queues and will send a packet based on 
	whats in prio (1 > 2 > 3). It then will pull the qObject, sleep for its wait time, then 
	based upon probability, will drop the packet or send it
	"""
	def sendPacket(self, sock, pType):
		#setup the queue to pull from
		myQ = self.grabQ()

		#if the queue is None, return false
		if myQ is None:
			print("q's empty")
			return False, -1, get_time() 
		
		qObj = myQ.get()

		#print checks
		#print(qObj.nextIp)
		#print(qObj.nextPort)
		#print(qObj.packet)
		#print(qObj.delay)
		#print(qObj.losProb)

		#print("before del" + get_time())

		#if the delay is > 0 sleep
		if qObj.delay > 0:
			time.sleep(qObj.delay)
		
		#print("post delay" + get_time())
		
		#if the packet type is not "E" we calculate drop probability (end pkts never drop)
		if pType != "E":
			#test print
			print("type is not E, calculate drop probability")

			#determine from probability if we drop
			lossProb = float(qObj.losProb)

			targetVal = random.uniform(0, 1)

			#print(targetVal)

			if targetVal < lossProb or targetVal == lossProb:
				print("packet to be dropped")
				return False, 2, get_time()
		
		else:
			print("END PACKET REACHED")
			print(pType)

		#send the packet!
		nextIp = socket.gethostbyname(qObj.nextIp)
	
		print("Packet Type: ", pType, " SENT TO: ", qObj.nextIp, " | ", qObj.nextPort)
		
		nextPort = int(qObj.nextPort)

		sock.sendto(qObj.packet, (nextIp, nextPort))

		#we've sent the pkt, return
		#print("pkt sent")
		
		return True, -1, get_time()

	"""
	Given a priority, match the queue
	"""
	def findQ(self, prio):
		match prio:
			case 1:
				return self.queue1
			case 2:
				return self.queue2
			case 3:
				return self.queue3
	"""
	Given the sendPkt, find the queue to pull from (1 is first, then if empty 2 is next, then 3)

	"""
	def grabQ(self):
		if not self.queue1.empty():
			return self.queue1
		elif not self.queue2.empty():
			return self.queue2
		elif not self.queue3.empty():
			return self.queue3
		else:
			return None


	"""
	DEFINING THE LOGGING FCNS
	"""
	def destNotFound(self, myIp, myPort, destIp, destPort, time, pri, data):
		f = open(self.LOG_FILE, 'w')

		f.write("PACKET DROP: Destination not found in table => SOURCE HOST - " + str(myIp) + " | SOURCE PORT - " + str(myPort) + " | DEST HOST - " + str(destIp) +
				" | DEST PORT - " + str(destPort) + " | TIME LOST - " + str(time) + " | PRIORITY OF PACKET - " + str(pri) + " | PAYLOAD LENGTH - " + str(data))

		f.close()

	def qFull(self, myIp, myPort, destIp, destPort, time, pri, data):
		f = open(self.LOG_FILE, 'w')

		f.write("PACKET DROP: Queue is FULL => SOURCE HOST - " + str(myIp) + " | SOURCE PORT - " + str(myPort) + " | DEST HOST - " + str(destIp) +
				" | DEST PORT - " + str(destPort) + " | TIME LOST - " + str(time) + " | PRIORITY OF PACKET - " + str(pri) + " | PAYLOAD LENGTH - " + str(data))

		f.close()


	def netDrop(self, myIp, myPort, destIp, destPort, time, pri, data):
		f = open(self.LOG_FILE, 'w')

		f.write("PACKET DROP: Packet lost due to network error => SOURCE HOST - " + str(myIp) + " | SOURCE PORT - " + str(myPort) + " | DEST HOST - " + str(destIp) +
				" | DEST PORT - " + str(destPort) + " | TIME LOST - " + str(time) + " | PRIORITY OF PACKET - " + str(pri) + " | PAYLOAD LENGTH - " + str(data))





def get_time():
	now = datetime.datetime.now()
	hours = now.hour
	minutes = now.minute
	seconds = now.second
	milliseconds = now.microsecond // 1000
	return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"

def main():
	#setup the parser for the emulator
	parser = argparse.ArgumentParser(prog='PROG', prefix_chars='-')

	#adding args
	parser.add_argument('-p') #Port -> port in which the emulator waits for packets
	parser.add_argument('-q') #QueueSize -> the size of each of the three queues
	parser.add_argument('-f') #Filename -> the name of the file that has all the static forwarding table
	parser.add_argument('-l') #Log -> the name of the log file we write to on errors

	args = parser.parse_args()

	PORT = int(args.p)
	QUEUE_SIZE = int(args.q)
	TABLE_NAME = args.f
	LOG_NAME = args.l

	#bind ourselves
	emulator = Emulator(TABLE_NAME, QUEUE_SIZE, LOG_NAME)
	sock = emulator.bind(myIpAddr, PORT)
	
	print("Bound at -> ", myIpAddr, " w/ port -> ", PORT, "\n")    

	while True:
		
		try:
					
			fullPacket, addr = sock.recvfrom(4092)
			
			sock.settimeout(.05) 
			
			print("fullPacket received!")
		
			priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length, p_type, seq_no, payload_len = emulator.unpack_packet(fullPacket)

			#take items and route the packet
			canRoute, flag, ts = emulator.route_packet(priority, dest_ip, fullPacket, PORT)
			print(canRoute)
			#if canRoute is False, we log the error based on flag
			if not canRoute:
				if flag == 0:
				#dest not found
					emulator.destNotFound(myIpAddr, PORT, dest_ip, dest_port, ts, priority, payload_len)
			else:
				#queue is full
				emulator.qFull(myIpAddr, PORT, dest_ip, dest_port, ts, priority, payload_len)
		
		except Exception:
			isSent, flag, ts = emulator.sendPacket(sock, p_type)
			
			#if we've dropped, log to file
			if not isSent:
				emulator.netDrop(myIpAddr, PORT, dest_ip, dest_port, ts, priority, payload_len)


		print("done")	  
	

	

main()
