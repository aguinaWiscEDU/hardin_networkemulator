
import socket
import argparse
import struct
import sys
import datetime
import ipaddress

#GLOBAL LIST
# -- OUR IP VALUES --
myIpName = socket.gethostname() #Name of the machine ie could be mumble01, royal-02, vm-instunix (based upon the wisc csl machinies used)
myIpAddr = socket.gethostbyname(myIpName) #The ip address based upon our name (in format 0.0.0.0)
myIpAddrLong = int(ipaddress.ip_address(myIpAddr)) #A converted long of our ip address (used in the pkt)



"""
Class that will track port information about the packets sent from that specific host/port.
This will help with our print summary when the end packet is sent.
"""
class portClass:
	"""Class to house information for each port """
	name: int
	totalPackets: int
	total: int
	avgSec: int
	firstPacket: datetime
	lastPacket: datetime
	durationSec: datetime
	duration: datetime


	def __init__(self, name):
		self.name = name
		self.totalPackets = 0
		self.total = 0
		self.avgSec = 0

	def addPacket(self):
		self.totalPackets += 1
	
	def addSize(self, l):
		self.total += l

	def setFirstTimeStamp(self, t):
		self.firstPacket = t

	def setLastTimeStamp(self, t):
		self.lastPacket = t

	def calcTot(self):
		timeSlice = self.lastPacket - self.firstPacket
		self.duration = timeSlice.total_seconds() * 1000
		self.durationSec = timeSlice.total_seconds()
	   # print(self.duration)
	
	def calcAvg(self):
		if self.durationSec != 0:
			self.avgSec = self.totalPackets / self.durationSec
		else:
			self.avgSec = 0
		#print(self.avgSec)

"""
Method that returns a string value represenation of the current time.
Ensures we have ms granularity.
"""
def get_time():
	now = datetime.datetime.now()
	hours = now.hour
	minutes = now.minute
	seconds = now.second
	milliseconds = now.microsecond // 1000
	
	return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"


"""
Print the packet information for each request coming in.
"""
def printPkt(t, a, sq, l, d, ty):
	#check the type 
	if ty == "D":
		pktTy = "DATA"
	elif ty == "E":
		pktTy = "END"

	#print bound
	print("--------------------------------------------------------------------------------")
	print("PACKET RECIEVED")
	print(pktTy, "PACKET")
	print("Time: \t\t\t ", t)
	print("Host/Port: \t\t ", a[0], "|", a[1])
	print("Sequence Num: \t\t ", sq)
	print("Length (B): \t\t ", len(d))
	print("Payload: \t\t ", d[:4])
	print("--------------------------------------------------------------------------------\n")


"""
Ensuring the length of packet is byte encoded
"""
def enUTF(b):
	return len(b.encode('utf-8'))


"""
Everytime a packet is received, we invoke updateStats to update the portobjects information.
Depending on the circumstances:
	1. Set first timestamp (if we have 0 packets)
	2. Add a packet to our total count
	3. Add length to oru total length
	4. Set last timestamp, calculate total duration, and get avg PPS (when Pkt 'E' is received)
"""
def updateStats(t, a, d, l, ty):
	#find the object
	for pkt in l:
		if pkt.name == a[1]:
			
			#if this is the first packet, update time too
			if pkt.totalPackets == 0:
				pkt.setFirstTimeStamp(t)
				#print(pkt.firstPacket)

			#increment packetcount
			pkt.addPacket()
			#print(pkt.totalPackets)

			#increment length -> send it to def method first
			byte = enUTF(d)
			pkt.addSize(byte)
			
			#if this is the end packet, set the end stamp
			if ty == "E":
				pkt.setLastTimeStamp(t)
				pkt.calcTot()
				pkt.calcAvg()
			
"""
Print the summary of the packets
"""
def printSummary(l, a):
	#find object
	for pkt in l:
		if pkt.name == a[1]:
			print("--------------------------------------------------------------------------------")
			print("SUMMARY OF SENDER -> ", pkt.name)
			print("HOST/PORT: \t\t ", a[0], "|", a[1])
			print("TOTAL PACKETS: \t\t ", pkt.totalPackets)
			print("TOTAL LENGTH: \t\t ", pkt.total)
			print("AVG/S: \t\t\t ", pkt.avgSec)
			print("DURATION: \t\t ", pkt.duration)
			print("--------------------------------------------------------------------------------\n")

"""
Given a dictionary, file, and the requested file build a dictionary of all parts of the file
requested with their associated host & ports. 

fileName -> list of all files and their network details
myPorts -> dictionary to house each part of the file
targetFile -> the file being requested

returns a dictionary of Key(filenum), Value(host, port) pairs
"""
def buildRequests(fileName, targetFile):
	myPorts = {}

	# Try to open the file
	try:
		with open(fileName, 'r') as file:
			for line in file:
				(file_name, fileNum, host, port) = line.strip("\n").split(' ')
				if file_name == targetFile:
					fileNum = int(fileNum)
					if fileNum not in myPorts:
						myPorts[fileNum] = []

					myPorts[fileNum].append((host, port))
	except IOError:
		print("Error reading file")
		sys.exit(-1)

	return myPorts

def get_time():
	now = datetime.datetime.now()
	hours = now.hour
	minutes = now.minute
	seconds = now.second
	milliseconds = now.microsecond // 1000
	return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"

"""
Given the new packet structure in P2, we'll encapsulate the original packet into a larger packet for the emulator


"""

def create_packet(src_ip, src_port, dest_ip, dest_port, p_type, seq_no, window_length, payload):

	# NOTE -> Just commenting this out for now, feel free to reuse this if we feel its easier

	p_type = p_type.encode()
	payload = payload.encode()
	seq_no = socket.htonl(seq_no)
	
	inner_packet_format = "!cII8s"
	inner_packet_length = struct.calcsize(inner_packet_format)

	packed_src_ip = socket.inet_aton(src_ip)
	packed_dest_ip = socket.inet_aton(dest_ip)
	
	outer_header = struct.pack("!B4sH4sHI", 1, packed_src_ip, src_port, packed_dest_ip, dest_port, inner_packet_length)
	
	inner_packet = struct.pack("!cII8s", p_type, seq_no, window_length, payload)
	
	full_packet = outer_header + inner_packet
	
	return full_packet


def unpack_packet(full_packet):
	
	outer_header_format = "!B4sH4sHI"
	inner_header_format = "!cII"
	outer_header_size = struct.calcsize(outer_header_format)
	inner_header_size = struct.calcsize(inner_header_format)
	outer_header_values = struct.unpack(outer_header_format, full_packet[:outer_header_size])
	
	priority, packed_src_ip, src_port, packed_dest_ip, dest_port, inner_pack_length = outer_header_values
	
	src_ip = socket.inet_ntoa(packed_src_ip)
	dest_ip = socket.inet_ntoa(packed_dest_ip)
	
	# print("Outer Header Vals: ", priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length)
	
	p_type, seq_no, payload_len  = struct.unpack('!cII', full_packet[outer_header_size:(outer_header_size + inner_header_size)])
	
	unpack_help = '!' + str(payload_len) + 's'
	
	payload = struct.unpack(unpack_help, full_packet[(outer_header_size + inner_header_size):])
	
	p_type = p_type.decode()
	seq_no = socket.ntohl(seq_no)
	payload = payload[0].decode()
	#print("payload received is: " + payload)

	return priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length, p_type, seq_no, payload_len, payload


"""
Build a list of dictionaries to house the payload data of the packets for writing later
For now we setup the list, and the dictionary with key tuple (ID#, HostName), value tuple (seqNum, data) pairs
"""
def setupWrites(portInfo):
	myPayload = {}

	for key, values in portInfo.items():
		for value in values:
			#test prints if necessary
			#print("examining each value for creating payload dict\n")
			#print(key)
			#print(value[0])
			#print(value[1])

			#create a blank list
			myList = []
			
			#insert list into dict
			myPayload[key, value[0]] = myList

	#once completed, return the dict
	return myPayload
	

"""
Given a dictionary, host, seqNumber, and data we'll append our lists to add the data in a tuple (seqNum, data)
pair. Once completed before we exit we'll sort the list to ensure sequence is in order for printing. If the 
item already exists in our list (seqNum, data are found) we will print an error and abort the append process.
"""
def appendLists(payList, host, seqNum, data, pType):
	#if the packet type is E we return
	#if pType == 'E':
		#print("The end packet was found, Dropping")
		#return

	#print(host)
	host = socket.gethostbyaddr(host)
	#print("PRINTING HOST AT 0")
	#print(host[0])

	for keys, value in payList.items():
		target = host[0]
		#print(target)
		#if the hostname give is key at index 1 we can append
		if str(keys[1]) in target:
			print("host found, entering append")

			myList = value

			#build an item for search
			item = (seqNum, data)
			
			#If the item exists in our list, it means this is a duplicate packet we don't need.
			if data in myList:
				#report ERR to terminal
				print("WARING: packet has already be stored, aborting append\n")
				return

			#append value to the list
			myList.append(item)

			#sort list 
			myList.sort()
			
			#print list to ensure its sorted by seqNum
			#print(myList)

"""
Given a filename and dict of seqnum, data list we'll write the payloads of our packets to our file.
"""
def writeOut(payList, file):
	#openfile
	with open(file, "w") as f:
		for keys, value in payList.items():
			#grab the list
			myList = value

			#print to ensure we have it
			print("list grabbed -> ")
			print(myList)
			print("\n")
			#iterate over list
			for items in myList:
				#print("writing: " + items[1])

				#to ensure we're only writing the data write items at index 1
				f.write(items[1])
	f.close()


def main():
	print("starting")
	parser = argparse.ArgumentParser(prog='PROG', prefix_chars='-')
	
	parser.add_argument('-p') #port -> the port on which the requester waits for packets
	parser.add_argument('-o') #file -> the file the requester wishes to receive
	#adding new parser arguments -> p2
	parser.add_argument('-f') #f_hostname -> host of the emulator
	parser.add_argument('-e') #f_port -> the port of the emulator
	parser.add_argument('-w') #window -> the requester's window size
	
	args = parser.parse_args()
	
	PORT = int(args.p)
	FILE_OPTION = args.o
	F_HOSTNAME = args.f
	F_PORT = int(args.e)
	R_WINDOW = int(args.w)
	pktList = []

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((myIpAddr, PORT))

	#grab the host & ports for the requested file
	portInfo = buildRequests('tracker.txt', FILE_OPTION)
	print(portInfo)

	#portInfo is made, time to create our payList
	payList = setupWrites(portInfo)
	
	#print("before with open file")

	for key, values in portInfo.items():
		for value in values:
			# print("entered for loop")
			print(value)
			ipAddr = socket.gethostbyname(value[0])
			port = int(value[1])
	
			# print("past the for key, and IP")
			
			type_p = "R"
			seq_no = 0
	
			packet = create_packet(myIpAddr, PORT, ipAddr, port, type_p, seq_no, R_WINDOW, FILE_OPTION)
	
			#setup the emulator ip for sending
			emIp = socket.gethostbyname(F_HOSTNAME)
			sock.sendto(packet, (emIp, F_PORT))
			#print("sent packet to -> " + emIp + " at Port: " + str(F_PORT))
			
			#create the packet object, then send to the list
			p = portClass(port)
			
			if port not in pktList:
				pktList.append(p)
				
			while True:
				
				data, clientAddress = sock.recvfrom(4096)
				# print("packet received")
				priority, src_ip, src_port, dest_ip, dest_port, inner_pack_length, p_type, seq_no, payload_len, payload = unpack_packet(data)
			
				#packet is received, we can append our list!
				appendLists(payList, src_ip, seq_no, payload, p_type)

				if dest_ip != myIpAddr or dest_port != PORT:
					# print("This packet wasn't meant for me")
					sys.exit(-1)

				"""
				with open("payload.txt", 'a') as file:
					print("Writing payload -> " + payload) 
					file.write(payload)
					file.close()
				"""

				if p_type == 'E':
					# print("End packet recieved")
					break
					
				ackPacket = create_packet(myIpAddr, PORT, ipAddr, port, 'A', seq_no, 0, "		 ")
				sock.sendto(ackPacket, (emIp, F_PORT))
				
	
	print("Reached END OF PACKET DELIVERY")
	#we've reached the end of transmission of packets, write to file
	writeOut(payList, FILE_OPTION)

			


main()


'''

FROM P1
				udp_header = data[:9]
				p_type, seq_no, length = struct.unpack("!cII", udp_header)
				p_type = p_type.decode()
				seq_no = socket.ntohl(seq_no)
				
				fmt_help = '!' + str(length) + 's'
				
				payload = data[9:]
				payload = struct.unpack(fmt_help, payload)
	
				payload = payload[0].decode()





			#We're gonna comment this out for now just to test emulator
			
			"""
			while True:
				fullPacket = sock.recvfrom(2048)
				strTime = get_time()
				recTime = datetime.datetime.now()

				prio, fromIp, fromPort, targetIp, targetPort, innerLength, p_type, sqNum, datLength, data = unpack_packet(fullPacket)

				updateStats(recTime, fromIp, payload, pktList, p_type)

				ackPack = create_packet(myIpAddr, PORT, fromIp, fromPort, 'A', seq_no,	R_WINDOW, ackData)


				#once we've updated the stats, go ahead and send the ack
				sock.sendto(ackPack, (emIp, F_PORT))

				#if p_type == "D":
					#print(payload)

				#printPkt(strTime, addr, seq_no, length, payload, p_type)

				if p_type == "E":
					printSummary(pktList, emIp)
					
					break
					
				else:
					
					file.write(payload)

			"""

				'''
