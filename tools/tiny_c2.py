#TinyLoader C2 POC script
#Jason Reaves
#March-2017

import sys
import time
import struct
import binascii
import socket

def send_msg(msg, addr):
	tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		tcpsock.connect(addr)
	except:
		print("Socket error")
		return None
	tcpsock.sendall(msg)

	ret = tcpsock.recv(12)
	rsize = struct.unpack_from('<I', ret[8:])[0]
	if rsize != 0:
		ret += tcpsock.recv(rsize-12)
	return ret

class C2_Data:
	def __init__(self, botnet, data="", version=32):
		self.botnet = struct.pack('<I', botnet)
		self.send_data = '\x00\x00\x00\x54'
		self.data = data
		if data == "":
			self.length = 12
		else:
			self.length = 12 + len(data)
		if version == 32:
			self.ver = '\x32'
		else:
			self.ver = '\x86'

	def set_data(self, data):
		self.data = data
		self.length = 12 + len(data)

	def set_send_data(self, data):
		self.send_data = data

	def build(self):
		ret_val = self.send_data
		ret_val += self.botnet
		ret_val += self.data
		ret_val += struct.pack('<H', self.length)
		ret_val += '\x00'+self.ver
		return ret_val

def decode(data):
	key = bytearray(data[4:8])
	blob = bytearray(data[12:])
	for i in range(len(blob)):
		blob[i] ^= key[i%len(key)]
	return(str(blob))


if __name__ == "__main__":
	ip = sys.argv[1]
	port = int(sys.argv[2])
	c2 = C2_Data(0x207715d3,version=64)
	done = False
	while not done:
		out = c2.build()
		print("Data Sent:"+binascii.hexlify(out))
		r = send_msg(out, (ip,port))
		if r == None:
			time.sleep(50)
			continue
		print("Data Received:"+binascii.hexlify(r))
		decoded = decode(r)
		print("Data Decoded:"+binascii.hexlify(decoded))
		offset = decoded.find('\x8b\x55\x00\xc7\x02')
		if offset != -1:
			send_data = decoded[offset+5:offset+5+4]
			if send_data != '\x00\x00\x00\x54':
				print("New command received!")
				c2.set_send_data(send_data)
			time.sleep(50)
		else:
			print("Unknown data alert")
			done = True
