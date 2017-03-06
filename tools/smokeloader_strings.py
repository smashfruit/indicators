import struct

def rc4_crypt(data, key):
	S = list(range(256))
	j = 0
	out = []
 
	for i in range(256):
		j = (j + S[i] + ord( key[i % len(key)] )) % 256
		S[i] , S[j] = S[j] , S[i]
 
	i = j = 0
	for char in data:
		i = ( i + 1 ) % 256
		j = ( j + S[i] ) % 256
		S[i] , S[j] = S[j] , S[i]
		out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))    
	return ''.join(out)

for addr in XrefsTo(0x1031724, flags=0):
	addr = addr.frm
	while GetMnem(addr) != "push":
		addr = idc.PrevHead(addr)
	data_addr = GetOperandValue(addr,0)
	addr = idc.PrevHead(addr)
	while GetMnem(addr) != "push":
		addr = idc.PrevHead(addr)
	data_length = GetOperandValue(addr,0)
	temp = GetManyBytes(data_addr, data_length)
	
	key = "zVsO"
	
	strings = rc4_crypt(temp, key)
	try:
		strings = strings.decode('utf-16')
	except:
		pass
	for s in strings.split('\x01'):
		print(s)

		
#URLs:

for addr in XrefsTo(0x103169c, flags=0):
	addr = addr.frm
	while GetMnem(addr) != "push":
		addr = idc.PrevHead(addr)
	print(hex(addr)),
	data_addr = GetOperandValue(addr,0)
	if data_addr > 100:
		temp = GetManyBytes(data_addr,10)
		data_length = ord(temp[4]) / 2
		data = bytearray(GetManyBytes(data_addr, data_length+50))
	
	
		out = ""
		for i in range(1,data_length):
			out += chr((((data[0] ^ data[5+(i-1)*2])&0xFF) - ((data[0] ^ data[5+i+(i-1)])&0xFF)) & 0xff)
		print(out)
		
data_addr = 0x103406c

if data_addr > 100:
	temp = GetManyBytes(data_addr,10)
	data_length = ord(temp[4]) / 2
	data = bytearray(GetManyBytes(data_addr, data_length+50))
	
	crc32_hash = struct.unpack_from('<I', data)[0]
	out = ""
	for i in range(1,data_length):
		out += chr((((data[0] ^ data[5+(i-1)*2])&0xFF) - ((data[0] ^ data[5+i+(i-1)])&0xFF)) & 0xff)
	print(out)