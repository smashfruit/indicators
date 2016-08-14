import struct

def decode_config(data):
	(total, num_secs) = struct.unpack_from('<IB', data)
	data = data[5:]
	ret = {}
	for i in range(num_secs):
		(toVal,cmd,pcount,length) = struct.unpack_from('<BBBI',data)
		data = data[7:]
		print("CMD: "+str(cmd))
		if cmd == 2:
			#webinject config
			(seed,s2) = struct.unpack_from('<II', data)
			data = data[8:]
			conf = bytearray(data[:seed^s2])
			data = data[seed^s2:]
			for i in range(len(conf)):
				seed = PRNG(seed)
				conf[i] = ((conf[i] - (seed & 0xFF)) & 0xFF)
			(cbout,) = struct.unpack_from('<I', conf)
			conf = conf[4:]
			conf_decomp = lzmat_decode(str(conf), len(conf), cbout)
			ret['config'] = conf_decomp
		elif cmd == 3:
			#Modules
			mods = []
			for i in range(pcount):
				mods.append (struct.unpack_from('<'+str(length)+'s', data)[0])
				data = data[length:]
				if i < pcount-1:				
					length = struct.unpack_from('<I', data)[0]
					data = data[4:]
			ret['mods'] = '\n'.join(mods)
		elif cmd == 41:
			#C2s and signer hash
			test = bytearray(data)
			(sig,seed,length2) = struct.unpack_from('<128sII', data)
			data = data[136:]
			c2s = bytearray(data[:length2])
			data = data[length2:]
					
			for i in range(len(c2s)):
				seed = PRNG(seed)
				c2s[i] = ((c2s[i] ^ (seed & 0xFF)) & 0xFF)
			print("C2s from Config:")
			print('\n'.join([x[1:] for x in str(c2s).split('\x00')]))
			ret['c2s'] = '\n'.join([x[1:] for x in str(c2s).split('\x00')])
			
		else:
			for i in range(pcount):
				data = data[length:]
				if i < pcount-1:
					length = struct.unpack_from('<I', data)[0]
					data = data[4:]
	return(ret)
