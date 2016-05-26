# [Vawtrak Trojan: Bank on it Evolving](http://www.threatgeek.com/2016/05/vawtrak-trojan-bank-on-it-evolving.html)
On May 12, 2016, Fidelis Cybersecurity witnessed an update to Vawtrak malware, a banking trojan, spread via an email campaign using subpoena- and lawsuit-related themes.  The configurations observed in this campaign point to an attempt to harvest user credentials when visiting accounts on major financial websites in the U.S. and U.K., such as ADP, Capital One, Citibank, Lloyds Bank, etc. The downloaded Vawtrak malware displays characteristics unlike previously seen variants, including new obfuscation and potential antivirus injection. The full list of targets and details around the technical evolution are discussed in [here](http://www.threatgeek.com/2016/05/vawtrak-trojan-bank-on-it-evolving.html)


### IDA python script for decoding unpacked loader and dll strings

	def PRNG(seed):
	
	            seed = (seed * 0x41c64e6d) + 0x3039
	
	            return (seed & 0xFFFFFFFF)
	
	#Unpacked loader - Md5: 3678dc31a2be281fa7ed178d535364fb
	
	for addr in XrefsTo(0x401a1b, flags=0):
			
	#Unpacked dll - Md5: 54db3f86aabaf3e87016bcff923dba41
	
	#for addr in XrefsTo(0x10007df8, flags=0):
	
	            addr = addr.frm
	
	            #print(hex(addr))
	
	            addr = idc.PrevHead(addr)
	
	            while GetMnem(addr) != "push":
	
	                        addr = idc.PrevHead(addr)
	
	            print(hex(addr))
	
	            #Get first param pushed which is address of domain
	
		            data_addr = GetOperandValue(addr,0)
	
	            init_seed = Dword(data_addr)
	
	            data_addr += 4
	
	            xork = Dword(data_addr)
	
	            data_addr += 4
	
	            length = (init_seed ^ xork) >> 16
		
	            out = ""
	
	            for i in range(length):
	
	                        init_seed = PRNG(init_seed)
	
	                        out += chr((Byte(data_addr) - (init_seed & 0xFF)) & 0xFF)
	
	                        data_addr += 1
	
	            if out[-2:] == '\x00\x00':
	
	                        print(out.decode('utf16'))
	
	            else:
	
	                        print(out)
	
	addr = 0x1000f8a0
	
	for i in range(10):
	
	            data_addr = Dword(addr)
	
	            addr += 4
	
	            init_seed = Dword(data_addr)
	
	            data_addr += 4
	
	            xork = Dword(data_addr)
	
	            data_addr += 4
	
	            length = (init_seed ^ xork) >> 16
	
	            out = ""
	
	            for i in range(length):
	
	                        init_seed = PRNG(init_seed)
	
	                        out += chr((Byte(data_addr) - (init_seed & 0xFF)) & 0xFF)
	
	                        data_addr += 1
	
	            print(out)


	 
