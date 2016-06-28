#Xenon2FF unpacker
import struct
import sys
import base64
import os
from ctypes import *

nt = windll.ntdll

def LZNT_decompress(buffer, pos):
size = len(buffer)
uncompressed_buffer = create_string_buffer(2*size)
final_size = c_ulong(0)
nt.RtlDecompressBuffer(
258,
uncompressed_buffer,
2*size,
c_char_p(buffer[pos:]),
size,
byref(final_size)
)
return uncompressed_buffer

exe = open(sys.argv[1],'rb').read()
#sometimes you have to play with this number or setup a loop to check if xorkeys are 0
exe = exe[512:]

start = exe.index('\x00\x00\x40\x00'+'\x00'*8)-5

(unk,xorkey2,unk,unk,unk,unk,unk,xorkey1,xorkey3) = struct.unpack_from('<IBIIIIIBB', exe[start:])

blob = bytearray(exe[start+39:])
for i in range(len(blob)):
blob[i] ^= xorkey1

dec1 = base64.b64decode(blob)
dec1 = bytearray(dec1)
for i in range(len(dec1)):
dec1[i] ^= xorkey2

decompressed = LZNT_decompress(str(dec1),0)
decompressed = bytearray(decompressed)
for i in range(len(decompressed)):
decompressed[i] ^= xorkey3
open(sys.argv[1]+'.unpacked','wb').write(decompressed)

