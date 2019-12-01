strace

gdb
  checksec
  b main
  r #run
  jmpcall
  pattern create ###
  
  
#find libc addr
ldd /path/to/bin | grep libc.so.6

# find system offset
readelf -s /lib32/libc/libc.so.6 | grep system

# find exit offset
readelf -s /lib32/libc/libc.so.6 | grep exit

# find arg offset, which is most of the times /bin/sh
strings -a -t x /lib32/libc.so.6 | grep bin/sh

#radare 2
r2
  aaa
  afl #print all functions
  vvv #visualization mode
