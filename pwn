strace

gdb
  checksec
  b main
  r #run
  jmpcall
  pattern create ###
  
  
#find libc addr

ldd /path/to/bin | grep libc.so.6

#radare 2
r2
  aaa
  afl #print all functions
  vvv #visualization mode
