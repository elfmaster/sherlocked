all: stub davinci stripx gen_shellcode
stub:
	gcc -g -static stub.c md5.c -o stub
davinci:
	gcc sherlocked.c md5.c -o sherlocked
stripx:
	gcc utils/stripx.c -o utils/stripx
gen_shellcode:
	gcc utils/gen_shellcode.c -o utils/gen_shellcode
clean:
	rm -f stub sherlocked utils/gen_shellcode utils/stripx *.o
