all:
	gcc -Wall -O2 -o netdump netdump.c

debug:
	gcc -g3 -Wall -O2 -o netdump netdump.c

clean:
	rm -f netdump
