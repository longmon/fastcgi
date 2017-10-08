objects = main.o fastcgi.o

factcgi : $(objects)
	cc -o fastcgi $(objects)

main.o : main.c
	cc -c main.c

fastcgi.o : fastcgi.c fastcgi.h
	cc -c fastcgi.c

.PHONY: clean
clean:
	-rm -f fastcgi $(objects)