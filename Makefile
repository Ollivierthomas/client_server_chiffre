all: client server

client.o: client.c common.h
	gcc -c client.c `pkg-config --cflags gtk4`

common.o: common.c common.h
	gcc -c common.c

client_array.o: client_array.c client_array.h
	gcc -c client_array.c

chiffrement.o: chiffrement.c chiffrement.h
	gcc -c chiffrement.c -std=c23

server.o: server.c common.h client_array.h
	gcc -c server.c

client: client.o common.o chiffrement.o
	gcc -o client client.o common.o chiffrement.o `pkg-config --cflags --libs gtk4` -lm -pthread

chiffrement: chiffrement.o
	gcc -o chiffrement chiffrement.o -lm

server: server.o common.o client_array.o chiffrement.o
	gcc -o server server.o common.o client_array.o chiffrement.o -lm

.PHONY: clean
clean:
	rm -f *.o client server chiffrement