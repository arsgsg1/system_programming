CC = gcc
OBJ1 = server.o
OBJ2 = client.o
CFLAGS = -lcrypto -g
TARGET = Server Client
.SUFFIXES : .c .o
all : Server Client
Server : $(OBJ1)
	$(CC) -o Server $(OBJ1) $(CFLAGS)

Client : $(OBJ2)
	$(CC) -o Client $(OBJ2) $(CFLAGS)

clean :
	rm *.o $(TARGET)
