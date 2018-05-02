CC = gcc
OBJ1 = server.o
CFLAGS = -lcrypto -g
TARGET = proxy_cache
.SUFFIXES : .c .o
all : $(TARGET)
$(TARGET) : $(OBJ1)
	$(CC) -o $(TARGET) $(OBJ1) $(CFLAGS)

clean :
	rm *.o $(TARGET)
