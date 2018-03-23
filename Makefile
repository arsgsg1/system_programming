CC = gcc
OBJS = proxy_cache.o
CFLAGS = -lcrypto -g
TARGET = proxy_cache
.SUFFIXES : .c .o

all : $(TARGET)
$(TARGET) : $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS)

clean :
	rm *.o $(TARGET)
