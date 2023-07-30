# Compiler and flags
CC = gcc
CFLAGS = -Wall

# Executable name
EXEC = packet_gen

# Source file
SRCS = packet_gen.c

# Object files
OBJS = $(SRCS:.c=.o)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) $(OBJS)
