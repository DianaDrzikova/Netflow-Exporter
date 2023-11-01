CC = g++
CFLAGS = -std=c++17 -pedantic -g #-Wextra -Wall 

all: flow

flow: flow.o 
	$(CC) $(CFLAGS) -o flow flow.o -lpcap

flow.o: flow.cpp flow.hpp flowStructs.hpp
	$(CC) $(CFLAGS) -c flow.cpp -lpcap


clean:
	rm flow
	rm flow.o
