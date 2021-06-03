.PHONY : all

CPP = g++ -Wall -Werror -O2 -std=c++17

all : stun-example udp-example

stun-example : stun-example.o
	$(CPP) -o '$@' '$<'

udp-example : udp-example.o
	$(CPP) -o '$@' '$<'

%.o : %.cpp
	$(CPP) -c -o '$@' '$<'
