CPP = g++ -Wall -Werror -O2 -std=c++17

%.o : %.cpp
	$(CPP) -c -o '$@' '$<'


udp-example : udp-example.o
	$(CPP) -o '$@' '$<'
