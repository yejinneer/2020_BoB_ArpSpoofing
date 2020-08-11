LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	
mac.o: mac.h mac.cpp
	g++ -c -o mac.o mac.cpp -lpcap

ip.o: ip.h ip.cpp
	g++ -c -o ip.o ip.cpp -lpcap
	
ethhdr.o: ethhdr.h ethhdr.cpp
	g++ -c -o ethhdr.o ethhdr.cpp -lpcap	
	
arphdr.o: arphdr.h arphdr.cpp
	g++ -c -o arphdr.o arphdr.cpp -lpcap
	
main.o: main.cpp ethhdr.h arphdr.h
	g++ -c -o main.o main.cpp -lpcap
	
clean:
	rm -f arp-spoof *.o
