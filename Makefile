all: send_arp

send_arp:
	g++ -o send_arp main.cpp -lpcap

clean:
	rm -f send_arp
