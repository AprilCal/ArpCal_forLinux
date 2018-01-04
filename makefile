#Create by AprilCal on 2015.5.31

CC=g++
objects = main.o arp-trick.o arp-list.o arp-detect.o parse-options.o o_funcs.o encap_pcap.o output_format.o usage.o
ArpCal:$(objects)
	$(CC) -g -Wall -o $@ $(objects) -lpcap -std=gnu++11

main.o:main.cpp arp-trick.h arp-list.h
arp-trick.o:arp-trick.h parse-options.h
arp-list.o:arp-list.h
arp-detect.o:arp-detect.h
o_funcs.o:o_funcs.h
encap_pcap.0:encap_pcap.h
usage.o:usage.h
output_format.o:output_format.h
parse-options.o:parse-options.h
	$(CC) -c -o parse-options.o parse-options.cpp -std=gnu++11
	#Header file <regex> need to be compiled by c++11.

#ArpCal:main.cpp arp-trick.cpp parse-options.cpp arp-list.cpp
#	$(CC) -g -Wall -o ArpCal main.cpp arp-trick.cpp parse-options.cpp arp-list.cpp -lpcap -std=gnu++11
.PHONY:clean
clean:
	rm ArpCal $(objects)
	echo "clean"

.PHONY:config
config:
	echo "config"
