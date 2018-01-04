What's this?
======
An Arp trick tool for linux, also do some other things else.  
ArpCal does not mean any thing by itself, I don't konw how to name it so far.  

How to use it?
======
It's up to you :P  

How to install libpcap for Linux?
======
For example. I work under Ubuntu.  
1.Download the latest release version of libpcap from http://www.tcpdump.org/#latest-release  
2.Decompress libpcap-1.6.1.tar.gz ---- tar -zxvf libpcap-1.8.1.tar.gz  
3.Ensure that you have installed flex ---- sudo apt-get install flex  
4.Ensure that you have installed yacc ---- sudo apt-get install -y byacc  
5.cd libpcap-1.8.1  
6.sudo make && make install  
7.done

Usage:
======
ArpCal [--version][--help]<command>[args]

These are common commands used in various situations:

attack    arp attack.  
list      list interface information.  
detect    detect if there are any arp spoofing attact or promiscuous host inside the LAN.  

use ArpCal <command> --help to see details.
