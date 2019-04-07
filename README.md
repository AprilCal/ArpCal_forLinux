What's this?
======
An Arp trick tool for linux, also do some other things else.  

How to install libpcap for Linux?
======
For example.i work under Ubuntu.  
1.Download the latest release version of libpcap from http://www.tcpdump.org/#latest-release  
2.Decompress libpcap-1.6.1.tar.gz ---- tar -zxvf libpcap-1.8.1.tar.gz  
3.Ensure that you have installed flex ---- sudo apt-get install flex  
4.Ensure that you have installed yacc ---- sudo apt-get install -y byacc  
5.cd libpcap-1.8.1  
6.sudo make && make install  
7.done

Usage:
======
ArpCal &lt;trick&gt; &lt;target ip&gt; &lt;spoofing ip&gt; &lt;time&gt; [timeUnit] [intervalTime]  

ArpCal &lt;list&gt; &lt;object&gt;  

