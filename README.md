What's this?
======
An Arp trick tool for linux, also do some other things else.  
ArpCal does not mean any thing by itself, cause I don't konw how to name it so far.  

How to use it?
======
It's up to you :P  

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

How to execute it as a command?
======
1.echo $PAtH  
2.move it to any of the path above.  
for example ---- sudo mv ArpCal usr/local/sbin

Usage:
======
ArpCal &lt;trick&gt; &lt;target ip&gt; &lt;spoofing ip&gt; &lt;time&gt; [timeUnit] [intervalTime]  
       &lt;trick&gt; means executring the trick unit.  
       &lt;target ip&gt; represent the target ip to trick.  
       &lt;spoofing ip&gt; represent the target ip to fake.  
       timeUnit={second|minute|hour}. The default time unit is second.  
       The unit of intervalTime is milisecond, which is of 500 default value.  

ArpCal &lt;list&gt; &lt;object&gt;  
       object={deviceName|all}. DeviceName represent a specific device on the local machine.
       all represent all apaper on the local machine.

