#ifndef USAGE_H
#define USAGE_H

/*const char* usageString[]={"Usage: ArpCal <command> [args]\t",
                           "       ArpCal <trick> <target ip> <time> [second|minute|hour] [interval time]\t",
			   "       ArpCal <list> [-v]                                                   \t"};

const char* usage[]={"ArpCal [--version][--help]<command>[args]\t",
		     "These are common commands used in various situations:\t",
		     "attack    arp attack.\t",
		     "list      list interface information.\t",
		     "detect    detect if there are any arp spoofing attact or promiscuous host inside the LAN.\t"};*/ 

/*const char* usage[] = {"ArpCal attack [<args>][<flags>]\t
	                ArpCal attack <target><spoofing ip><time>[timeUnit][intervalTime]
target represent the target ip to attack.
spoofing ip means the ip to fake.
timeUnit={second|minute|hour}. The default time unit is second.  
The unit of intervalTime is milisecond, which is of 500 default value.  
-h --help  
-q --quiet            be quiet.  
-v --verbose          be more stupid.  
-f --force            break through firewall(if there is one).

ArpCal list [<args>][flags]  
object={deviceName|all}. DeviceName represent a specific device on the local machine.
       all represent all apaper on the local machine.
-h --help            output help information.  
-u --usb             usb interface.  
-v --verbose         output more information.

ArpCal detect [promisc|attack][flags]  
-h --help  
-v --verbose         output more information.  
-p --promiscuous      detect promiscuous host inside LAN.  
-p --packet          output suspecious packet meanwhile.  
-a --attack          detect attack in daemon process.}
"*/

void print_usage();

#endif //USAGE_H
