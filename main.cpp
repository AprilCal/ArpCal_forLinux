//#define HAVE_REMOTE
#include <stdlib.h>
#include <string.h>
/*include <pcap.h> instead of including <pcap/pcap.h> for backwards compatiability*/
#include <pcap.h>
#include <iostream>
#include <iomanip>
#include "arp-trick.h"
#include "arp-list.h"
#include "arp-detect.h"
#include "usage.h"

#ifndef LINUX
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    //#include <winsock.h>
#endif
using namespace std;

//void getDeviceList();
int main(int argc,char* argv[])
{  
    //TODO: refactor parse options
    if(argc<3)
    {
	print_usage();
	return 0;
    }
    /*Arp trick*/
    else if(!strcmp("attack",argv[1])){
	if(!strcmp("--help",argv[2])||!strcmp("-he",argv[2]))
	    print_attack_usage();
        else if(argc==5)
	    arpTrick(argv[2],argv[3],atoi(argv[4]));
	else if(argc==6)
	    arpTrick(argv[2],argv[3],atoi(argv[4]),argv[5]);
	else if(argc==7)
	    arpTrick(argv[2],argv[3],atoi(argv[4]),argv[5],atoi(argv[6]));
	else
	    print_attack_usage();
    }
    else if(!strcmp("detect",argv[1])){
	if(argc<3)
	{
	    print_detect_usage();
	    return 0;
	}
	else if(!strcmp("--help",argv[2])||!strcmp("-he",argv[2]))
	    print_detect_usage();
	else if(!strcmp("promisc",argv[2]))
	{
            detect_promisc();	
	}
	else if(!strcmp("attack",argv[2]))
	{
	    sniff_arp_packet();
	}
	else if(!strcmp("reverse",argv[2]))
	{
	    reverseDetect();
	}
	else
	{
	    cout<<"Usage:"<<endl;
	    return 0;
	}
    }
    else if(!strcmp("list",argv[1]))
    {
	if(argc<3)
	{
	    print_list_usage();
	    return 0;
	}
	else if(!strcmp("--help",argv[2])||!strcmp("-h",argv[2]))
	{
            print_list_usage();	
	}
	/*get device list*/
	else if(!strcmp("devices",argv[2]))
	{
            getDeviceList();	
	}
	/*get ip list in LAN*/
	else if(!strcmp("iplist",argv[2]))
	{
	    //getIPList();
	}
	else
	{
	    listSpecificDevice(argv[2]);
	}
    }
    else if(!strcmp("-h",argv[1])||!strcmp("--help",argv[1]))
    {
	print_usage();
    }
    else{
	print_usage();
    }
    return 0;  
}
