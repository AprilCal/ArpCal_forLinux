//#define HAVE_REMOTE
#include<stdlib.h>
#include<string.h>
/*include <pcap.h> instead of including <pcap/pcap.h> for backwards compatiability*/
#include<pcap.h>
#include<iostream>
#include<iomanip>
#include "arp-trick.h"
#include "arp-list.h"
#include "arp-detect.h"

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
    if(argc<2)
    {
	cout<<"arguement error!"<<endl;
	return 0;
    }
    cout<<"argc:"<<argc<<endl;

    /*Arp trick*/
    if(!strcmp("trick",argv[1]))
    {
        if(argc==5)
	    arpTrick(argv[2],argv[3],atoi(argv[4]));
	else if(argc==6)
	    arpTrick(argv[2],argv[3],atoi(argv[4]),argv[5]);
	else if(argc==7)
	    arpTrick(argv[2],argv[3],atoi(argv[4]),argv[5],atoi(argv[6]));
	else
	    cout<<"Usage:"<<endl;
    }

    if(!strcmp("detect",argv[1]))
    {
	if(argc<3)
	{
	    cout<<"Usage:"<<endl;
	    return 0;
	}
	cout<<"detect function is under building."<<endl;
	if(!strcmp("promiscuous",argv[2]))
	{
            detectPromiscuous();	
	}
	else if(!strcmp("attack",argv[2]))
	{
	    SniffArpPacket();
	    //detectAttack();
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
    if(!strcmp("-h",argv[1]))
    {
	cout<<"Usage: ArpCal <trick> [-d] <ip address> <time> [second|minute|hour] [interval time]|"<<endl<<
	      "              <list> [<device>|<iplist>]|"<<endl<<
	      "              <detect> [promiscuous|attack|reverse]"<<endl;
    }
    if(!strcmp("list",argv[1]))
    {
	if(argc<3)
	{
	    cout<<"Usage:"<<endl;
	    return 0;
	}
	/*get device list*/
	if(!strcmp("devices",argv[2]))
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
    return 0;  
}
