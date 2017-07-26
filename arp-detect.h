/*Create by AprilCal on 2017/5/29. contains some functions used 
  to detect if there are any device working under promiscuous mode;
                    or any device attacking(arp) ur host.
  also detect if your arp trick is detetcted by anyone.		
*/

#ifndef ARP_DETECT_H
#define ARP_DETECT_H

#include <pcap.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAXBYTES2CAPTURE 2048

int detect_arp_trick(u_char* arg, struct pcap_pkthdr* pkthdr, u_char* packet);

/* Name arphdr is already used in if_arp.h. */
struct ArpHeader
{
    /*The following 3 fields are in the Ethernet frame header.*/
    unsigned char dstAddr[6];   //Target hardware address in Ethernet frame header.
    unsigned char srcAddr[6];   //Sender hardware address in Ethernet frame header.
    u_int16_t protocolTpye;     //
    
    /*The other fields are in the frame body.*/
    u_int16_t htype;            //Hardware type
    u_int16_t ptype;            //Protocol type
    unsigned char hlen;         //Hardware address length
    unsigned char plen;         //Protocol address length
    u_int16_t oper;             //Operation code
    unsigned char sha[6];       //Sender hardware address
    unsigned char spa[4];       //Sender ip address
    unsigned char tha[6];       //Target hardware address
    unsigned char tpa[4];       //Target ip address
};

struct hostInfo
{
    /*I still don't konw how to get a deviceName(other host in a LAN)
      if anybody konws how to do, please fix here.*/
    char* deviceName;
    char* macAddress;
    char* ipAddress;
};

/*test function. remember to delete it.*/
void sniff_arp_packet();

/*This function will return */
hostInfo* detect_promisc();
hostInfo* reverseDetect();
hostInfo* detectAttack();
/*Process packet captured by NIC. Called back by function detectAttack.*/
void processPacket_Attack(unsigned char *arg,const pcap_pkthdr* pkthdr,const unsigned char *packet);

#endif //ARP_DETECT_H
