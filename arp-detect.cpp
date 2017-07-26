#include "arp-detect.h"
#include "encap_pcap.h"
#include <pcap.h>
#include <iostream>
#include <string.h>
#include <netinet/in.h>
using namespace std;

int detect_arp_trick(u_char* arg, struct pcap_pkthdr* pkthdr, u_char* packet)
{
    //TODO: detect if there are any arp trick
}

hostInfo* detect_promisc()
{
    cout<<"detectPromiscuous"<<endl;
    hostInfo* h;
    return h;
}

hostInfo* reverseDetect()
{
    cout<<"reverseDetect"<<endl;
    hostInfo* h;
    return h;
}

void sniff_arp_packet()
{ 
    bpf_u_int32 netaddr=0, mask=0;
    struct bpf_program filter;
    char *device=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr=NULL;
    pcap_pkthdr pkthdr;
    const unsigned char *packet=NULL;
    ArpHeader *arpheader=NULL;
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    device=pcap_lookupdev_with_prompts(errbuf);
    
    cout<<"Opening device: "<<device<<endl;
    
    if((descr=pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf))==NULL)
    {
	cout<<errbuf<<endl;
    }
    else{cout<< "success in opening"<<endl;}

    pcap_lookupnet(device, &netaddr,&mask,errbuf);
    pcap_compile(descr, &filter, "arp",1,mask);    
    pcap_setfilter(descr,&filter);

    if(pcap_set_promisc(descr,1)==0)
    {
	cout<<"set promiscuous mode success."<<endl;
    }
    else
    {
	cout<<"set promiscuous mode failed."<<endl;
    }

    while(1)
    {
	packet=pcap_next(descr,&pkthdr);
	arpheader=(ArpHeader*)(packet);
	if(pkthdr.len==0||packet==NULL)
	    continue;
	cout<<"\n\nReceived packet size:"<<pkthdr.len<<" bytes"<<endl;
	if(ntohs(arpheader->oper)==ARP_REQUEST)
	{
	    cout<<"who has ";
	    for(int i=0;i<4;i++)
		{printf("%d.",arpheader->tpa[i]);}
	    cout<<" tell ";
	    for(int i=0;i<4;i++)
		{printf("%d.",arpheader->spa[i]);}
	    cout<<endl;
	}
	else if(ntohs(arpheader->oper)==ARP_REPLY)
	{
	    for(int i=0;i<4;i++)
		{printf("%d.",arpheader->tpa[i]);}
	    cout<<" is at ";
	    for(int i=0;i<6;i++)
		{printf("%02X:",arpheader->sha[i]);}
	    cout<<"."<<endl;
	}
	else
	{
	    cout<<"arp packet error. impossible operation code."<<endl;
	}

	if(packet!=NULL)
	{
	    cout<<ntohs(arpheader->htype)<<endl;
	    cout<<ntohs(arpheader->ptype)<<endl;
	    cout<<"head dst mac:";
	    for(int i=0;i<6;i++)
	    {
		printf("%02X:",arpheader->dstAddr[i]);
	    }
	    cout<<"head src mac:";
	    for(int i=0;i<6;i++)
		printf("%02X:",arpheader->srcAddr[i]);
	    cout<<"Src Mac:";
	    for(int i=0;i<6;i++)
		printf("%02X:",arpheader->sha[i]);
	    cout<<"Src IP:";
	    for(int i=0;i<4;i++)
		printf("%d.",arpheader->spa[i]);
	    cout<<endl;
	    cout<<"Target Mac:";
	    for(int i=0;i<6;i++)
		printf("%02X:",arpheader->tha[i]);
	    cout<<"Target IP:";
	    for(int i=0;i<4;i++)
		printf("%d.",arpheader->tpa[i]);
	    cout<<endl;
	}
	cout<<endl;
    }
    
    
}

hostInfo* detectAttack()
{
    int i=0;
    int count=0;
    pcap_t *descr=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device=NULL;
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    
    device=pcap_lookupdev_with_prompts(errbuf);
    
    cout<<"Opening device: "<<device<<endl;
    descr=pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(descr)
    {
	cout<<errbuf<<endl;
    }
    else{cout<< "success in opening"<<endl;}
    
    pcap_loop(descr, -1, processPacket_Attack, (unsigned char*)&count);
    hostInfo* h;
    return h;
}

void processPacket_Attack(unsigned char *arg,const pcap_pkthdr* pkthdr,const unsigned char *packet)
{
    int *count=(int *)arg;
    cout<<*count<<endl;
    count++;
    for(int i=0; i<pkthdr->len; i++)
    {
	if(isprint(packet[i]))
	    cout<<(char)packet[i];
	else
	{
	    cout<<". ";
	}
	if((i%16==0&&i!=0)||i==pkthdr->len-1)
	{
	    cout<<"\n";
	}
    }
    return;
}

















