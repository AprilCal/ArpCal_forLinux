/*ifconfig.c interface.c xfuncs_printf.c xfuncs.c platform.c*/

//#define HAVE_REMOTE
#include<stdlib.h>
#include<string.h>
/*include <pcap.h> instead of including <pcap/pcap.h> for backwards compatiability*/
#include<pcap.h>
#include<iostream>
#include<iomanip>
#include "arp-list.h"
#include "o_funcs.h"

/* From ifconfig. */
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>

/*I do not know what's this.*/
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/time.h>				/* concession to AIX */
#include <net/if.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace std;

FILE* fopen_with_warn(const char* path, const char* mode)
{
    FILE* fp = fopen(path, mode);
    if(!fp)
    {
	//TODO: encapsulate errorCode
	output_error_msg_and_exit("can not open the file.",0);
    }
}


char* FAST_FUNC auto_string(char *str)
{
	static char *saved[4];
	static uint8_t cur_saved; /* = 0 */

	free(saved[cur_saved]);
	saved[cur_saved] = str;
	cur_saved = (cur_saved + 1) & (ARRAY_SIZE(saved)-1);

	return str;
}

/* Check our hardware type table for this type. */
const hwtype* FAST_FUNC get_hwtype(const char *name)
{
	const struct hwtype *const *hwp;

	hwp = hwtypes;
	while (*hwp != NULL) {
		if (strcmp((*hwp)->name, name) == 0)
			return (*hwp);
		hwp++;
	}
	return NULL;
}

/* Check our hardware type table for this type. */
const hwtype* FAST_FUNC get_hwntype(int type)
{
	const struct hwtype *const *hwp;

	hwp = hwtypes;
	while (*hwp != NULL) {
		if ((*hwp)->type == type)
			return *hwp;
		hwp++;
	}
	return NULL;
}
int FAST_FUNC in_ether(const char *bufp, struct sockaddr *sap)
{
}
char* FAST_FUNC xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	//if (r < 0)
		//bb_error_msg_and_die(bb_msg_memory_exhausted);
	return string_ptr;
}

/* display the information of a interface*/
int FAST_FUNC display_interfaces(char *ifname)
{
	int status;

	//status = if_print(ifname);

	return (status < 0); /* status < 0 == 1 -- error */
}








//native code.
/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    unsigned char *p;

    /*Get the address of 'in'(u_long) and cast it into a unsigned char*.
      Now, p has became a pointer pointing to a byte(u_char) array.   */
    p = (unsigned char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which],sizeof(output[which]),"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    return output[which];
}

/*Print all the available information on the given interface.*/
void ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];

    /* Name */
    printf("%s\n",d->name);

    /* Description */
    if (d->description)
	printf("\tDescription: %s\n",d->description);

    /* Loopback Address*/
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) 
    {
	cout<<"\tAddress Family: "<<a->addr->sa_family<<endl;
	switch(a->addr->sa_family)
	{
	    case AF_INET:
		cout<<"\t    Address Family Name: AF_INET(ipv4)"<<endl;
		if (a->addr)
		    cout<<"\t\tAddress:"<<iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr)<<"\n";
		if (a->netmask)
		    cout<<"\t\tNetmask:"<<iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr)<<endl;
		if (a->broadaddr)
		    cout<<"\t\tBroadcast:"<<iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr)<<endl;
		if (a->dstaddr)
		    cout<<"\t\tDestination:"<<iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr)<<endl;
            break;

	    case AF_INET6:
		cout<<"\t    Address Family Name: AF_INET6(ipv6)"<<endl;
		if (a->addr)
		    /*fix below, print ipv6 address*/
		    //cout<<"\t\tAddress:"<<((struct sockaddr_in *)a->addr)->sin_addr.s_addr<<endl;
		    //printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
	    break;

	    default:
		cout<<"\t    Address Family Name: Unknown"<<endl;
	    break;
	}
    }
    printf("\n");
}



#define PROC_NET_DEV_PATH "/proc/net/dev"
//typedef signed char smallint
/*Used by command ArpCal list <device name>.
  list the imformation of a specific device.*/


/* Just use it. Do not bb. Do not ask. */
char* FAST_FUNC skip_whitespace(const char *s)
{
	/* In POSIX/C locale (the only locale we care about: do we REALLY want
	 * to allow Unicode whitespace in, say, .conf files? nuts!)
	 * isspace is only these chars: "\t\n\v\f\r" and space.
	 * "\t\n\v\f\r" happen to have ASCII codes 9,10,11,12,13.
	 * Use that.
	 */
	while (*s == ' ' || (unsigned char)(*s - 9) <= (13 - 9))
		s++;

	return (char *) s;
}

/*bool set_hwaddr_for_packet(const char* interfaceName)
{
    return true;
}*/


void listSpecificDevice(char* deviceName)
{	
    cout<<deviceName<<"\t";
    interface *ife;
    ife = (interface*) malloc(sizeof(interface));
    memcpy(ife->name,deviceName,strlen(deviceName));
    ife->name[strlen(deviceName)]='\0';
    ifreq ifr;
    char *ifname = ife->name;
    int skfd;

    //TODO:encapsulate
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    //skfd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ifname, 16);
    //strncpy_IFNAMSIZ(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
	close(skfd);
	return;
    }
    ife->flags = ifr.ifr_flags;
    strncpy(ifr.ifr_name, ifname, 16);
    memset(ife->hwaddr, 0, 32);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0)
	memcpy(ife->hwaddr, ifr.ifr_hwaddr.sa_data, 8);
    ife->type = ifr.ifr_hwaddr.sa_family;
    cout<<"ife->hwaddr";
    for(int i=0;i<6;i++)
    {
	printf("%02x",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    }
    /* Display an Ethernet address in readable format. */
    char macc[18];
    const char *test_eth = "eth0";  
    snprintf(macc, 18, "%02x:%02x:%02x:%02x:%02x:%02x",  
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],   
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],  
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],   
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],  
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],  
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    cout<<macc<<endl;
    
    /*My code.*/
    pcap_if_t *alldevs;/*point to the first element of the list*/
    char errbuf[PCAP_ERRBUF_SIZE];

    /*Retrieve the device list from the local machine.*/
    cout << "Retrieving device "<<deviceName<<" from the local machine..."<<endl;

    /*pcap_findalldevs() returns 0 on success and -1 on failure;               */
    /*finding no devices is considered success, rather than failure.           */
    /*if -1 is returned, errbuf is filled in with an appropriate error message.*/
    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
	fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
	cout<<errbuf<<endl;
    }


    /* From ifconfig. */
    int fd;
    int interfaceNum = 0;
    struct ifreq buf[16];
    struct ifconf ifc;
    struct ifreq ifrcopy;
    char mac[16] = {0};
    char ip[32] = {0};
    char broadAddr[32] = {0};
    char subnetMask[32] = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        (void)close(fd);
        return;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;
    if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        interfaceNum = ifc.ifc_len / sizeof(ifreq);
        printf("interface num = %d\n\n", interfaceNum);
        while (interfaceNum-- > 0)
        {
            printf("ndevice name: %sn", buf[interfaceNum].ifr_name);

            //ignore the interface that not up or not runing  
            ifrcopy = buf[interfaceNum];
            if (ioctl(fd, SIOCGIFFLAGS, &ifrcopy))
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                //close(fd);
                return;
            }

            //get the mac of this interface  
            if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
            {
                memset(mac, 0, sizeof(mac));
                snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);
                printf("device mac: %s\n", mac);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                //close(fd);
                return;
            }

            //get the IP of this interface  
            if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[interfaceNum]))
            {
                snprintf(ip, sizeof(ip), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_addr))->sin_addr));
                printf("device ip: %s\n", ip);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                //close(fd);
                return;
            }

            //get the broad address of this interface  
            if (!ioctl(fd, SIOCGIFBRDADDR, &buf[interfaceNum]))
            {
                snprintf(broadAddr, sizeof(broadAddr), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_broadaddr))->sin_addr));
                printf("device broadAddr: %s\n", broadAddr);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                //close(fd);
                return;
            }

            //get the subnet mask of this interface  
            if (!ioctl(fd, SIOCGIFNETMASK, &buf[interfaceNum]))
            {
                snprintf(subnetMask, sizeof(subnetMask), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_netmask))->sin_addr));
                printf("device subnetMask: %s\n", subnetMask);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                //close(fd);
                return;
            }
	    cout<<endl;
        }
    }
    else
    {
        printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
        //close(fd);
        return;
    }


    cout<<endl<<"my method:"<<endl;

    for(;alldevs;alldevs=alldevs->next)
    {
	if(!strcmp(alldevs->name,deviceName))
	{
            ifprint(alldevs);
	    return;
        }
    }
    cout<<"Error. Do not have such a device: "<<deviceName<<"."<<endl;
    cout<<"Check all device through command: ArpCal list device."<<endl;
    pcap_freealldevs(alldevs);
    return;
}

void getDeviceList()
{
    pcap_if_t *alldevs;              /*point to the first element of the list*/
    char errbuf[PCAP_ERRBUF_SIZE];

    /*Retrieve the device list from the local machine.*/
    cout << "retrieving device list from the local machine..."<<endl;

    /*pcap_findalldevs() returns 0 on success and -1 on failure;               */
    /*finding no devices is considered success, rather than failure.           */
    /*if -1 is returned, errbuf is filled in with an appropriate error message.*/
    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
	fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
	cout<<errbuf<<endl;
    }

    /*Get the longest length of description field for tabling*/
    unsigned int longestDesc=0;          //hold the length
    for(pcap_if_t *d=alldevs;d->next!=NULL;d=d->next)
    {
	if(d->description&&strlen(d->description)>=longestDesc)
	{
	    longestDesc=strlen(d->description);
	}
    }

    /*Set format of the device table. The device list contains 
      3 fields: Devices(device name); Descriptions(descriptions
      of the corresponding device); Addresses(indicating if there
      are any address of the device.).                      */
    //now, set table header.
    cout<<endl<<left<<setw(13)<<"Devices:";                          //Devices field
    cout<<"|"<<left<<setw(longestDesc)<<"Descriptions:";             //Descriptions field
    cout<<"|"<<left<<setw(13)<<"Addresses:"<<endl;                                       //Addresses field

    /*Print division line corresponding to total length.*/
    for(int i=0;i<13+longestDesc+13+2;i++)
    {
	cout<<"-";
    }
    cout<<endl;

    /*Print table body.*/
    for(pcap_if_t *d=alldevs;d;d=d->next)
    {
	cout<<left<<setw(12)<<d->name<<" ";
	if(d->description)
	{
	    cout<<"|"<<left<<setw(longestDesc)<<d->description;
	}
	else
	{
	    cout<<"|"<<left<<setw(longestDesc)<<"do not have description";
	}
	if(d->addresses)
	{
	    cout<<"|Y (do have)"<<endl;
	}
	else
	{
	    cout<<"|no addresses"<<endl;
	}
    }
    pcap_freealldevs(alldevs);
}
