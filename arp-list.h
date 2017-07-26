#ifndef ARP_LIST_H
#define ARP_LIST_H

#define FAST_FUNC
#include <inttypes.h>
#include <stdarg.h>



#include <net/if.h>
#include <net/if_arp.h>
#ifdef HAVE_NET_ETHERNET_H
# include <net/ethernet.h>
#endif

#if ENABLE_FEATURE_HWIB
/* #include <linux/if_infiniband.h> */
# undef INFINIBAND_ALEN
# define INFINIBAND_ALEN 20
#endif

#if ENABLE_FEATURE_IPV6
# define HAVE_AFINET6 1
#else
# undef HAVE_AFINET6
#endif

#define _PATH_PROCNET_DEV               "/proc/net/dev"
#define _PATH_PROCNET_IFINET6           "/proc/net/if_inet6"

#ifdef HAVE_AFINET6
# ifndef _LINUX_IN6_H
/*
 * This is from linux/include/net/ipv6.h
 */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};
# endif
#endif /* HAVE_AFINET6 */

/* Defines for glibc2.0 users. */
#ifndef SIOCSIFTXQLEN
# define SIOCSIFTXQLEN      0x8943
# define SIOCGIFTXQLEN      0x8942
#endif

/* ifr_qlen is ifru_ivalue, but it isn't present in 2.0 kernel headers */
#ifndef ifr_qlen
# define ifr_qlen        ifr_ifru.ifru_mtu
#endif

#ifndef HAVE_TXQUEUELEN
# define HAVE_TXQUEUELEN 1
#endif

#ifndef IFF_DYNAMIC
# define IFF_DYNAMIC     0x8000 /* dialup device with changing addresses */
#endif

/*From ifconfig.*/
struct interface 
{
    struct interface *next, *prev;	    /* :)                    */
    char name[16];                    /* interface name        */
    short type;                             /* if type               */
    short flags;                            /* various flags         */
    int metric;                             /* routing metric        */
    int mtu;                                /* MTU value             */
    int tx_queue_len;                       /* transmit queue length */
    struct ifmap map;                       /* hardware setup        */
    struct sockaddr addr;                   /* IP address            */
    struct sockaddr dstaddr;                /* P-P IP address        */
    struct sockaddr broadaddr;              /* IP broadcast address  */
    struct sockaddr netmask;                /* IP network mask       */
    int has_ip;
    char hwaddr[32];                        /* HW address            */
    int statistics_valid;
    //struct user_net_device_stats stats;     /* statistics            */
    int keepalive;                          /* keepalive value for SLIP */
    int outfill;                            /* outfill value for SLIP */
};

static interface *int_list, *int_last;

FILE* fopen_with_warn(const char* path, const char* mode);
static int if_readlist_proc(char *target)
{
	static short proc_read;

	FILE *fh;
	char buf[512];
	interface *ife;
	int err, procnetdev_vsn;

	if (proc_read)
		return 0;
	if (!target)
		proc_read = 1;

	fh = fopen_with_warn(_PATH_PROCNET_DEV, "r");
	if (!fh) {
		return 1;// if_readconf();
	}
	fgets(buf, sizeof buf, fh);	/* eat line */
	fgets(buf, sizeof buf, fh);

}

static struct interface *add_interface(char *name)
{
	interface *ife, **nextp, *new_;

	for (ife = int_last; ife; ife = ife->prev) {
		int n = /*n*/strcmp(ife->name, name);

		if (n == 0)
			return ife;
		if (n < 0)
			break;
	}

/*
	new = xzalloc(sizeof(*new));
	strncpy_IFNAMSIZ(new->name, name);
	nextp = ife ? &ife->next : &int_list;
	new->prev = ife;
	new->next = *nextp;
	if (new->next)
		new->next->prev = new;
	else
		int_last = new;
	*nextp = new;
	return new;*/
}



/* Networking */
/* This structure defines protocol families and their handlers. */
struct aftype {
	const char *name;
	const char *title;
	int af;
	int alen;
	char*       FAST_FUNC (*print)(unsigned char *);
	const char* FAST_FUNC (*sprint)(struct sockaddr *, int numeric);
	int         FAST_FUNC (*input)(/*int type,*/ const char *bufp, struct sockaddr *);
	void        FAST_FUNC (*herror)(char *text);
	int         FAST_FUNC (*rprint)(int options);
	int         FAST_FUNC (*rinput)(int typ, int ext, char **argv);
	/* may modify src */
	int         FAST_FUNC (*getmask)(char *src, struct sockaddr *mask, char *name);
};

/* This structure defines hardware protocols and their handlers. */
struct hwtype 
{
	const char *name;
	const char *title;
	int type;
	int alen;
	char* FAST_FUNC (*print)(unsigned char *);
	int   FAST_FUNC (*input)(const char *, struct sockaddr *);
	int   FAST_FUNC (*activate)(int fd);
	int suppress_null_addr;
};

/* From ifconfig.      hwtype should be a class. 
   Using structure to represent hardware type is a 
   pile of dog shit, cause it has a lot of subclass.*/
/*
class HardwareType
{
    public:
    const char *name
    const char *title;
    int type;
    int alen;
    int FAST_FUNC print(unsigned char*);
    int FAST_FUNC input(const char *,struct sockaddr *);
    int FAST_FUNC activate(int fd);
    int supress_null_addr;
};
*/




/* return 1 if address is all zeros */
static int hw_null_address(const struct hwtype *hw, void *ap)
{
	int i;
	unsigned char *address = (unsigned char *) ap;

	for (i = 0; i < hw->alen; i++)
		if (address[i])
			return 0;
	return 1;
}

#define ARRAY_SIZE(x) ((unsigned)(sizeof(x) / sizeof((x)[0])))

char* FAST_FUNC xasprintf(const char *format, ...);

char* FAST_FUNC auto_string(char *str);

/* Display an Ethernet address in readable format. */
static char* FAST_FUNC ether_print(unsigned char *ptr)
{
}



int FAST_FUNC in_ether(const char *bufp, struct sockaddr *sap);

#define ARPHRD_ETHER 1
#define ETH_ALEN 1
static const struct hwtype ether_hwtype = {
	.name  = "ether",
	.title = "Ethernet",
	.type  = ARPHRD_ETHER,
	.alen  = ETH_ALEN,
	.print = ether_print,
	.input = in_ether
};

static const hwtype *const hwtypes[] = {
	//&loop_hwtype,
	&ether_hwtype,
	//&ppp_hwtype,
	//&unspec_hwtype,
#if ENABLE_FEATURE_IPV6
	//&sit_hwtype,
#endif
#if ENABLE_FEATURE_HWIB
	//&ib_hwtype,
#endif
	NULL
};

/* Check our hardware type table for this type. */
const hwtype* FAST_FUNC get_hwtype(const char *name);

/* Check our hardware type table for this type. */
const hwtype* FAST_FUNC get_hwntype(int type);

static void ife_print(interface *ptr)
{
	//const struct aftype *ap;
	const struct hwtype *hw;
	int hf;
	int can_compress = 0;

	/*ap = get_afntype(ptr->addr.sa_family);
	if (ap == NULL)
		ap = get_afntype(0);
*/
	hf = ptr->type;	

	/* i don't konw */
	if (hf == ARPHRD_CSLIP || hf == ARPHRD_CSLIP6)
		can_compress  = 1;

	hw = get_hwntype(hf);
	if (hw == NULL)
		hw = get_hwntype(-1);

	printf("%-9s Link encap:%s  ", ptr->name, hw->title);
	/* For some hardware types (eg Ash, ATM) we don't print the
	   hardware address if it's null.  */
	if (hw->print != NULL
	 && !(hw_null_address(hw, ptr->hwaddr) && hw->suppress_null_addr)
	) {
		printf("HWaddr %s  ", hw->print((unsigned char *)ptr->hwaddr));
	}
}

/* display the information of a interface*/
int FAST_FUNC display_interfaces(char *ifname);

void getDeviceList();
void listSpecificDevice(char* deviceName);

/* TODO:These all functions should be in one class. */
class InterfaceManager
{
public:
    /* Read PROCESS_NET_DEV_PATH "/proc/net/dev"*/
    void read_proc_net_dev();
    void addInterface();
}; 

/* Get hardware address for trick. Only used by
   arp-trick module.                           */
//char* get_hwaddr(const char* interfaceName);
//bool set_hwaddr_for_packet(const char* interfaceName);


#endif //ARP_LIST_H
