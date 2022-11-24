/**
 * NetSwitch utility
 * Switches wireless connection priority (metric). Ethernet with the highest priority
 * connection checked thru current Doorbell server (from application config file)
 * - If there is only one connected interface - do nothing
 * - If mobile and ethernet are available - mobile priority = 710
 * - If mobile is available and ethernet is not - mobile priority = 10
 *
*/
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <memory.h>
#include <netdb.h>
// #include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <bits/sockaddr.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include "app.h"
#include "nlrequest.h"

#define  SERVER_CONFIG          "/home/defigo/.config/Doorbell ink/Doorbell.conf"
#define  SERVER_OPTION          "url="
#define  MAX_ROUTES             64
#define  CONNECT_TIMEOUT_S      5
#define  CONNECT_TIMEOUT_uS     0

int check_error = 0;
int g_stop = 0;
int g_run = 0;
int g_reload = 0;
struct in_addr server = {0L};
struct nlmsghdr *routes[MAX_ROUTES];
int n_routes;
int server_port = 0;
int netlink_sck = 0;
int active_cnt = 0;
int verbose = 0;

const struct option long_options[] = {
    {"verbose", no_argument,        0,  'v'}
};

typedef struct connection_info_s {
    char interface[IFNAMSIZ + 1];
    int ifx;
    int metric;
    int valid;
} connection_info_t;

connection_info_t emak[2] = {
    {ETH_INTERFACE, -1, 0, 0},
    {MOB_INTERFACE, -1, 0, 0}
};

#define MOB 0
#define ETH 1

void run_handler(int sig) {
    g_run = 1;
}

void stop_handler(int sig) {
    g_stop = 1;
}

void reload_handler(int sig) {
    g_reload = 1;
}

const char* rta_type_name(unsigned short val) {
    static char ret[10] = {0};
    switch(val) {
        case RTA_UNSPEC: return "RTA_UNSPEC";
        case RTA_DST: return "RTA_DST";
        case RTA_SRC: return "RTA_SRC";
        case RTA_IIF: return "RTA_IIF";
        case RTA_OIF: return "RTA_OIF";
        case RTA_GATEWAY: return "RTA_GATEWAY";
        case RTA_PRIORITY: return "RTA_PRIORITY";
        case RTA_PREFSRC: return "RTA_PREFSRC";
        case RTA_METRICS: return "RTA_METRICS";
        case RTA_MULTIPATH: return "RTA_MULTIPATH";
        case RTA_PROTOINFO: return "RTA_PROTOINFO";
        case RTA_FLOW: return "RTA_FLOW";
        case RTA_CACHEINFO: return "RTA_CACHEINFO";
        case RTA_SESSION: return "RTA_SESSION";
        case RTA_MP_ALGO: return "RTA_MP_ALGO";
        case RTA_TABLE: return "RTA_TABLE";
        case RTA_MARK: return "RTA_MARK";
        case RTA_MFC_STATS: return "RTA_MFC_STATS";
        case RTA_VIA: return "RTA_VIA";
        case RTA_NEWDST: return "RTA_NEWDST";
        case RTA_PREF: return "RTA_PREF";
        case RTA_ENCAP_TYPE: return "RTA_ENCAP_TYPE";
        case RTA_ENCAP: return "RTA_ENCAP";
        case RTA_EXPIRES: return "RTA_EXPIRES";
        case RTA_PAD: return "RTA_PAD";
        case RTA_UID: return "RTA_UID";
        case RTA_TTL_PROPAGATE: return "RTA_TTL_PROPAGATE";
        case RTA_IP_PROTO: return "RTA_IP_PROTO";
        case RTA_SPORT: return "RTA_SPORT";
        case RTA_DPORT: return "RTA_DPORT";
        case RTA_NH_ID: return "RTA_NH_ID";
        case __RTA_MAX: return "__RTA_MAX";
    }
    snprintf(ret, 9, "%d", val);
    return ret;
}

const char* ifla_type_name(unsigned short val) {
    static char ret[10] = {0};
    switch(val) {
        case IFLA_UNSPEC: return "IFLA_UNSPEC";
        case IFLA_ADDRESS: return "IFLA_ADDRESS";
        case IFLA_BROADCAST: return "IFLA_BROADCAST";
        case IFLA_IFNAME: return "IFLA_IFNAME";
        case IFLA_MTU: return "IFLA_MTU";
        case IFLA_LINK: return "IFLA_LINK";
        case IFLA_QDISC: return "IFLA_QDISC";
        case IFLA_STATS: return "IFLA_STATS";
        case IFLA_COST: return "IFLA_COST";
        case IFLA_PRIORITY: return "IFLA_PRIORITY";
        case IFLA_MASTER: return "IFLA_MASTER";
        case IFLA_WIRELESS: return "IFLA_WIRELESS";
        case IFLA_PROTINFO: return "IFLA_PROTINFO";
        case IFLA_TXQLEN: return "IFLA_TXQLEN";
        case IFLA_MAP: return "IFLA_MAP";
        case IFLA_WEIGHT: return "IFLA_WEIGHT";
        case IFLA_OPERSTATE: return "IFLA_OPERSTATE";
        case IFLA_LINKMODE: return "IFLA_LINKMODE";
        case IFLA_LINKINFO: return "IFLA_LINKINFO";
        case IFLA_NET_NS_PID: return "IFLA_NET_NS_PID";
        case IFLA_IFALIAS: return "IFLA_IFALIAS";
        case IFLA_NUM_VF: return "IFLA_NUM_VF";
        case IFLA_VFINFO_LIST: return "IFLA_VFINFO_LIST";
        case IFLA_STATS64: return "IFLA_STATS64";
        case IFLA_VF_PORTS: return "IFLA_VF_PORTS";
        case IFLA_PORT_SELF: return "IFLA_PORT_SELF";
        case IFLA_AF_SPEC: return "IFLA_AF_SPEC";
        case IFLA_GROUP: return "IFLA_GROUP";
        case IFLA_NET_NS_FD: return "IFLA_NET_NS_FD";
        case IFLA_EXT_MASK: return "IFLA_EXT_MASK";
        case IFLA_PROMISCUITY: return "IFLA_PROMISCUITY";
        case IFLA_NUM_TX_QUEUES: return "IFLA_NUM_TX_QUEUES";
        case IFLA_NUM_RX_QUEUES: return "IFLA_NUM_RX_QUEUES";
        case IFLA_CARRIER: return "IFLA_CARRIER";
        case IFLA_PHYS_PORT_ID: return "IFLA_PHYS_PORT_ID";
        case IFLA_CARRIER_CHANGES: return "IFLA_CARRIER_CHANGES";
        case IFLA_PHYS_SWITCH_ID: return "IFLA_PHYS_SWITCH_ID";
        case IFLA_LINK_NETNSID: return "IFLA_LINK_NETNSID";
        case IFLA_PHYS_PORT_NAME: return "IFLA_PHYS_PORT_NAME";
        case IFLA_PROTO_DOWN: return "IFLA_PROTO_DOWN";
        case IFLA_GSO_MAX_SEGS: return "IFLA_GSO_MAX_SEGS";
        case IFLA_GSO_MAX_SIZE: return "IFLA_GSO_MAX_SIZE";
        case IFLA_PAD: return "IFLA_PAD";
        case IFLA_XDP: return "IFLA_XDP";
        case IFLA_EVENT: return "IFLA_EVENT";
        case IFLA_NEW_NETNSID: return "IFLA_NEW_NETNSID";
        case IFLA_IF_NETNSID: return "IFLA_IF_NETNSID";
        case IFLA_CARRIER_UP_COUNT: return "IFLA_CARRIER_UP_COUNT";
        case IFLA_CARRIER_DOWN_COUNT: return "IFLA_CARRIER_DOWN_COUNT";
        case IFLA_NEW_IFINDEX: return "IFLA_NEW_IFINDEX";
        case IFLA_MIN_MTU: return "IFLA_MIN_MTU";
        case IFLA_MAX_MTU: return "IFLA_MAX_MTU";
        case IFLA_PROP_LIST: return "IFLA_PROP_LIST";
        case IFLA_ALT_IFNAME: return "IFLA_ALT_IFNAME";
        case IFLA_PERM_ADDRESS: return "IFLA_PERM_ADDRESS";
        case IFLA_PROTO_DOWN_REASON: return "IFLA_PROTO_DOWN_REASON";
        case IFLA_PARENT_DEV_NAME: return "IFLA_PARENT_DEV_NAME";
        case IFLA_PARENT_DEV_BUS_NAME: return "IFLA_PARENT_DEV_BUS_NAME";
    }
    snprintf(ret, 9, "%d", val);
    return ret;
}

void read_config() {
    char buf[256], ip[INET_ADDRSTRLEN];
    struct hostent *hp;
    char *pbuf, *purl;
    size_t sz, szn;
    FILE *fp = fopen(SERVER_CONFIG, "r");
    if(!fp) {
        server.s_addr = 0x08080808;
        server_port = 53;
        fprintf(stderr, "Unable to open config file [%d], use ip=8.8.8.8, port=53\n", errno);
        return;
    }
    szn = strlen(SERVER_OPTION);
    while(!feof(fp)) {
        pbuf = fgets(buf, 255, fp);
        if(pbuf) {
            sz = strlen(buf);
            if(sz) buf[sz-1] = 0;
            if(strncmp(SERVER_OPTION, buf, szn) == 0) {
                pbuf += szn;
                purl = pbuf;
                while(*purl && *purl != ':') {
                    purl++;
                }
                if(*purl == ':') {
                    *(purl++) = 0;
                    *(purl++) = 0;
                    *(purl++) = 0;
                }
                if(strcmp(pbuf, "https") == 0) {
                    server_port = 443;
                } else {
                    server_port = 80;
                }

                hp = gethostbyname(purl);
                if(hp) {
                    bcopy(hp->h_addr_list[0], (__caddr_t)&server, hp->h_length);
                } else {
                    server.s_addr = 0x08080808;
                    server_port = 53;
                }
                inet_ntop(AF_INET, &server, ip, INET_ADDRSTRLEN);
                if(verbose)
                    printf("Use URL %s = %s:%d\n", purl, ip, server_port);
            }
        }
    }
    fclose(fp);
}

int parse_reply_interfaces(char *buf, int nll) {
    char *p;
    int rtl;
    struct nlmsghdr *nlp;
    struct ifinfomsg *ifp;
    struct rtattr *ifap;

    nlp = (struct nlmsghdr *) buf;
    for(;NLMSG_OK(nlp, nll);nlp=NLMSG_NEXT(nlp, nll)) {
        ifp = NLMSG_DATA(nlp);
        ifap = IFLA_RTA(ifp);
        rtl = RTM_PAYLOAD(nlp);

        for(;RTA_OK(ifap, rtl);ifap=RTA_NEXT(ifap,rtl)) {
            switch(ifap->rta_type) {
                case IFLA_IFNAME:
                    p = RTA_DATA(ifap);
                    if(p[0] == 'w') { // wireless
                        emak[MOB].ifx = ifp->ifi_index;
                        strncpy(emak[MOB].interface, p, IFNAMSIZ);
                        if(verbose)
                            printf("wireless %s index %d\n", p, emak[MOB].ifx);
                    } else if(p[0] == 'e') { // ethernet
                        emak[ETH].ifx = ifp->ifi_index;
                        strncpy(emak[ETH].interface, p, IFNAMSIZ);
                        if(verbose)
                            printf("ethernet %s index %d\n", p, emak[ETH].ifx);
                    }
                    break;
            }
        }
    }
    return 0;
}

int read_interfaces() {
    struct {
        struct nlmsghdr  nl;
        struct ifinfomsg i;
    } req;
    int nll;
    char *buf = NULL;

    bzero(&req, sizeof(req));

    // set the NETLINK header
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETLINK;

    // set the routing message header
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_change = -1;


    nll = netlink_request(netlink_sck, (void*)&req, &buf, 0);
    if(nll < 0) {
        return -1;
    }
    return parse_reply_interfaces(buf, nll);
}

struct nlmsghdr* set_route_metric(struct nlmsghdr* n, int metric) {
    struct rtmsg *r;
    struct rtattr *a = NULL;
    int l, t;

    r = NLMSG_DATA(n);
    l = NLMSG_PAYLOAD(n, sizeof(struct rtmsg));
    a = RTM_RTA(r);

    while(RTA_OK(a, l)) {
        switch(a->rta_type) {
            case RTA_PRIORITY:

                if (RTA_PAYLOAD(a) != sizeof(int)) {
                    fprintf(stderr, "NETLINK: Recieved corrupt RTA_PRIORITY payload.\n");
                    return NULL;
                }

                *((int*) RTA_DATA(a)) = metric;
                return n;
        }

        a = RTA_NEXT(a, l);
    }

    if ((n = realloc(n, (t = n->nlmsg_len+1024))))
        addattr32(n, t, RTA_PRIORITY, metric);
    else
        fprintf(stderr, "realloc() failed.\n");

    return n;
}

int delete_route(struct nlmsghdr* n) {
    n->nlmsg_type = RTM_DELROUTE;
    n->nlmsg_flags = NLM_F_REQUEST;

    return netlink_request(netlink_sck, n, NULL, 1);
}

int add_route(struct nlmsghdr* n) {
    n->nlmsg_type = RTM_NEWROUTE;
    n->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;

    return netlink_request(netlink_sck, n, NULL, 1);
}

int set_wireless_metric(int metric) {
    int j;
    if (n_routes) {
        for (j = 0; j < n_routes; j++) {
            if (delete_route(routes[j]) >= 0) {
                if ((routes[j] = set_route_metric(routes[j], metric))) {
                    add_route(routes[j]);
                }
            }

            free(routes[j]);
            routes[j] = NULL;
        }
        n_routes = 0;
    }
    return 0;
}

int check_interface(char *ifa_name) {
    int r;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;
    int sock = socket( AF_INET, SOCK_STREAM, 0 );

    if(sock < 0) {
        fprintf(stderr, "Unable to create socket for %s : (%d) %s\n", ifa_name, errno, strerror(errno));
        return 1;
    }

    r = fcntl(sock, F_SETFL, O_NONBLOCK);
    if(r < 0) {
        fprintf(stderr, "Unable to fcntl socket for %s : (%d) %s\n", ifa_name, errno, strerror(errno));
        close(sock);
        return 2;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr = server;
    r = setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifa_name, strlen(ifa_name) );
    if(r < 0) {
        fprintf(stderr, "Unable setsockopt for %s : (%d) %s\n", ifa_name, errno, strerror(errno));
        close(sock);
        return 3;
    }

    connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) );
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = CONNECT_TIMEOUT_S;
    tv.tv_usec = CONNECT_TIMEOUT_uS;

    if(select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error = 1;
        socklen_t len = sizeof so_error;

        r = getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if(r < 0) {
            check_error = errno;
            r = 5;
        } else {
            if (so_error == 0) {
                r = 0;
            } else {
                check_error = so_error;
                r = 4;
            }
        }
    } else {
        check_error = errno;
        r = 6;
    }
    close(sock);
    return r;
}

void check_interfaces() {
    connection_info_t *ci;
    int i, r;
    for (i = 0; i < 2; i++) {
        ci = emak + i;
        if(verbose)
            printf("%s: ", ci->interface);
        r = check_interface(ci->interface);
        ci->valid = r == 0 ? 1 : 0;
        if(!ci->valid && check_error == EINTR)
            return;
        if(verbose) {
            if(ci->valid) {
                printf("has access");
            } else {
                printf("no access");
                if(r == 4) {
                    printf(" [so_error=%s]", strerror(check_error));
                } else {
                    printf(" [%s]", strerror(check_error));
                }
            }
            printf("\n");
        }
    }
    if(emak[ETH].valid && emak[MOB].metric < 700) {
        printf("Switch to Ethernet\n");
        set_wireless_metric(710);
    }
    if(!emak[ETH].valid && emak[MOB].valid && emak[MOB].metric > 700) {
        printf("Switch to Wireless\n");
        set_wireless_metric(10);
    }
}

int parse_reply_routes(char *buf, int nll) {
    // char ip[25];
    int rtl, i;
    struct nlmsghdr *nlp;
    struct nlmsghdr **nlpp;
    connection_info_t *ci;

    nlpp = routes;
    while(*nlpp) {
        free(*nlpp);
        (*nlpp++) = 0;
    }
    n_routes = 0;
    active_cnt = 0;

    struct rtmsg *rtp;
    struct rtattr *rtap;
    struct nlmsghdr* copy;

    nlp = (struct nlmsghdr *) buf;
    for(;NLMSG_OK(nlp, nll);nlp=NLMSG_NEXT(nlp, nll)) {
        rtp = (struct rtmsg *) NLMSG_DATA(nlp);
        if(rtp->rtm_table != RT_TABLE_MAIN)
            continue;

        rtap = (struct rtattr *) RTM_RTA(rtp);
        rtl = RTM_PAYLOAD(nlp);
        int gateway = 0;
        int oif = 0;
        int metric = 0;
        for(;RTA_OK(rtap, rtl);rtap=RTA_NEXT(rtap,rtl)) {
            switch(rtap->rta_type) {
                case RTA_GATEWAY:
                    gateway = 1;
                    // inet_ntop(AF_INET, RTA_DATA(rtap), ip, 25);
                    break;

                case RTA_OIF:
                    oif = *((int *) RTA_DATA(rtap));
                    if(n_routes < MAX_ROUTES) {
                        if(oif == emak[MOB].ifx) { // wwan0
                            if(!(copy = malloc(nlp->nlmsg_len))) {
                                fprintf(stderr, "Could not allocate memory.\n");
                                return -1;
                            }
                            memcpy(copy, nlp, nlp->nlmsg_len);
                            routes[n_routes++] = copy;
                        }
                    } else {
                        fprintf(stderr, "Found too many routes.\n");
                    }
                    break;

                case RTA_PRIORITY:
                    metric = *((int *) RTA_DATA(rtap));
                    break;

                default:
                    break;
            }
        }

        if(gateway) {
            for(i = 0; i <= 2; i++) {
                ci = emak + i;
                if(ci->ifx == oif) {
                    ci->metric = metric;
                    active_cnt++;
                    break;
                }
            }
        }
    }

    return 0;
}

int read_routes() {
    struct {
        struct nlmsghdr nl;
        struct rtmsg    rt;
    } req;
    int nll;
    char *buf = NULL;


    bzero(&req, sizeof(req));
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETROUTE;

    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;

    nll = netlink_request(netlink_sck, (void*)&req, &buf, 0);
    if(nll < 0) {
        return -1;
    }
    return parse_reply_routes(buf, nll);
}

int main(int argc, char *argv[]) {
    struct sysinfo si;
    int i, r = 0, last = 0;

    printf("NetSwitch utility v.%s started\n", VERSION);

    while ((i = getopt_long(argc, argv, "v", long_options, NULL)) != -1) {
        switch(i) {
            case 'v':
                verbose = 1;
                break;

            default:
                break;
        }
    }

    netlink_sck = netlink_open();
    if(netlink_sck < 0) {
        fprintf(stderr, "NETLINK open error\n");
        return 1;
    }

    memset(routes, 0, 64 * sizeof(struct nlmsghdr *));

    signal(SIGUSR1, run_handler);
    signal(SIGUSR2, stop_handler);
    signal(SIGHUP, reload_handler);

reload:
    g_reload = 0;
    read_config();
    if(read_interfaces(netlink_sck) < 0) {
        fprintf(stderr, "Error getting interfaces!\n");
        r = 1;
    }
    for(i = 0; i < 2; i++) {
        if(emak[i].ifx < 0) {
            fprintf(stderr, "Interface %s not found!\n", emak[i].interface);
            r = 1;
        }
    }
    if(r) {
        goto finish;
    }

    while(!g_stop) {
        sysinfo(&si);
        if(last == 0 || si.uptime > last + 10 || g_run) {
            read_routes(netlink_sck);
            if(active_cnt > 1) {
                check_interfaces();
            }
            last = si.uptime;
            if(g_run) {
                g_run = 0;
            }
        }
        if(g_reload) {
            goto reload;
        }
    }
    printf("Stopped by SIGUSR2\n");

finish:
    close(netlink_sck);
    return 0;
}