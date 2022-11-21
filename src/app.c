#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <errno.h>
#include <memory.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bits/sockaddr.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include "app.h"
#include "nlrequest.h"
#include "getifn.h"

#define  SERVER_CONFIG  "/home/defigo/.config/Doorbell ink/Doorbell.conf"
#define  SERVER_OPTION  "url="

int check_error = 0;
time_t tmLast = 0;
int g_stop = 0;
int g_run = 0;
pthread_mutex_t mtx_signal;
struct in_addr server = {0L};
int server_port = 0;
int netlink_sck = 0;
int active_cnt = 0;

typedef struct connection_info_s {
    char interface[10];
    char name[24];
    int ifx;
    int metric;
    int status;
    int valid;
} connection_info_t;

connection_info_t emak[2] = {
    {MOB_INTERFACE, MOB_CONNECTION, -1, 0, 0, 0},
    {ETH_INTERFACE, ETH_CONNECTION, -1, 0, 0, 0}
};

void sigusr1_handler(int sig) {
    pthread_mutex_lock(&mtx_signal);
    g_run = 1;
    pthread_mutex_unlock(&mtx_signal);
}

void sigusr2_handler(int sig) {
    pthread_mutex_lock(&mtx_signal);
    g_stop = 1;
    pthread_mutex_unlock(&mtx_signal);
}

void printTime(char *msg) {
    time_t tm = time(NULL);
    printf("%s %ld sec\n", msg, tm - tmLast);
    tmLast = tm;
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
                printf("URL is [%s], ip=%s, port=%d\n", purl, ip, server_port);
            }
        }
    }
    fclose(fp);
}


void check_routes() {

}

void read_reply_ifn(int fd) {
    char buf[8192];
    char ip[25];
    char *p;
    int nll = 0, rtl, rtn;
    struct nlmsghdr *nlp;

    bzero(buf, sizeof(buf));

    p = buf;
    nll = 0;

    // read from the socket until the NLMSG_DONE is
    // returned in the type of the RTNETLINK message
    // or if it was a monitoring socket
    while(1) {
        rtn = recv(fd, p, sizeof(buf) - nll, 0);

        nlp = (struct nlmsghdr *) p;

        if(nlp->nlmsg_type == NLMSG_DONE)
        break;

        // increment the buffer pointer to place
        // next message
        p += rtn;

        // increment the total size by the size of
        // the last received message
        nll += rtn;

        // if((la.nl_groups & RTMGRP_IPV4_ROUTE)
        //                 == RTMGRP_IPV4_ROUTE)
        // break;
    }


    struct ifinfomsg *rtp;
    struct rtattr *rtap;
    // outer loop: loops thru all the NETLINK
    // headers that also include the route entry
    // header
    nlp = (struct nlmsghdr *) buf;
    for(;NLMSG_OK(nlp, nll);nlp=NLMSG_NEXT(nlp, nll)) {
        // get route entry header
        rtp = (struct ifinfomsg *) NLMSG_DATA(nlp);

        // inner loop: loop thru all the attributes of
        // one route entry
        rtap = (struct rtattr *) RTM_RTA(rtp);
        rtl = RTM_PAYLOAD(nlp);
        int gateway = 0;
        unsigned char oif_dmp[8];
        unsigned char priority_dmp[8];
        int oif = 0;
        int metric = 0;
        int len;
        char *data;
        for(;RTA_OK(rtap, rtl);rtap=RTA_NEXT(rtap,rtl)) {
            // print_data(rtap, rtp);
            len = rtap->rta_len;
            switch(rtap->rta_type) {
                case RTA_GATEWAY:
                    gateway = 1;
                    inet_ntop(AF_INET, RTA_DATA(rtap), ip, 25);
                    break;

                case RTA_OIF:
                    oif = *((int *) RTA_DATA(rtap));
                    data = (((char*)(rtap)) + sizeof(struct rtattr));
                    bcopy(data, oif_dmp, MIN(8, len));
                    break;

                case RTA_PRIORITY:
                    metric = *((int *) RTA_DATA(rtap));
                    data = (((char*)(rtap)) + sizeof(struct rtattr));
                    bcopy(data, priority_dmp, MIN(8, len));
                    break;

                default:
                    break;
            }
        }

        if(gateway) {
            printf("oif=%d metric=%d, gw=%s\n", oif, metric, ip);
        }
    }
}

void read_interfaces_old(int fd) {
    // connection_info_t *ci;
    // int i;
    // for (i = 0; i < 2; i++) {
    //     ci = emak + i;
    //     ci->ifx = getifn(netlink_sck, ci->interface);
    //     printf("%-10s: %d\n", ci->interface, ci->ifx);
    // }

    struct {
        struct nlmsghdr  nl;
        struct ifinfomsg i;
        char             buf[8192];
    } req;
    int r;

    bzero(&req, sizeof(req));

    struct sockaddr_nl pa;
    struct iovec iov;
    struct msghdr msg;

    bzero(&pa, sizeof(pa));
    pa.nl_family = AF_NETLINK;

    // set the NETLINK header
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETLINK;

    // set the routing message header
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_change = -1;

    bzero(&iov, sizeof(iov));
    iov.iov_base = (void * )&req.nl;
    iov.iov_len = req.nl.nlmsg_len;

    bzero(&msg, sizeof(msg));
    msg.msg_name = (void*) &pa;
    msg.msg_namelen = sizeof(pa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    r = sendmsg(fd, &msg, 0);
    if(r < 0) {
        fprintf(stderr, "Sendmsg error: %s\n", strerror(errno));
        return;
    }
    read_reply_ifn(fd);
}

    // SOCK_STREAM == TCP
    // SOCK_DGRAM == UDP
    // IP protocol == 0
int check_interface(char *ifa_name, struct in_addr *server) {
    int r;
    struct sockaddr_in addr;
    int sock = socket( AF_INET, SOCK_STREAM, 0 );

    if(sock < 0) {
        fprintf(stderr, "Unable to create socket for %s\n", ifa_name);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr = *server;
    r = setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifa_name, strlen(ifa_name) );
    if(r < 0) {
        fprintf(stderr, "setsockopt error [%d] %s\n", errno, strerror(errno));
        return 2;
    }
    r = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) );
    check_error = r < 0 ? errno : 0;
    close(sock);
    return r;
}

void check_interfaces() {

}

const char* rta_type_name(unsigned short val) {
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
    return "?";
}

const char* rt_table_name(unsigned long val) {
    switch(val) {
        case RT_TABLE_UNSPEC: return "RT_TABLE_UNSPEC";
        case RT_TABLE_COMPAT: return "RT_TABLE_COMPAT";
        case RT_TABLE_DEFAULT: return "RT_TABLE_DEFAULT";
        case RT_TABLE_MAIN: return "RT_TABLE_MAIN";
        case RT_TABLE_LOCAL: return "RT_TABLE_LOCAL";
        case RT_TABLE_MAX: return "RT_TABLE_MAX";
    }
    return "?";
}

void print_data(struct rtattr *rtap, struct rtmsg *rtp) {
    int len = rtap->rta_len;
    char buf[256];
    char *data = (((char*)(rtap)) + sizeof(struct rtattr));
    printf("--- %s [sz=%d] =", rta_type_name(rtap->rta_type), rtap->rta_len);
    for(int i = 0; i < len; i++) {
        printf(" %02X", data[i]);
    }
    switch(rtap->rta_type) {
        case RTA_GATEWAY:
            inet_ntop(AF_INET, RTA_DATA(rtap), buf, 24);
            printf(" == %s", buf);
            break;

        case RTA_DST:
            inet_ntop(AF_INET, RTA_DATA(rtap), buf, 24);
            printf(" == %s/%d", buf, rtp->rtm_dst_len);
            break;

        case RTA_OIF:
        case RTA_METRICS:
        case RTA_PRIORITY:
            printf(" == %d", *((int *) RTA_DATA(rtap)));
            break;

        default:
            break;
    }
    printf("\n");
}

void read_reply(int fd) {
    // string to hold content of the route
    // table (i.e. one entry)
    char buf[8192];
    char ip[25];
    char *p;
    int nll = 0, rtl, rtn, i;
    struct nlmsghdr *nlp;
    connection_info_t *ci;

    // initialize the socket read buffer
    bzero(buf, sizeof(buf));

    p = buf;
    nll = 0;
    active_cnt = 0;

    // read from the socket until the NLMSG_DONE is
    // returned in the type of the RTNETLINK message
    // or if it was a monitoring socket
    while(1) {
        rtn = recv(fd, p, sizeof(buf) - nll, 0);

        nlp = (struct nlmsghdr *) p;

        if(nlp->nlmsg_type == NLMSG_DONE)
        break;

        // increment the buffer pointer to place
        // next message
        p += rtn;

        // increment the total size by the size of
        // the last received message
        nll += rtn;

        // if((la.nl_groups & RTMGRP_IPV4_ROUTE)
        //                 == RTMGRP_IPV4_ROUTE)
        // break;
    }



    struct rtmsg *rtp;
    struct rtattr *rtap;
    // outer loop: loops thru all the NETLINK
    // headers that also include the route entry
    // header
    nlp = (struct nlmsghdr *) buf;
    for(;NLMSG_OK(nlp, nll);nlp=NLMSG_NEXT(nlp, nll)) {
        // get route entry header
        rtp = (struct rtmsg *) NLMSG_DATA(nlp);

        // we are only concerned about the
        // main route table
        if(rtp->rtm_table != RT_TABLE_MAIN)
        continue;

        // inner loop: loop thru all the attributes of
        // one route entry
        rtap = (struct rtattr *) RTM_RTA(rtp);
        rtl = RTM_PAYLOAD(nlp);
        int gateway = 0;
        unsigned char oif_dmp[8];
        unsigned char priority_dmp[8];
        int oif = 0;
        int metric = 0;
        int len;
        char *data;
        for(;RTA_OK(rtap, rtl);rtap=RTA_NEXT(rtap,rtl)) {
            // print_data(rtap, rtp);
            len = rtap->rta_len;
            switch(rtap->rta_type) {
                case RTA_GATEWAY:
                    gateway = 1;
                    inet_ntop(AF_INET, RTA_DATA(rtap), ip, 25);
                    break;

                case RTA_OIF:
                    oif = *((int *) RTA_DATA(rtap));
                    data = (((char*)(rtap)) + sizeof(struct rtattr));
                    bcopy(data, oif_dmp, MIN(8, len));
                    break;

                case RTA_PRIORITY:
                    metric = *((int *) RTA_DATA(rtap));
                    data = (((char*)(rtap)) + sizeof(struct rtattr));
                    bcopy(data, priority_dmp, MIN(8, len));
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
                    printf("%10s[%d] metric : %d  gw %s\n", ci->interface, ci->ifx, ci->metric, ip);
                    break;
                }
            }
        }
    }
}

// void read_routes() {
//     char buf[132];
//     int sz;
//     FILE *f = fopen("/proc/net/route", "r");
//     if(f) {
//         while(!feof(f)) {
//             fgets(buf, 132, f);
//             sz = strlen(buf);
//             if(sz) buf[sz-1] = 0;
//             printf("Read [%s]\n", buf);
//         }
//     } else {
//         printf("Error opening routes\n");
//     }
// }

void read_metrics(int fd) {
    struct {
        struct nlmsghdr nl;
        struct rtmsg    rt;
        char            buf[8192];
    } req;
    int r;

    struct sockaddr_nl pa;
    struct iovec iov;
    struct msghdr msg;

    bzero(&pa, sizeof(pa));
    pa.nl_family = AF_NETLINK;

    bzero(&req, sizeof(req));
    // set the NETLINK header
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETROUTE;

    // set the routing message header
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;

    bzero(&iov, sizeof(iov));
    iov.iov_base = (void * )&req.nl;
    iov.iov_len = req.nl.nlmsg_len;

    bzero(&msg, sizeof(msg));
    msg.msg_name = (void*) &pa;
    msg.msg_namelen = sizeof(pa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    r = sendmsg(fd, &msg, 0);
    if(r < 0) {
        fprintf(stderr, "Sendmsg error: %s\n", strerror(errno));
        return;
    }
    read_reply(fd);
}

void read_interfaces() {
    connection_info_t *ci;
    int i;
    for (i = 0; i < 2; i++) {
        ci = emak + i;
        ci->ifx = if_nametoindex(ci->interface);
        printf("%10s: %d\n", ci->interface, ci->ifx);
    }
}

int main() {
    connection_info_t *ci;
    struct sysinfo si;
    int i, r, last = 0, stop = 0, run = 0;

    netlink_sck = netlink_open();
    if(netlink_sck < 0) {
        fprintf(stderr, "NETLINK open error\n");
        return 1;
    }

    pthread_mutex_init(&mtx_signal, NULL);

    signal(SIGUSR1, sigusr1_handler);
    signal(SIGUSR2, sigusr2_handler);

    tmLast = time(NULL);

    read_config();
    read_interfaces();
    read_interfaces_old(netlink_sck);

    while(1) {
        sysinfo(&si);
        if(last == 0 || si.uptime > last + 60 || run) {
            read_metrics(netlink_sck);
            if(active_cnt > 1) {
                check_interfaces();
                for (i = 0; i < 2; i++) {
                    ci = emak + i;
                    printf("%10s: ", ci->interface);
                    r = check_interface(ci->interface, &server);
                    ci->valid = r;
                    if(r < 0) {
                        ci->valid = 0;
                        // no connection
                        printf("no access [%s]\n", strerror(check_error));
                    } else if(r == 0) {
                        ci->valid = 1;
                        // has connection
                        printf("has access\n");
                    } else {
                        ci->valid = 0;
                        // check error
                        printf("error %d\n", r);
                    }
                    g_stop = 1;
                }
                last = si.uptime;
                if(run) {
                    run = 0;
                    pthread_mutex_lock(&mtx_signal);
                    g_run = 0;
                    pthread_mutex_unlock(&mtx_signal);
                }
            }
        }
        pthread_mutex_lock(&mtx_signal);
        stop = g_stop;
        run = g_run;
        pthread_mutex_unlock(&mtx_signal);
        if(stop) break;
    }
    pthread_mutex_destroy(&mtx_signal);
    close(netlink_sck);
    return 0;
}