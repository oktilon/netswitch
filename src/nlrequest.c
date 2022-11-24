#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "nlrequest.h"

char buf[8192];

int netlink_open(void) {
    struct sockaddr_nl addr;
    int s;
                              //SOCK_DGRAM
    if ((s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        fprintf(stderr, "socket(PF_NETLINK): %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = 0;
    addr.nl_pid = getpid();

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(): %s\n", strerror(errno));
        return -1;
    }

    return s;
}


int netlink_request(int fd, struct nlmsghdr *n, char **data, int dont_wait) {
    static int seq = 0;
    char *p;
    int nll = 0, rtn;
    struct nlmsghdr *nlp;
    struct sockaddr_nl pa;
    struct iovec iov;
    struct msghdr msg;
    assert(fd >= 0 && n);

    n->nlmsg_seq = seq++;
    n->nlmsg_flags |= NLM_F_ACK;

    bzero(buf, sizeof(buf));

    bzero(&pa, sizeof(pa));
    pa.nl_family = AF_NETLINK;


    bzero(&iov, sizeof(iov));
    iov.iov_base = (void * )n;
    iov.iov_len = n->nlmsg_len;

    bzero(&msg, sizeof(msg));
    msg.msg_name = (void*) &pa;
    msg.msg_namelen = sizeof(pa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(fd, &msg, 0) < 0) {
        fprintf(stderr, "Sendmsg error: %s\n", strerror(errno));
        return -1;
    }

    if(!dont_wait) {
        p = buf;

        while(1) {
            rtn = recv(fd, p, sizeof(buf) - nll, 0);

            nlp = (struct nlmsghdr *) p;

            if(nlp->nlmsg_type == NLMSG_DONE) break;

            p += rtn;
            nll += rtn;
        }

        if(data) {
            *data = buf;
        }
    }

    return nll;
}

/*
 * Utility function comes from iproute2.
 * Author: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen) {
    int len;
    struct rtattr *rta;

    len = RTA_LENGTH(alen);

    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
        return -1;

    rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy (RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

    return 0;
}

/*
 * Utility function originated from iproute2.
 * Author: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

int addattr32(struct nlmsghdr *n, int maxlen, int type, int data) {
    int len;
    struct rtattr *rta;

    len = RTA_LENGTH(4);

    if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
        return -1;

    rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy (RTA_DATA(rta), &data, 4);
    n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

    return 0;
}

