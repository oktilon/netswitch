#ifndef foonlrequesthfoo
#define foonlrequesthfoo

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

int netlink_request(int fd, struct nlmsghdr *n, char **data);

int addattr32(struct nlmsghdr *n, int maxlen, int type, int data);
int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen);

int netlink_open(void);


#endif

