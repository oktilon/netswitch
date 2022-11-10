#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <errno.h>
#include <memory.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define  SERVER_ADDR    "webrtc.defigohome.com"
#define  SERVER_PORT    443

int check_error = 0;

typedef struct connection_info_s {
    char *interface[10];
    char *name[24];
    int metric;
    int status;
} connection_info_t;

connection_info_t emak[2] = {
    {"wwan0", "telenor", 0, 0},
    {"eth0",  "Wired_connection_1", 0, 0}
};

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
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr = *server;
    r = setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifa_name, strlen(ifa_name) );
    if(r < 0) {
        return 2;
    }
    r = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) );
    check_error = r < 0 ? errno : 0;
    close(sock);
    return r;
}

int main() {
    struct ifaddrs *ifas, *ifa;
    struct in_addr server;
    struct hostent *hp;
    char buf[64] = {0};
    int r;

    hp = gethostbyname(SERVER_ADDR);
    if(hp) {
        bcopy(hp->h_addr_list[0], (__caddr_t)&server, hp->h_length);
    }

    getifaddrs(&ifas);
    for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strncmp(ifa->ifa_name, "lo", 2) != 0) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr), buf, 64);
            printf("%-8s: %s ", ifa->ifa_name, buf);
            r = check_interface(ifa->ifa_name, &server);
            if(r < 0) {
                // no connection
                printf("no access [%s]\n", strerror(check_error));
            } else if(r == 0) {
                printf("has access\n");
                // has connection
            } else {
                // check error
                printf("error %d\n", r);
            }
        }
    }

    freeifaddrs(ifas);
    return 0;
}