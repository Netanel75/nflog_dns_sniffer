#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <parse_dns.h>
#include <stdbool.h>
#include <errno.h>

#include "nflog_utils.h"
#include "exec_lib.h"

int attach_cb(struct nflog_g_handle **qh, struct nflog_handle **h, nflog_callback *cb, unsigned int queue_number)
{
    int fd;

    *h = nflog_open();
    if (!*h) {
            printf("error during nflog_open()\n");
            return errno * -1;
    }

    printf("unbinding existing nf_log handler for AF_INET (if any)\n");
    if (nflog_unbind_pf(*h, AF_INET) < 0) {
            printf("error nflog_unbind_pf()\n");
            return errno * -1;
    }

    printf("binding nfnetlink_log to AF_INET\n");
    if (nflog_bind_pf(*h, AF_INET) < 0) {
            printf("error during nflog_bind_pf()\n");
            return errno * -1;
    }

    printf("binding this socket to group 1234\n");
    *qh = nflog_bind_group(*h, 1234);
    if (!qh) {
            printf("no handle for group 1234\n");
            return errno * -1;
    }

    if (nflog_callback_register(*qh, cb, NULL) < 0) {
        return errno * -1;
    }

    fd = nflog_fd(*h);
    if (fd < 0) {
        return errno * -1;
    }

    return fd;
}