#include <parse_dns.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define TERMINATE_BUFFER(buff) do{buff[sizeof(buff) -1] = 0;}while(0)

int parse_dns(struct ip_domain *ips,
              const unsigned char *msg,
              int msg_len,
              unsigned int *number_of_answers)
{
    ns_msg handle;
    int err;
    uint16_t ancount;
    unsigned int i;
    ns_rr rr;
    char dispbuf[INET6_ADDRSTRLEN];

    err = ns_initparse(msg, msg_len, &handle);
    if (err < 0) {
        perror("couldn't parse packet");
        return errno;
    }

    ancount = ns_msg_count(handle, ns_s_an);

    for (i = 0; i < ancount; ++i) {
        if (ns_parserr(&handle, ns_s_an, i, &rr)) {
            perror("ns_parse failed");
            return errno;
        }

        strncpy(ips[i].domain, rr.name, sizeof(ips[i].domain));
        TERMINATE_BUFFER(ips[i].domain);

        if (ns_rr_type(rr) == ns_t_a) {
            if(!inet_ntop(AF_INET, ns_rr_rdata(rr), dispbuf, sizeof(dispbuf))) {
                return errno;
            }
            ++*number_of_answers;

        } else if (ns_rr_type(rr) == ns_t_aaaa) {
            if(!inet_ntop(AF_INET6, ns_rr_rdata(rr), dispbuf, sizeof(dispbuf))) {
                return errno;
            }
            ++*number_of_answers;
        } else {
            return EAFNOSUPPORT;
        }

        strncpy(ips[i].ip, dispbuf, sizeof(ips[i].ip));
        TERMINATE_BUFFER(ips[i].domain);
    }

    return 0;
}