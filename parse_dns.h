#ifndef __PARSE_DNS__
#define __PARSE_DNS__

#include <netinet/in.h>
#include <arpa/nameser.h>

struct ip_domain {
    char ip[INET6_ADDRSTRLEN];
    char domain[MAXDNAME];
};

int parse_dns(struct ip_domain *ips,
              const unsigned char *msg,
              int msg_len,
              unsigned int *number_of_answers);
#endif