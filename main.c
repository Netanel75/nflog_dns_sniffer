#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <parse_dns.h>
#include <stdbool.h>
#include <signal.h>

#include "exec_lib.h"
#include "nflog_utils.h"

static int print_pkt(struct nflog_data *ldata)
{
    static struct ip_domain ips[30];
    char *payload;
    int payload_len = nflog_get_payload(ldata, &payload);
    unsigned int num_answers;
    int err;
    unsigned int i;
    unsigned int heders_offset;

    if (payload_len >= 0) {
        printf("payload_len=%d\n", payload_len);
    }

    heders_offset = sizeof(struct iphdr) + sizeof(struct udphdr);
    err = parse_dns(ips, (unsigned char*)payload + heders_offset, payload_len - heders_offset, &num_answers);
    if (err) {
        printf("error parsing dns");
    }

    for (i = 0; i < num_answers; ++i) {
        printf("%s: %s\n", ips[i].domain, ips[i].ip);
    }

    return 0;
}

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
              struct nflog_data *nfa, void *data)
{
         print_pkt(nfa);
         return 0;
}

static int rule_cb(struct mbuf *buffer)
{
    if (buffer && buffer->buf) {
        printf("%s\n", buffer->buf);
    }
    return 0;
}

static void nflog_cleanup(int s){
    char *dns_nflog_rule[] = {"iptables", "-D", "INPUT", "-i", "wlp61s0", "-p" ,"udp", "--sport", "53", "-j", "NFLOG", "--nflog-group", "1234", NULL};

    exec_proccess(dns_nflog_rule, false, rule_cb);
}


int main(int argc, char **argv)
{
    struct nflog_handle *h;
    struct nflog_g_handle *qh1234;
    int rv, fd;
    char buf[4096];
    char *dns_nflog_rule[] = {"iptables", "-A", "INPUT", "-i", "wlp61s0", "-p" ,"udp", "--sport", "53", "-j", "NFLOG", "--nflog-group", "1234", NULL};
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = nflog_cleanup;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    exec_proccess(dns_nflog_rule, false, rule_cb);

    fd = attach_cb(&qh1234, &h, cb, 1234);
    if (fd < 0) {
        return EXIT_FAILURE;
    }

    printf("going into main loop\n");
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            printf("pkt received (len=%u)\n", rv);

            /* handle messages in just-received packet */
            nflog_handle_packet(h, buf, rv);
    }

    printf("unbinding from group 100\n");
    nflog_unbind_group(qh1234);
    printf("unbinding from group 0\n");

    printf("closing handle\n");
    nflog_close(h);

    return EXIT_SUCCESS;
}