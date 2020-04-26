#ifndef __NFLOG_UTILS__
#define __NFLOG_UTILS__

#include <libnetfilter_log/libnetfilter_log.h>

int attach_cb(struct nflog_g_handle **qh, struct nflog_handle **h, nflog_callback *cb, unsigned int queue_number);

#endif