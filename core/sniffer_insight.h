#ifndef SNIFFER_INSIGHT_H
#define SNIFFER_INSIGHT_H

#include "sniffer_core.h"

typedef struct {
	char     ip[48];
	char     mac[24];
	char     alias[160];
	uint64_t last_seen_ms;
	uint64_t packets;
	uint64_t bytes_tx;
	uint64_t bytes_rx;
	uint8_t  is_console;
} sniffer_host_t;

typedef struct {
	char     ip_a[48];
	uint16_t port_a;
	char     ip_b[48];
	uint16_t port_b;
	char     proto[8];
	uint64_t bytes;
	uint64_t packets;
	uint64_t last_seen_ms;
	char     hint[128];
} sniffer_flow_t;

void sniffer_insight_reset(void);
void sniffer_insight_feed(const sniffer_packet_t *pkt);

int sniffer_insight_host_count(void);
int sniffer_insight_host_get(int index, sniffer_host_t *out);

int sniffer_insight_flow_count(void);
int sniffer_insight_flow_get(int index, sniffer_flow_t *out);

const char *sniffer_category_name(sniffer_category_t c);

#endif
