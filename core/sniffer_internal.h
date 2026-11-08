#ifndef SNIFFER_INTERNAL_H
#define SNIFFER_INTERNAL_H

#include "sniffer_core.h"

struct sniffer_pcap;
typedef struct sniffer_pcap sniffer_pcap_t;

typedef struct {
	uint64_t ts_ms;
	unsigned caplen;
	unsigned wirelen;
} sniffer_cap_meta_t;

int sniffer_wpcap_available(void);
int sniffer_wpcap_enum_devices(char names[][SNIFFER_DEV_NAME_LEN],
                               char descs[][SNIFFER_DEV_DESC_LEN], int max_count);

sniffer_pcap_t *sniffer_pcap_open(const char *device, char *errbuf, size_t errlen);
void sniffer_pcap_close(sniffer_pcap_t *sp);
int sniffer_pcap_read(sniffer_pcap_t *sp, sniffer_cap_meta_t *meta, const unsigned char **data);
const char *sniffer_pcap_error(sniffer_pcap_t *sp);
void sniffer_wpcap_unload(void);

void sniffer_parse_packet(const unsigned char *data, unsigned caplen, unsigned wirelen,
                          uint64_t ts_ms, sniffer_packet_t *out);

#endif
