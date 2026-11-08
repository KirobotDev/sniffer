#ifndef SNIFFER_UTIL_H
#define SNIFFER_UTIL_H

#include <stddef.h>

/* name = identifiant pour pcap_open_live, label = texte affiché */
void sniffer_device_normalize(const char *pcap_name, const char *pcap_desc, char *name,
                              size_t name_len, char *desc, size_t desc_len);

#endif
