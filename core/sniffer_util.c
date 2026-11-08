#include "sniffer_util.h"

#include <string.h>

void sniffer_device_normalize(const char *pcap_name, const char *pcap_desc, char *name,
                              size_t name_len, char *desc, size_t desc_len) {
	const char *raw_name = pcap_name ? pcap_name : "";
	const char *raw_desc = (pcap_desc && pcap_desc[0]) ? pcap_desc : "";

	const char *capture = raw_name;
	const char *label = raw_desc;

#ifdef _WIN32
	if (raw_name[0] && !strncmp(raw_name, "\\Device\\NPF_", 14) && raw_desc[0]) {
		capture = raw_name;
		label = raw_desc;
	} else if (raw_desc[0] && !strncmp(raw_desc, "\\Device\\NPF_", 14)) {
		capture = raw_desc;
		label = raw_name;
	} else if (!raw_desc[0]) {
		label = raw_name;
	}
#else
	if (!raw_desc[0])
		label = raw_name;
#endif

	strncpy(name, capture, name_len - 1);
	name[name_len - 1] = '\0';
	strncpy(desc, label, desc_len - 1);
	desc[desc_len - 1] = '\0';
}
