#include "../core/sniffer_core.h"
#include "../core/sniffer_console.h"
#include "../core/sniffer_insight.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
	fprintf(stderr, "Usage: %s [-l] [interface]\n", argv0);
	fprintf(stderr, "  -l  Liste les interfaces puis quitte.\n");
	fprintf(stderr, "  Sans argument: liste puis capture sur la première interface.\n");
}

static int list_devices(void) {
	int n = sniffer_device_count();
	if (n <= 0) {
		fprintf(stderr, "Aucune interface Npcap.\n");
		return 1;
	}
	for (int i = 0; i < n; i++) {
		char name[SNIFFER_DEV_NAME_LEN];
		char desc[SNIFFER_DEV_DESC_LEN];
		sniffer_device_get(i, name, sizeof(name), desc, sizeof(desc));
		sniffer_console_print("[%d] %s", i, desc[0] ? desc : name);
		sniffer_console_print(" — %s\n", name);
	}
	return 0;
}

int main(int argc, char **argv) {
	sniffer_console_init();
	if (sniffer_init() != 0) {
		sniffer_stats_t st;
		sniffer_stats(&st);
		fprintf(stderr, "Init échouée: %s\n", st.last_error);
		return 1;
	}

	if (argc >= 2 && (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0)) {
		int rc = list_devices();
		sniffer_shutdown();
		return rc;
	}

	int n = sniffer_device_count();
	if (n <= 0) {
		fprintf(stderr, "Aucune interface Npcap.\n");
		sniffer_shutdown();
		return 1;
	}

	const char *dev = NULL;
	char name0[SNIFFER_DEV_NAME_LEN];
	if (argc >= 2) {
		dev = argv[1];
	} else {
		if (list_devices() != 0) {
			sniffer_shutdown();
			return 1;
		}
		char desc[SNIFFER_DEV_DESC_LEN];
		sniffer_device_get(0, name0, sizeof(name0), desc, sizeof(desc));
		dev = name0;
		printf("\nCapture sur %s… (Ctrl+C pour arrêter)\n\n", dev);
	}

	if (sniffer_start(dev, NULL) != 0) {
		sniffer_stats_t st;
		sniffer_stats(&st);
		fprintf(stderr, "Démarrage capture: %s\n", st.last_error);
		sniffer_shutdown();
		return 1;
	}

	for (;;) {
		sniffer_packet_t pkt;
		if (!sniffer_poll(&pkt))
			continue;
		const char *proto =
		    sniffer_proto_name(pkt.l4 != SNIFFER_PROTO_OTHER ? pkt.l4 : pkt.l3);
		printf("[%llu ms] [%s] %s %s -> %s | %s | %u o\n", (unsigned long long)pkt.timestamp_ms,
		       sniffer_category_name(pkt.category), proto, pkt.src, pkt.dst, pkt.info, pkt.caplen);
	}

	sniffer_shutdown();
	return 0;
}
