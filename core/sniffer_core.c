#include "sniffer_internal.h"
#include "sniffer_insight.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

typedef struct {
	char name[SNIFFER_DEV_NAME_LEN];
	char desc[SNIFFER_DEV_DESC_LEN];
} sniffer_device_t;

static sniffer_device_t g_devices[SNIFFER_MAX_DEVICES];
static int g_device_count;

static sniffer_packet_t g_ring[SNIFFER_RING_SIZE];
static volatile unsigned g_ring_head;
static volatile unsigned g_ring_tail;

static sniffer_stats_t g_stats;
#ifdef _WIN32
static CRITICAL_SECTION g_lock;
#else
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static volatile int g_running;
static sniffer_pcap_t *g_pcap;
#ifdef _WIN32
static HANDLE g_thread;
#else
static pthread_t g_thread;
#endif

static void lock_init(void) {
#ifdef _WIN32
	InitializeCriticalSection(&g_lock);
#endif
}

static void lock_shutdown(void) {
#ifdef _WIN32
	DeleteCriticalSection(&g_lock);
#endif
}

static void lock_enter(void) {
#ifdef _WIN32
	EnterCriticalSection(&g_lock);
#else
	pthread_mutex_lock(&g_lock);
#endif
}

static void lock_leave(void) {
#ifdef _WIN32
	LeaveCriticalSection(&g_lock);
#else
	pthread_mutex_unlock(&g_lock);
#endif
}

static int ring_push(const sniffer_packet_t *p) {
	unsigned next = (g_ring_head + 1) % SNIFFER_RING_SIZE;
	if (next == g_ring_tail) {
		g_stats.dropped++;
		return 0;
	}
	g_ring[g_ring_head] = *p;
	g_ring_head = next;
	return 1;
}

static int ring_pop(sniffer_packet_t *out) {
	lock_enter();
	if (g_ring_tail == g_ring_head) {
		lock_leave();
		return 0;
	}
	*out = g_ring[g_ring_tail];
	g_ring_tail = (g_ring_tail + 1) % SNIFFER_RING_SIZE;
	lock_leave();
	return 1;
}

const char *sniffer_proto_name(sniffer_proto_t p) {
	switch (p) {
	case SNIFFER_PROTO_ARP:
		return "ARP";
	case SNIFFER_PROTO_IPV4:
		return "IPv4";
	case SNIFFER_PROTO_IPV6:
		return "IPv6";
	case SNIFFER_PROTO_ICMP:
		return "ICMP";
	case SNIFFER_PROTO_TCP:
		return "TCP";
	case SNIFFER_PROTO_UDP:
		return "UDP";
	default:
		return "OTHER";
	}
}

int sniffer_init(void) {
	memset(&g_stats, 0, sizeof(g_stats));
	g_ring_head = g_ring_tail = 0;
	sniffer_insight_reset();
	lock_init();

	if (!sniffer_wpcap_available()) {
		snprintf(g_stats.last_error, sizeof(g_stats.last_error),
		         "Npcap / wpcap.dll introuvable");
		return -1;
	}

	char names[SNIFFER_MAX_DEVICES][SNIFFER_DEV_NAME_LEN];
	char descs[SNIFFER_MAX_DEVICES][SNIFFER_DEV_DESC_LEN];
	g_device_count = sniffer_wpcap_enum_devices(names, descs, SNIFFER_MAX_DEVICES);
	for (int i = 0; i < g_device_count; i++) {
		strncpy(g_devices[i].name, names[i], SNIFFER_DEV_NAME_LEN - 1);
		strncpy(g_devices[i].desc, descs[i], SNIFFER_DEV_DESC_LEN - 1);
	}
	return 0;
}

void sniffer_shutdown(void) {
	sniffer_stop();
	lock_shutdown();
	sniffer_wpcap_unload();
}

int sniffer_device_count(void) {
	return g_device_count;
}

int sniffer_device_get(int index, char *name, size_t name_len, char *desc, size_t desc_len) {
	if (index < 0 || index >= g_device_count)
		return -1;
	strncpy(name, g_devices[index].name, name_len - 1);
	name[name_len - 1] = '\0';
	strncpy(desc, g_devices[index].desc, desc_len - 1);
	desc[desc_len - 1] = '\0';
	return 0;
}

static int device_score(const char *desc, const char *name) {
	const char *s = desc[0] ? desc : name;
	if (!s || !s[0])
		return -100;
	if (strstr(s, "Loopback"))
		return -50;
	if (strstr(s, "Miniport"))
		return -40;
	if (strstr(s, "VirtualBox") || strstr(s, "Hyper-V") || strstr(s, "Tailscale"))
		return -10;
	if (strstr(s, "Realtek") || strstr(s, "Ethernet") || strstr(s, "Wi-Fi") || strstr(s, "Wireless"))
		return 100;
	if (strstr(s, "Gigabit") || strstr(s, "2.5GbE"))
		return 90;
	return 10;
}

int sniffer_device_default_index(void) {
	if (g_device_count <= 0)
		return 0;
	int best = 0, best_sc = -999;
	for (int i = 0; i < g_device_count; i++) {
		int sc = device_score(g_devices[i].desc, g_devices[i].name);
		if (sc > best_sc) {
			best_sc = sc;
			best = i;
		}
	}
	return best;
}

#ifdef _WIN32
static unsigned __stdcall capture_thread(void *arg) {
#else
static void *capture_thread(void *arg) {
#endif
	(void)arg;
	while (g_running) {
		sniffer_cap_meta_t meta;
		const unsigned char *data = NULL;
		int rc = sniffer_pcap_read(g_pcap, &meta, &data);
		if (rc == 0)
			continue;
		if (rc == -1) {
			snprintf(g_stats.last_error, sizeof(g_stats.last_error), "%s",
			         sniffer_pcap_error(g_pcap));
			break;
		}

		sniffer_packet_t pkt;
		sniffer_parse_packet(data, meta.caplen, meta.wirelen, meta.ts_ms, &pkt);

		lock_enter();
		ring_push(&pkt);
		g_stats.packets_captured++;
		g_stats.bytes_captured += meta.caplen;
		lock_leave();
	}
	g_running = 0;
	g_stats.capturing = 0;
#ifdef _WIN32
	return 0;
#else
	return NULL;
#endif
}

int sniffer_start(const char *device, const char *bpf_filter) {
	(void)bpf_filter;
	if (g_running)
		return -2;

	char err[256];
	g_pcap = (sniffer_pcap_t *)sniffer_pcap_open(device, err, sizeof(err));
	if (!g_pcap) {
		snprintf(g_stats.last_error, sizeof(g_stats.last_error), "%s", err);
		return -1;
	}

	g_ring_head = g_ring_tail = 0;
	g_running = 1;
	g_stats.capturing = 1;
	g_stats.last_error[0] = '\0';

#ifdef _WIN32
	g_thread = (HANDLE)_beginthreadex(NULL, 0, capture_thread, NULL, 0, NULL);
	if (!g_thread) {
		sniffer_pcap_close(g_pcap);
		g_pcap = NULL;
		g_stats.capturing = 0;
		return -1;
	}
#else
	if (pthread_create(&g_thread, NULL, capture_thread, NULL) != 0) {
		sniffer_pcap_close(g_pcap);
		g_pcap = NULL;
		g_stats.capturing = 0;
		return -1;
	}
#endif
	return 0;
}

int sniffer_stop(void) {
	if (!g_running && !g_pcap)
		return 0;
	g_running = 0;
#ifdef _WIN32
	if (g_thread) {
		WaitForSingleObject(g_thread, 5000);
		CloseHandle(g_thread);
		g_thread = NULL;
	}
#else
	if (g_thread)
		pthread_join(g_thread, NULL);
#endif
	if (g_pcap) {
		sniffer_pcap_close(g_pcap);
		g_pcap = NULL;
	}
	g_stats.capturing = 0;
	return 0;
}

int sniffer_poll(sniffer_packet_t *out) {
	return ring_pop(out);
}

void sniffer_stats(sniffer_stats_t *out) {
	lock_enter();
	*out = g_stats;
	lock_leave();
}
