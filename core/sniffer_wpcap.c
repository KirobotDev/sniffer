#include "sniffer_internal.h"
#include "sniffer_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

typedef struct pcap pcap_t;

typedef struct pcap_addr pcap_addr_t;

typedef struct pcap_if {
	struct pcap_if *next;
	char *name;
	char *description;
	pcap_addr_t *addresses;
	unsigned int flags;
} pcap_if_t;

typedef struct pcap_pkthdr {
	long tv_sec;
	long tv_usec;
	unsigned caplen;
	unsigned len;
} pcap_pkthdr_t;

typedef int (*pcap_findalldevs_fn)(pcap_if_t **, char *);
typedef void (*pcap_freealldevs_fn)(pcap_if_t *);
typedef pcap_t *(*pcap_open_live_fn)(const char *, int, int, int, char *);
typedef void (*pcap_close_fn)(pcap_t *);
typedef int (*pcap_next_ex_fn)(pcap_t *, pcap_pkthdr_t **, const unsigned char **);
typedef const char *(*pcap_geterr_fn)(pcap_t *);
typedef int (*pcap_compile_fn)(pcap_t *, void *, const char *, int, unsigned);
typedef int (*pcap_setfilter_fn)(pcap_t *, void *);

typedef struct {
	pcap_findalldevs_fn findalldevs;
	pcap_freealldevs_fn freealldevs;
	pcap_open_live_fn   open_live;
	pcap_close_fn       close;
	pcap_next_ex_fn     next_ex;
	pcap_geterr_fn      geterr;
	int                 loaded;
#ifdef _WIN32
	HMODULE lib;
#else
	void *lib;
#endif
} wpcap_api_t;

static wpcap_api_t g_wpcap;

static int wpcap_load(void) {
	if (g_wpcap.loaded)
		return 1;

#ifdef _WIN32
	const char *paths[] = {
		"wpcap.dll",
		"C:\\Windows\\System32\\Npcap\\wpcap.dll",
		"C:\\Windows\\System32\\wpcap.dll",
	};
	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		g_wpcap.lib = LoadLibraryA(paths[i]);
		if (g_wpcap.lib)
			break;
	}
	if (!g_wpcap.lib)
		return 0;
#define LOAD(sym, name)                                                                        \
	sym = (typeof(sym))GetProcAddress(g_wpcap.lib, name);                                     \
	if (!sym)                                                                                  \
		return 0
#else
	g_wpcap.lib = dlopen("libpcap.so.1", RTLD_LAZY);
	if (!g_wpcap.lib)
		g_wpcap.lib = dlopen("libpcap.so", RTLD_LAZY);
	if (!g_wpcap.lib)
		return 0;
#define LOAD(sym, name)                                                                        \
	sym = (typeof(sym))dlsym(g_wpcap.lib, name);                                              \
	if (!sym)                                                                                  \
		return 0
#endif

	LOAD(g_wpcap.findalldevs, "pcap_findalldevs");
	LOAD(g_wpcap.freealldevs, "pcap_freealldevs");
	LOAD(g_wpcap.open_live, "pcap_open_live");
	LOAD(g_wpcap.close, "pcap_close");
	LOAD(g_wpcap.next_ex, "pcap_next_ex");
	LOAD(g_wpcap.geterr, "pcap_geterr");
#undef LOAD

	g_wpcap.loaded = 1;
	return 1;
}

int sniffer_wpcap_available(void) {
	return wpcap_load();
}

int sniffer_wpcap_enum_devices(char names[][SNIFFER_DEV_NAME_LEN],
                               char descs[][SNIFFER_DEV_DESC_LEN], int max_count) {
	if (!wpcap_load())
		return -1;

	pcap_if_t *all = NULL;
	char err[256] = {0};
	if (g_wpcap.findalldevs(&all, err) != 0)
		return -1;

	int n = 0;
	for (pcap_if_t *d = all; d && n < max_count; d = d->next) {
		if (!d->name)
			continue;
		sniffer_device_normalize(d->name, d->description, names[n], SNIFFER_DEV_NAME_LEN,
		                         descs[n], SNIFFER_DEV_DESC_LEN);
		n++;
	}
	g_wpcap.freealldevs(all);
	return n;
}

struct sniffer_pcap {
	pcap_t *handle;
};

sniffer_pcap_t *sniffer_pcap_open(const char *device, char *errbuf, size_t errlen) {
	if (!wpcap_load()) {
#ifdef _WIN32
		snprintf(errbuf, errlen, "Impossible de charger wpcap.dll (installez Npcap)");
#else
		snprintf(errbuf, errlen, "libpcap introuvable (installez libpcap-dev)");
#endif
		return NULL;
	}
	char ebuf[256] = {0};
	pcap_t *h = g_wpcap.open_live(device, 65536, 1, 200, ebuf);
	if (!h) {
		snprintf(errbuf, errlen, "%s", ebuf[0] ? ebuf : "pcap_open_live a échoué");
		return NULL;
	}
	sniffer_pcap_t *sp = (sniffer_pcap_t *)calloc(1, sizeof(*sp));
	if (!sp) {
		g_wpcap.close(h);
		snprintf(errbuf, errlen, "malloc");
		return NULL;
	}
	sp->handle = h;
	return sp;
}

void sniffer_pcap_close(sniffer_pcap_t *sp) {
	if (!sp)
		return;
	if (sp->handle)
		g_wpcap.close(sp->handle);
	free(sp);
}

int sniffer_pcap_read(sniffer_pcap_t *sp, sniffer_cap_meta_t *meta, const unsigned char **data) {
	pcap_pkthdr_t *h = NULL;
	const unsigned char *d = NULL;
	int rc = g_wpcap.next_ex(sp->handle, &h, &d);
	if (rc != 1 || !h || !meta) {
		*data = d;
		return rc;
	}
	meta->ts_ms = (uint64_t)h->tv_sec * 1000ULL + (uint64_t)h->tv_usec / 1000ULL;
	meta->caplen = h->caplen;
	meta->wirelen = h->len;
	*data = d;
	return rc;
}

const char *sniffer_pcap_error(sniffer_pcap_t *sp) {
	return g_wpcap.geterr(sp->handle);
}

void sniffer_wpcap_unload(void) {
	if (!g_wpcap.loaded)
		return;
#ifdef _WIN32
	FreeLibrary(g_wpcap.lib);
#else
	dlclose(g_wpcap.lib);
#endif
	memset(&g_wpcap, 0, sizeof(g_wpcap));
}
