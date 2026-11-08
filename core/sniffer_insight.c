#include "sniffer_insight.h"

#include <stdio.h>
#include <string.h>

#define SNIFFER_MAX_HOSTS  512
#define SNIFFER_MAX_FLOWS  2048

static sniffer_host_t g_hosts[SNIFFER_MAX_HOSTS];
static int g_host_count;
static sniffer_flow_t g_flows[SNIFFER_MAX_FLOWS];
static int g_flow_count;

const char *sniffer_category_name(sniffer_category_t c) {
	switch (c) {
	case SNIFFER_CAT_ARP:
		return "ARP";
	case SNIFFER_CAT_DNS:
		return "DNS";
	case SNIFFER_CAT_DHCP:
		return "DHCP";
	case SNIFFER_CAT_HTTP:
		return "HTTP";
	case SNIFFER_CAT_TLS:
		return "TLS/HTTPS";
	case SNIFFER_CAT_GAME:
		return "JEU";
	case SNIFFER_CAT_CONSOLE:
		return "CONSOLE";
	case SNIFFER_CAT_ICMP:
		return "ICMP";
	case SNIFFER_CAT_SSDP:
		return "SSDP";
	case SNIFFER_CAT_NBNS:
		return "NBNS";
	case SNIFFER_CAT_SMB:
		return "SMB";
	default:
		return "AUTRE";
	}
}

void sniffer_insight_reset(void) {
	g_host_count = 0;
	g_flow_count = 0;
	memset(g_hosts, 0, sizeof(g_hosts));
	memset(g_flows, 0, sizeof(g_flows));
}

static sniffer_host_t *find_ip(const char *ip) {
	for (int i = 0; i < g_host_count; i++) {
		if (strcmp(g_hosts[i].ip, ip) == 0)
			return &g_hosts[i];
	}
	return NULL;
}

static void upsert_host(const char *ip, const char *mac, const char *alias, uint64_t ts,
                        uint8_t console, uint32_t bytes, int src_to_dst) {
	if (!ip || !ip[0])
		return;
	if (strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "255.255.255.255") == 0)
		return;
	sniffer_host_t *h = find_ip(ip);
	if (!h && g_host_count < SNIFFER_MAX_HOSTS) {
		h = &g_hosts[g_host_count++];
		memset(h, 0, sizeof(*h));
		strncpy(h->ip, ip, sizeof(h->ip) - 1);
	}
	if (!h)
		return;
	if (mac && mac[0])
		strncpy(h->mac, mac, sizeof(h->mac) - 1);
	if (alias && alias[0])
		strncpy(h->alias, alias, sizeof(h->alias) - 1);
	h->last_seen_ms = ts;
	h->packets++;
	if (bytes) {
		if (src_to_dst)
			h->bytes_tx += bytes;
		else
			h->bytes_rx += bytes;
	}
	if (console)
		h->is_console = 1;
}

static int flow_match(const sniffer_flow_t *f, const char *a, uint16_t ap, const char *b,
                      uint16_t bp, const char *proto) {
	if (strcmp(f->proto, proto) != 0)
		return 0;
	if (strcmp(f->ip_a, a) == 0 && f->port_a == ap && strcmp(f->ip_b, b) == 0 && f->port_b == bp)
		return 1;
	if (strcmp(f->ip_a, b) == 0 && f->port_a == bp && strcmp(f->ip_b, a) == 0 && f->port_b == ap)
		return 1;
	return 0;
}

static sniffer_flow_t *upsert_flow(const char *a, uint16_t ap, const char *b, uint16_t bp,
                                   const char *proto, uint32_t bytes, uint64_t ts, const char *hint) {
	if (!a[0] || !b[0] || (ap == 0 && bp == 0))
		return NULL;
	for (int i = 0; i < g_flow_count; i++) {
		if (flow_match(&g_flows[i], a, ap, b, bp, proto)) {
			g_flows[i].bytes += bytes;
			g_flows[i].packets++;
			g_flows[i].last_seen_ms = ts;
			if (hint && hint[0])
				strncpy(g_flows[i].hint, hint, sizeof(g_flows[i].hint) - 1);
			return &g_flows[i];
		}
	}
	if (g_flow_count >= SNIFFER_MAX_FLOWS) {
		memmove(&g_flows[0], &g_flows[1], sizeof(g_flows[0]) * (SNIFFER_MAX_FLOWS - 1));
		g_flow_count = SNIFFER_MAX_FLOWS - 1;
	}
	sniffer_flow_t *f = &g_flows[g_flow_count++];
	memset(f, 0, sizeof(*f));
	strncpy(f->ip_a, a, sizeof(f->ip_a) - 1);
	f->port_a = ap;
	strncpy(f->ip_b, b, sizeof(f->ip_b) - 1);
	f->port_b = bp;
	strncpy(f->proto, proto, sizeof(f->proto) - 1);
	f->bytes = bytes;
	f->packets = 1;
	f->last_seen_ms = ts;
	if (hint && hint[0])
		strncpy(f->hint, hint, sizeof(f->hint) - 1);
	return f;
}

void sniffer_insight_feed(const sniffer_packet_t *pkt) {
	const char *proto =
	    (pkt->l4 == SNIFFER_PROTO_TCP)   ? "TCP"
	    : (pkt->l4 == SNIFFER_PROTO_UDP) ? "UDP"
	                                     : "IP";
	uint8_t console = (pkt->category == SNIFFER_CAT_CONSOLE || pkt->category == SNIFFER_CAT_GAME);

	if (pkt->l3 == SNIFFER_PROTO_IPV4) {
		upsert_host(pkt->src, "", "", pkt->timestamp_ms, console, pkt->caplen, 1);
		upsert_host(pkt->dst, "", "", pkt->timestamp_ms, console, pkt->caplen, 0);
		if (pkt->sport || pkt->dport)
			upsert_flow(pkt->src, pkt->sport, pkt->dst, pkt->dport, proto, pkt->caplen,
			            pkt->timestamp_ms, pkt->info);
	}
	if (pkt->category == SNIFFER_CAT_DNS && pkt->info[0]) {
		const char *dom = strstr(pkt->info, " ");
		if (dom)
			upsert_host(pkt->dst, "", dom + 1, pkt->timestamp_ms, 0, 0, 0);
	}
	if (pkt->category == SNIFFER_CAT_ARP && pkt->src[0] && strchr(pkt->src, '.'))
		upsert_host(pkt->src, "", "ARP", pkt->timestamp_ms, 0, 0, 0);
}

int sniffer_insight_host_count(void) {
	return g_host_count;
}

int sniffer_insight_host_get(int index, sniffer_host_t *out) {
	if (index < 0 || index >= g_host_count || !out)
		return -1;
	*out = g_hosts[index];
	return 0;
}

int sniffer_insight_flow_count(void) {
	return g_flow_count;
}

int sniffer_insight_flow_get(int index, sniffer_flow_t *out) {
	if (index < 0 || index >= g_flow_count || !out)
		return -1;
	*out = g_flows[index];
	return 0;
}
