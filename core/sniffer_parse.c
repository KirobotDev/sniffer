#include "sniffer_internal.h"
#include "sniffer_insight.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) {
	uint16_t v;
	memcpy(&v, p, 2);
	return sniffer_bswap16(v);
}

static uint32_t rd32(const uint8_t *p) {
	uint32_t hi = sniffer_bswap16(*(const uint16_t *)(p));
	uint32_t lo = sniffer_bswap16(*(const uint16_t *)(p + 2));
	return (hi << 16) | lo;
}

static void mac_str(const uint8_t *m, char *buf, size_t n) {
	snprintf(buf, n, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void ipv4_str(const uint8_t *a, char *buf, size_t n) {
	snprintf(buf, n, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void tcp_flags_str(uint8_t f, char *buf, size_t n) {
	size_t p = 0;
	buf[0] = 0;
	if (f & 0x02) {
		p += snprintf(buf + p, n - p, "SYN ");
	}
	if (f & 0x10) {
		p += snprintf(buf + p, n - p, "ACK ");
	}
	if (f & 0x01) {
		p += snprintf(buf + p, n - p, "FIN ");
	}
	if (f & 0x04) {
		p += snprintf(buf + p, n - p, "RST ");
	}
	if (f & 0x08) {
		p += snprintf(buf + p, n - p, "PSH ");
	}
	if (p == 0) {
		snprintf(buf, n, "0x%02x", f);
	}
}

typedef enum { PORT_NONE, PORT_GAME, PORT_CONSOLE } port_kind_t;

static port_kind_t classify_port(uint16_t port, char *label, size_t n) {
	if (label && n > 0)
		label[0] = 0;
	struct {
		uint16_t     p;
		port_kind_t  k;
		const char  *name;
	} table[] = {
	    {53, PORT_NONE, "DNS"},      {67, PORT_NONE, "DHCP-srv"}, {68, PORT_NONE, "DHCP-cli"},
	    {80, PORT_NONE, "HTTP"},     {443, PORT_NONE, "HTTPS"},   {445, PORT_NONE, "SMB"},
	    {1900, PORT_NONE, "SSDP"},   {137, PORT_NONE, "NBNS"},    {138, PORT_NONE, "NBNS"},
	    {139, PORT_NONE, "NetBIOS"}, {5353, PORT_NONE, "mDNS"},   {5355, PORT_NONE, "LLMNR"},
	    {3074, PORT_CONSOLE, "Xbox Live"}, {88, PORT_CONSOLE, "Xbox/Kerberos"},
	    {500, PORT_CONSOLE, "IKE/IPsec"},  {3544, PORT_CONSOLE, "Xbox Teredo"},
	    {4500, PORT_CONSOLE, "IPsec-NAT"}, {3478, PORT_CONSOLE, "STUN/PSN"},
	    {3479, PORT_CONSOLE, "SCE"},       {3658, PORT_CONSOLE, "PSN"},
	    {9308, PORT_CONSOLE, "PS Remote"}, {27015, PORT_GAME, "Steam"},
	    {27016, PORT_GAME, "Steam"},       {27017, PORT_GAME, "Steam"},
	    {7777, PORT_GAME, "Unreal/GTA"},   {25565, PORT_GAME, "Minecraft"},
	    {51820, PORT_NONE, "WireGuard"},
	};
	for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
		if (table[i].p == port) {
			if (label && n)
				snprintf(label, n, "%s", table[i].name);
			return table[i].k;
		}
	}
	return PORT_NONE;
}

static int parse_dns(const uint8_t *udp, unsigned ulen, char *info, size_t n) {
	if (ulen < 12)
		return 0;
	uint16_t flags = rd16(udp + 2);
	uint16_t qd = rd16(udp + 4);
	if (qd == 0)
		return 0;
	const uint8_t *p = udp + 12;
	const uint8_t *end = udp + ulen;
	char name[192];
	size_t ni = 0;
	while (p < end && *p) {
		uint8_t lab = *p++;
		if (lab > 63 || p + lab > end)
			break;
		if (ni)
			name[ni++] = '.';
		for (uint8_t i = 0; i < lab && ni + 1 < sizeof(name); i++)
			name[ni++] = (char)p[i];
		p += lab;
	}
	name[ni] = 0;
	if (ni == 0)
		return 0;
	const char *typ = (flags & 0x8000) ? "DNS-Réponse" : "DNS-Requête";
	snprintf(info, n, "%s %s", typ, name);
	return 1;
}

static int parse_dhcp(const uint8_t *udp, unsigned ulen, char *info, size_t n) {
	if (ulen < 240)
		return 0;
	uint8_t op = udp[0];
	const char *opn = op == 1 ? "BootREQUEST" : op == 2 ? "BootREPLY" : "Bootp";
	uint32_t yiaddr = rd32(udp + 16);
	char ip[20];
	snprintf(ip, sizeof(ip), "%u.%u.%u.%u", udp[16], udp[17], udp[18], udp[19]);
	const uint8_t *opt = udp + 236;
	unsigned olen = ulen - 236;
	uint8_t msg = 0;
	for (unsigned i = 0; i + 1 < olen;) {
		if (opt[i] == 255)
			break;
		if (opt[i] == 0) {
			i++;
			continue;
		}
		uint8_t code = opt[i++];
		uint8_t ln = opt[i++];
		if (i + ln > olen)
			break;
		if (code == 53 && ln >= 1)
			msg = opt[i];
		i += ln;
	}
	const char *mt = "DHCP";
	switch (msg) {
	case 1:
		mt = "DHCP DISCOVER";
		break;
	case 2:
		mt = "DHCP OFFER";
		break;
	case 3:
		mt = "DHCP REQUEST";
		break;
	case 5:
		mt = "DHCP ACK";
		break;
	default:
		break;
	}
	snprintf(info, n, "%s %s yiaddr=%s", opn, mt, ip);
	(void)yiaddr;
	return 1;
}

static void sniff_http_host(const uint8_t *tcp, unsigned tlen, char *info, size_t n) {
	if (tlen < 16)
		return;
	if (strncmp((const char *)tcp, "GET ", 4) && strncmp((const char *)tcp, "POST ", 5) &&
	    strncmp((const char *)tcp, "HEAD ", 5) && strncmp((const char *)tcp, "HTTP/", 5))
		return;
	const char *host = strstr((const char *)tcp, "\r\nHost: ");
	if (!host)
		host = strstr((const char *)tcp, "\r\nhost: ");
	if (!host)
		return;
	host += 8;
	char h[160];
	size_t i = 0;
	for (; host[i] && host[i] != '\r' && host[i] != '\n' && i + 1 < sizeof(h); i++)
		h[i] = host[i];
	h[i] = 0;
	snprintf(info, n, "HTTP Host: %s", h);
}

static int parse_arp(const uint8_t *arp, unsigned len, char *sip, char *dip, char *info, size_t n) {
	if (len < 28)
		return 0;
	uint16_t op = rd16(arp + 6);
	ipv4_str(arp + 14, sip, 48);
	ipv4_str(arp + 24, dip, 48);
	char smac[24], dmac[24];
	mac_str(arp + 8, smac, sizeof(smac));
	mac_str(arp + 18, dmac, sizeof(dmac));
	if (op == 1)
		snprintf(info, n, "who-has %s tell %s", dip, sip);
	else if (op == 2)
		snprintf(info, n, "%s is-at %s", sip, smac);
	else
		snprintf(info, n, "ARP op=%u %s -> %s", op, sip, dip);
	(void)dmac;
	return (int)op;
}

void sniffer_parse_packet(const unsigned char *data, unsigned caplen, unsigned wirelen,
                          uint64_t ts_ms, sniffer_packet_t *out) {
	memset(out, 0, sizeof(*out));
	out->timestamp_ms = ts_ms;
	out->caplen = caplen;
	out->wirelen = wirelen;
	out->category = SNIFFER_CAT_OTHER;
	if (caplen > SNIFFER_MAX_PACKET)
		caplen = SNIFFER_MAX_PACKET;
	memcpy(out->payload, data, caplen);

	if (caplen < 14) {
		snprintf(out->info, sizeof(out->info), "Trame trop courte");
		return;
	}

	uint16_t ethertype = rd16(data + 12);
	mac_str(data + 6, out->src, sizeof(out->src));
	mac_str(data, out->dst, sizeof(out->dst));

	if (ethertype == 0x0806) {
		out->l3 = SNIFFER_PROTO_ARP;
		out->category = SNIFFER_CAT_ARP;
		if (caplen >= 42) {
			const uint8_t *arp = data + 14;
			char sip[48], dip[48];
			ipv4_str(arp + 14, out->src, sizeof(out->src));
			ipv4_str(arp + 24, out->dst, sizeof(out->dst));
			parse_arp(arp, caplen - 14, sip, dip, out->info, sizeof(out->info));
		} else {
			snprintf(out->info, sizeof(out->info), "ARP");
		}
		sniffer_insight_feed(out);
		return;
	}

	if (ethertype == 0x86DD) {
		out->l3 = SNIFFER_PROTO_IPV6;
		snprintf(out->info, sizeof(out->info), "IPv6");
		return;
	}

	if (ethertype != 0x0800) {
		snprintf(out->info, sizeof(out->info), "EtherType 0x%04x", ethertype);
		return;
	}

	if (caplen < 34) {
		out->l3 = SNIFFER_PROTO_IPV4;
		snprintf(out->info, sizeof(out->info), "IPv4 (tronqué)");
		return;
	}

	const uint8_t *ip = data + 14;
	int ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20)
		return;

	out->l3 = SNIFFER_PROTO_IPV4;
	ipv4_str(ip + 12, out->src, sizeof(out->src));
	ipv4_str(ip + 16, out->dst, sizeof(out->dst));

	uint8_t proto = ip[9];
	unsigned ip_off = 14 + (unsigned)ihl;
	const uint8_t *l4 = data + ip_off;
	unsigned l4len = caplen > ip_off ? caplen - ip_off : 0;

	if (proto == 1 && l4len >= 4) {
		out->l4 = SNIFFER_PROTO_ICMP;
		out->category = SNIFFER_CAT_ICMP;
		uint8_t typ = l4[0], code = l4[1];
		snprintf(out->info, sizeof(out->info), "ICMP type=%u code=%u", typ, code);
		sniffer_insight_feed(out);
		return;
	}

	if (proto == 17 && l4len >= 8) {
		out->l4 = SNIFFER_PROTO_UDP;
		out->sport = rd16(l4);
		out->dport = rd16(l4 + 2);
		unsigned ulen = l4len - 8;
		const uint8_t *udp = l4 + 8;
		char la[48], lb[48];
		classify_port(out->sport, la, sizeof(la));
		classify_port(out->dport, lb, sizeof(lb));
		port_kind_t ka = classify_port(out->sport, la, sizeof(la));
		port_kind_t kb = classify_port(out->dport, lb, sizeof(lb));

		if (out->sport == 53 || out->dport == 53) {
			out->category = SNIFFER_CAT_DNS;
			if (!parse_dns(udp, ulen, out->info, sizeof(out->info)))
				snprintf(out->info, sizeof(out->info), "DNS %u -> %u", out->sport, out->dport);
		} else if (out->sport == 67 || out->dport == 67 || out->sport == 68 || out->dport == 68) {
			out->category = SNIFFER_CAT_DHCP;
			if (!parse_dhcp(udp, ulen, out->info, sizeof(out->info)))
				snprintf(out->info, sizeof(out->info), "DHCP %u -> %u", out->sport, out->dport);
		} else if (out->sport == 137 || out->dport == 137) {
			out->category = SNIFFER_CAT_NBNS;
			snprintf(out->info, sizeof(out->info), "NetBIOS Name Service");
		} else if (out->sport == 1900 || out->dport == 1900) {
			out->category = SNIFFER_CAT_SSDP;
			snprintf(out->info, sizeof(out->info), "SSDP / UPnP multicast");
		} else if (ka == PORT_CONSOLE || kb == PORT_CONSOLE) {
			out->category = SNIFFER_CAT_CONSOLE;
			snprintf(out->info, sizeof(out->info), "Console %s:%u -> %s:%u", la[0] ? la : "?", out->sport,
			         lb[0] ? lb : "?", out->dport);
		} else if (ka == PORT_GAME || kb == PORT_GAME) {
			out->category = SNIFFER_CAT_GAME;
			snprintf(out->info, sizeof(out->info), "Jeu en ligne %u -> %u (%s)", out->sport, out->dport,
			         lb[0] ? lb : la);
		} else {
			snprintf(out->info, sizeof(out->info), "UDP %s:%u -> %s:%u", la[0] ? la : "", out->sport,
			         lb[0] ? lb : "", out->dport);
		}
		sniffer_insight_feed(out);
		return;
	}

	if (proto == 6 && l4len >= 20) {
		out->l4 = SNIFFER_PROTO_TCP;
		out->sport = rd16(l4);
		out->dport = rd16(l4 + 2);
		int doff = ((l4[12] >> 4) & 0xf) * 4;
		uint8_t flags = l4[13];
		char fl[64];
		tcp_flags_str(flags, fl, sizeof(fl));
		unsigned tlen = l4len > (unsigned)doff ? l4len - (unsigned)doff : 0;
		const uint8_t *tcp = l4 + doff;

		char la[48], lb[48];
		port_kind_t ka = classify_port(out->sport, la, sizeof(la));
		port_kind_t kb = classify_port(out->dport, lb, sizeof(lb));

		if (out->dport == 443 || out->sport == 443) {
			out->category = SNIFFER_CAT_TLS;
			snprintf(out->info, sizeof(out->info), "TLS %u -> %u [%s]", out->sport, out->dport, fl);
		} else if (out->dport == 80 || out->sport == 80 || out->dport == 8080) {
			out->category = SNIFFER_CAT_HTTP;
			sniff_http_host(tcp, tlen, out->info, sizeof(out->info));
			if (!out->info[0])
				snprintf(out->info, sizeof(out->info), "HTTP/TCP %u -> %u [%s]", out->sport,
				         out->dport, fl);
		} else if (out->dport == 445 || out->sport == 445) {
			out->category = SNIFFER_CAT_SMB;
			snprintf(out->info, sizeof(out->info), "SMB %u -> %u [%s]", out->sport, out->dport, fl);
		} else if (ka == PORT_CONSOLE || kb == PORT_CONSOLE) {
			out->category = SNIFFER_CAT_CONSOLE;
			snprintf(out->info, sizeof(out->info), "Console TCP %s:%u -> %s:%u [%s]", la, out->sport, lb,
			         out->dport, fl);
		} else if (ka == PORT_GAME || kb == PORT_GAME) {
			out->category = SNIFFER_CAT_GAME;
			snprintf(out->info, sizeof(out->info), "Jeu TCP %u -> %u [%s]", out->sport, out->dport, fl);
		} else {
			snprintf(out->info, sizeof(out->info), "TCP %u -> %u [%s]", out->sport, out->dport, fl);
		}
		sniffer_insight_feed(out);
		return;
	}

	snprintf(out->info, sizeof(out->info), "IPv4 proto=%u", proto);
	sniffer_insight_feed(out);
}
