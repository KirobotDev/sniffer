#include "sniffer_winproc.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

#ifndef NTDDI_WIN6
#define MIB_TCP_STATE_LISTEN 2
#endif

#define SNIFFER_MAX_APPS       96
#define SNIFFER_MAX_FILT_PORTS 2048
#define SNIFFER_MAX_CONN_ROWS  2048

typedef struct {
	char  exe[72];
	int   connections;
	DWORD sample_pid;
} app_row_t;

static app_row_t g_apps[SNIFFER_MAX_APPS];
static int       g_app_count;

static char g_filter_exe[72];

typedef struct {
	uint16_t port;
	uint8_t  tcp;
} filt_port_t;

static filt_port_t g_filt_ports[SNIFFER_MAX_FILT_PORTS];
static int         g_filt_port_n;

typedef struct {
	char     rip[48];
	uint16_t rport;
	uint8_t  tcp;
} filt_remote_t;

static filt_remote_t g_filt_remotes[512];
static int           g_filt_remote_n;

typedef struct {
	char     exe[72];
	char     lip[48];
	uint16_t lp;
	char     rip[48];
	uint16_t rp;
	char     proto[8];
} conn_row_t;

static conn_row_t g_conn_rows[SNIFFER_MAX_CONN_ROWS];
static int        g_conn_row_n;

static void ip4_to_str(uint32_t addr, char *out, size_t n) {
	struct in_addr ia;
	ia.S_un.S_addr = addr;
	strncpy(out, inet_ntoa(ia), n - 1);
	out[n - 1] = 0;
}

static int  get_exe_for_pid(DWORD pid, char *out, size_t n);
static void app_add(DWORD pid);

static void conn_row_add(const char *exe, uint32_t la, uint16_t lp, uint32_t ra, uint16_t rp,
                         const char *proto) {
	if (g_conn_row_n >= SNIFFER_MAX_CONN_ROWS)
		return;
	conn_row_t *c = &g_conn_rows[g_conn_row_n++];
	strncpy(c->exe, exe, sizeof(c->exe) - 1);
	ip4_to_str(la, c->lip, sizeof(c->lip));
	c->lp = lp;
	ip4_to_str(ra, c->rip, sizeof(c->rip));
	c->rp = rp;
	strncpy(c->proto, proto, sizeof(c->proto) - 1);
}

static void record_conn(DWORD pid, uint32_t la, uint16_t lp, uint32_t ra, uint16_t rp,
                        const char *proto) {
	char exe[72];
	if (!get_exe_for_pid(pid, exe, sizeof(exe)))
		snprintf(exe, sizeof(exe), "PID %lu", (unsigned long)pid);
	conn_row_add(exe, la, lp, ra, rp, proto);
	app_add(pid);
}

static void exe_base(const char *path, char *out, size_t n) {
	const char *s = path ? path : "";
	const char *b = strrchr(s, '\\');
	if (!b)
		b = strrchr(s, '/');
	if (b)
		b++;
	else
		b = s;
	strncpy(out, b, n - 1);
	out[n - 1] = 0;
}

static int get_exe_for_pid(DWORD pid, char *out, size_t n) {
	if (!pid || pid == 4)
		return 0;
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h)
		h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h)
		return 0;
	char path[MAX_PATH] = {0};
	DWORD sz = MAX_PATH;
	int ok = 0;
	if (QueryFullProcessImageNameA(h, 0, path, &sz))
		ok = 1;
	else if (GetModuleFileNameExA(h, NULL, path, MAX_PATH))
		ok = 1;
	CloseHandle(h);
	if (!ok || !path[0])
		return 0;
	exe_base(path, out, n);
	return out[0] != 0;
}

static int app_index(const char *exe) {
	for (int i = 0; i < g_app_count; i++) {
		if (_stricmp(g_apps[i].exe, exe) == 0)
			return i;
	}
	return -1;
}

static void app_add(DWORD pid) {
	char exe[72];
	if (!get_exe_for_pid(pid, exe, sizeof(exe)))
		snprintf(exe, sizeof(exe), "PID %lu", (unsigned long)pid);
	int ix = app_index(exe);
	if (ix < 0) {
		if (g_app_count >= SNIFFER_MAX_APPS)
			return;
		ix = g_app_count++;
		memset(&g_apps[ix], 0, sizeof(g_apps[ix]));
		strncpy(g_apps[ix].exe, exe, sizeof(g_apps[ix].exe) - 1);
		g_apps[ix].sample_pid = pid;
	}
	g_apps[ix].connections++;
}

static void filt_port_add(uint16_t port, int tcp) {
	if (!port || g_filt_port_n >= SNIFFER_MAX_FILT_PORTS)
		return;
	for (int i = 0; i < g_filt_port_n; i++) {
		if (g_filt_ports[i].port == port && g_filt_ports[i].tcp == (uint8_t)tcp)
			return;
	}
	g_filt_ports[g_filt_port_n].port = port;
	g_filt_ports[g_filt_port_n].tcp = (uint8_t)tcp;
	g_filt_port_n++;
}

static void filt_remote_add(uint32_t addr, uint16_t port, int tcp) {
	if (g_filt_remote_n >= 512)
		return;
	struct in_addr ia;
	ia.S_un.S_addr = addr;
	char rip[48];
	strncpy(rip, inet_ntoa(ia), sizeof(rip) - 1);
	rip[sizeof(rip) - 1] = 0;
	for (int i = 0; i < g_filt_remote_n; i++) {
		if (g_filt_remotes[i].rport == port && strcmp(g_filt_remotes[i].rip, rip) == 0 &&
		    g_filt_remotes[i].tcp == (uint8_t)tcp)
			return;
	}
	filt_remote_t *r = &g_filt_remotes[g_filt_remote_n++];
	strncpy(r->rip, rip, sizeof(r->rip) - 1);
	r->rport = port;
	r->tcp = (uint8_t)tcp;
}

static int filter_active(void) {
	return g_filter_exe[0] != 0;
}

static int pid_matches_filter(DWORD pid) {
	if (!filter_active())
		return 1;
	char exe[72];
	if (!get_exe_for_pid(pid, exe, sizeof(exe)))
		return 0;
	return _stricmp(exe, g_filter_exe) == 0;
}

static void rebuild_filter_cache(void) {
	g_filt_port_n = 0;
	g_filt_remote_n = 0;
	if (!filter_active())
		return;

	ULONG size = 0;
	if (GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
		return;
	PMIB_TCPTABLE_OWNER_PID tb = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
	if (!tb)
		return;
	if (GetExtendedTcpTable(tb, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
		for (DWORD i = 0; i < tb->dwNumEntries; i++) {
			MIB_TCPROW_OWNER_PID *row = &tb->table[i];
			if (!pid_matches_filter(row->dwOwningPid))
				continue;
			if (row->dwState == MIB_TCP_STATE_LISTEN)
				continue;
			uint16_t lp = ntohs((uint16_t)row->dwLocalPort);
			uint16_t rp = ntohs((uint16_t)row->dwRemotePort);
			filt_port_add(lp, 1);
			filt_remote_add(row->dwRemoteAddr, rp, 1);
		}
	}
	free(tb);

	size = 0;
	if (GetExtendedUdpTable(NULL, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
		return;
	PMIB_UDPTABLE_OWNER_PID ut = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
	if (!ut)
		return;
	if (GetExtendedUdpTable(ut, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
		for (DWORD i = 0; i < ut->dwNumEntries; i++) {
			if (!pid_matches_filter(ut->table[i].dwOwningPid))
				continue;
			uint16_t lp = ntohs((uint16_t)ut->table[i].dwLocalPort);
			filt_port_add(lp, 0);
		}
	}
	free(ut);
}

static int port_in_filter(uint16_t port, int tcp) {
	for (int i = 0; i < g_filt_port_n; i++) {
		if (g_filt_ports[i].port == port && g_filt_ports[i].tcp == (uint8_t)tcp)
			return 1;
	}
	return 0;
}

static int remote_in_filter(const char *ip, uint16_t port, int tcp) {
	if (!ip || !ip[0])
		return 0;
	for (int i = 0; i < g_filt_remote_n; i++) {
		if (g_filt_remotes[i].rport == port && strcmp(g_filt_remotes[i].rip, ip) == 0 &&
		    g_filt_remotes[i].tcp == (uint8_t)tcp)
			return 1;
	}
	return 0;
}

void sniffer_proc_init(void) {
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
	g_filter_exe[0] = 0;
	g_app_count = 0;
}

void sniffer_proc_shutdown(void) {
	WSACleanup();
}

void sniffer_proc_refresh(void) {
	g_app_count = 0;
	g_conn_row_n = 0;

	ULONG size = 0;
	GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	PMIB_TCPTABLE_OWNER_PID tb = NULL;
	if (size) {
		tb = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
		if (tb && GetExtendedTcpTable(tb, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
			for (DWORD i = 0; i < tb->dwNumEntries; i++) {
				MIB_TCPROW_OWNER_PID *row = &tb->table[i];
				record_conn(row->dwOwningPid, row->dwLocalAddr,
				          ntohs((uint16_t)row->dwLocalPort), row->dwRemoteAddr,
				          ntohs((uint16_t)row->dwRemotePort), "TCP");
			}
		}
		free(tb);
	}

	size = 0;
	GetExtendedUdpTable(NULL, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	PMIB_UDPTABLE_OWNER_PID ut = NULL;
	if (size) {
		ut = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
		if (ut && GetExtendedUdpTable(ut, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
			for (DWORD i = 0; i < ut->dwNumEntries; i++) {
				MIB_UDPROW_OWNER_PID *row = &ut->table[i];
				record_conn(row->dwOwningPid, row->dwLocalAddr, ntohs((uint16_t)row->dwLocalPort),
				          0, 0, "UDP");
			}
		}
		free(ut);
	}

	for (int i = 0; i < g_app_count - 1; i++) {
		for (int j = i + 1; j < g_app_count; j++) {
			if (strcmp(g_apps[j].exe, g_apps[i].exe) < 0) {
				app_row_t t = g_apps[i];
				g_apps[i] = g_apps[j];
				g_apps[j] = t;
			}
		}
	}

	rebuild_filter_cache();
}

int sniffer_proc_app_count(void) {
	return g_app_count;
}

int sniffer_proc_app_get(int index, char *exe, size_t exe_len, int *conn_out) {
	if (index < 0 || index >= g_app_count)
		return -1;
	if (exe && exe_len)
		strncpy(exe, g_apps[index].exe, exe_len - 1);
	if (exe && exe_len)
		exe[exe_len - 1] = 0;
	if (conn_out)
		*conn_out = g_apps[index].connections;
	return 0;
}

void sniffer_proc_set_filter_exe(const char *exe_basename) {
	if (!exe_basename || !exe_basename[0])
		g_filter_exe[0] = 0;
	else
		strncpy(g_filter_exe, exe_basename, sizeof(g_filter_exe) - 1);
	g_filter_exe[sizeof(g_filter_exe) - 1] = 0;
	rebuild_filter_cache();
}

const char *sniffer_proc_filter_exe(void) {
	return g_filter_exe;
}

int sniffer_proc_exe_conn_count(const char *exe) {
	if (!exe || !exe[0])
		return 0;
	int n = 0;
	for (int i = 0; i < g_conn_row_n; i++) {
		if (_stricmp(g_conn_rows[i].exe, exe) == 0)
			n++;
	}
	return n;
}

int sniffer_proc_exe_conn_get(const char *exe, int index, sniffer_proc_conn_t *out) {
	if (!exe || !out || index < 0)
		return -1;
	int seen = 0;
	for (int i = 0; i < g_conn_row_n; i++) {
		if (_stricmp(g_conn_rows[i].exe, exe) != 0)
			continue;
		if (seen == index) {
			strncpy(out->local_ip, g_conn_rows[i].lip, sizeof(out->local_ip) - 1);
			out->local_port = g_conn_rows[i].lp;
			strncpy(out->remote_ip, g_conn_rows[i].rip, sizeof(out->remote_ip) - 1);
			out->remote_port = g_conn_rows[i].rp;
			strncpy(out->proto, g_conn_rows[i].proto, sizeof(out->proto) - 1);
			return 0;
		}
		seen++;
	}
	return -1;
}

int sniffer_proc_flow_matches(const sniffer_flow_t *f) {
	if (!f || !filter_active())
		return 1;
	int tcp = strcmp(f->proto, "TCP") == 0;
	int udp = strcmp(f->proto, "UDP") == 0;
	if (!tcp && !udp)
		return 0;
	if (tcp) {
		if (port_in_filter(f->port_a, 1) || port_in_filter(f->port_b, 1))
			return 1;
		if (remote_in_filter(f->ip_a, f->port_a, 1) || remote_in_filter(f->ip_b, f->port_b, 1))
			return 1;
	}
	if (udp) {
		if (port_in_filter(f->port_a, 0) || port_in_filter(f->port_b, 0))
			return 1;
	}
	return 0;
}

int sniffer_proc_pkt_matches(const sniffer_packet_t *pkt) {
	if (!pkt || !filter_active())
		return 1;
	if (pkt->l4 != SNIFFER_PROTO_TCP && pkt->l4 != SNIFFER_PROTO_UDP)
		return 0;
	int tcp = pkt->l4 == SNIFFER_PROTO_TCP;
	if (tcp) {
		if (port_in_filter(pkt->sport, 1) || port_in_filter(pkt->dport, 1))
			return 1;
		if (remote_in_filter(pkt->src, pkt->sport, 1) || remote_in_filter(pkt->dst, pkt->dport, 1))
			return 1;
		if (remote_in_filter(pkt->src, pkt->dport, 1) || remote_in_filter(pkt->dst, pkt->sport, 1))
			return 1;
	} else {
		if (port_in_filter(pkt->sport, 0) || port_in_filter(pkt->dport, 0))
			return 1;
	}
	return 0;
}

int sniffer_proc_host_matches(const sniffer_host_t *h) {
	if (!h || !filter_active())
		return 1;
	for (int i = 0; i < g_filt_remote_n; i++) {
		if (strcmp(g_filt_remotes[i].rip, h->ip) == 0)
			return 1;
	}
	return 0;
}

#else

void sniffer_proc_init(void) {}
void sniffer_proc_shutdown(void) {}
void sniffer_proc_refresh(void) {}

int sniffer_proc_app_count(void) {
	return 0;
}

int sniffer_proc_app_get(int index, char *exe, size_t exe_len, int *conn_out) {
	(void)index;
	(void)exe;
	(void)exe_len;
	(void)conn_out;
	return -1;
}

void sniffer_proc_set_filter_exe(const char *exe_basename) {
	(void)exe_basename;
}

const char *sniffer_proc_filter_exe(void) {
	return "";
}

int sniffer_proc_flow_matches(const sniffer_flow_t *f) {
	(void)f;
	return 1;
}

int sniffer_proc_pkt_matches(const sniffer_packet_t *pkt) {
	(void)pkt;
	return 1;
}

int sniffer_proc_host_matches(const sniffer_host_t *h) {
	(void)h;
	return 1;
}

int sniffer_proc_exe_conn_count(const char *exe) {
	(void)exe;
	return 0;
}

int sniffer_proc_exe_conn_get(const char *exe, int index, sniffer_proc_conn_t *out) {
	(void)exe;
	(void)index;
	(void)out;
	return -1;
}

#endif
