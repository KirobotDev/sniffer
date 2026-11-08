#ifndef SNIFFER_WINPROC_H
#define SNIFFER_WINPROC_H

#include "sniffer_core.h"
#include "sniffer_insight.h"

#include <stddef.h>
#include <stdint.h>

void sniffer_proc_init(void);
void sniffer_proc_shutdown(void);
void sniffer_proc_refresh(void);

int sniffer_proc_app_count(void);
int sniffer_proc_app_get(int index, char *exe, size_t exe_len, int *conn_out);

void sniffer_proc_set_filter_exe(const char *exe_basename);
const char *sniffer_proc_filter_exe(void);

int sniffer_proc_flow_matches(const sniffer_flow_t *f);
int sniffer_proc_pkt_matches(const sniffer_packet_t *pkt);
int sniffer_proc_host_matches(const sniffer_host_t *h);

typedef struct {
	char     local_ip[48];
	uint16_t local_port;
	char     remote_ip[48];
	uint16_t remote_port;
	char     proto[8];
} sniffer_proc_conn_t;

int sniffer_proc_exe_conn_count(const char *exe);
int sniffer_proc_exe_conn_get(const char *exe, int index, sniffer_proc_conn_t *out);

#endif
