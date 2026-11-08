#ifndef SNIFFER_CORE_H
#define SNIFFER_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#ifdef SNIFFER_BUILD_DLL
#define SNIFFER_API __declspec(dllexport)
#elif defined(SNIFFER_STATIC)
#define SNIFFER_API
#else
#define SNIFFER_API __declspec(dllimport)
#endif
#else
#define SNIFFER_API
#endif

#define SNIFFER_MAX_PACKET   2048
#define SNIFFER_MAX_DEVICES  64
#define SNIFFER_DEV_NAME_LEN 256
#define SNIFFER_DEV_DESC_LEN 512
#define SNIFFER_RING_SIZE    4096

typedef enum {
	SNIFFER_PROTO_OTHER = 0,
	SNIFFER_PROTO_ARP   = 1,
	SNIFFER_PROTO_IPV4  = 2,
	SNIFFER_PROTO_IPV6  = 3,
	SNIFFER_PROTO_ICMP  = 4,
	SNIFFER_PROTO_TCP   = 5,
	SNIFFER_PROTO_UDP   = 6,
} sniffer_proto_t;

typedef enum {
	SNIFFER_CAT_OTHER   = 0,
	SNIFFER_CAT_ARP     = 1,
	SNIFFER_CAT_DNS     = 2,
	SNIFFER_CAT_DHCP    = 3,
	SNIFFER_CAT_HTTP    = 4,
	SNIFFER_CAT_TLS     = 5,
	SNIFFER_CAT_GAME    = 6,
	SNIFFER_CAT_CONSOLE = 7,
	SNIFFER_CAT_ICMP    = 8,
	SNIFFER_CAT_SSDP    = 9,
	SNIFFER_CAT_NBNS    = 10,
	SNIFFER_CAT_SMB     = 11,
} sniffer_category_t;

typedef struct {
	uint64_t            timestamp_ms;
	uint32_t            wirelen;
	uint32_t            caplen;
	sniffer_proto_t     l3;
	sniffer_proto_t     l4;
	sniffer_category_t  category;
	uint16_t            sport;
	uint16_t            dport;
	char                src[48];
	char                dst[48];
	char                info[256];
	uint8_t             payload[SNIFFER_MAX_PACKET];
} sniffer_packet_t;

typedef struct {
	uint64_t packets_captured;
	uint64_t bytes_captured;
	uint64_t dropped;
	int      capturing;
	char     last_error[256];
} sniffer_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Fonctions assembleur x86 (asm/sniffer_x86.S) */
uint16_t sniffer_bswap16(uint16_t v);
uint32_t sniffer_fold_checksum(uint32_t sum, const uint8_t *data, size_t len);

SNIFFER_API int  sniffer_init(void);
SNIFFER_API void sniffer_shutdown(void);

SNIFFER_API int sniffer_device_count(void);
SNIFFER_API int sniffer_device_get(int index, char *name, size_t name_len,
                                   char *desc, size_t desc_len);
SNIFFER_API int sniffer_device_default_index(void);

SNIFFER_API int sniffer_start(const char *device, const char *bpf_filter);
SNIFFER_API int sniffer_stop(void);

SNIFFER_API int sniffer_poll(sniffer_packet_t *out);
SNIFFER_API void sniffer_stats(sniffer_stats_t *out);

SNIFFER_API const char *sniffer_proto_name(sniffer_proto_t p);

#ifdef __cplusplus
}
#endif

#endif
