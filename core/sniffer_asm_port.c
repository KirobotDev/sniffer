#include "sniffer_core.h"

#include <stddef.h>
#include <stdint.h>

uint16_t sniffer_bswap16(uint16_t v) {
	return (uint16_t)((v >> 8) | (v << 8));
}

uint32_t sniffer_fold_checksum(uint32_t sum, const uint8_t *data, size_t len) {
	uint32_t acc = sum;
	for (size_t i = 0; i + 1 < len; i += 2)
		acc += (uint32_t)((data[i] << 8) | data[i + 1]);
	return acc;
}
