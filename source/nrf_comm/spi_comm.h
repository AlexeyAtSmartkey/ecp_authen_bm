#ifndef _NRF_COMM_H_
#define _NRF_COMM_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void SpiHwInit(void (*on_error)(void), void (*on_rx_done)(void), void (*on_tx_done)(void));
void SpiHwExchange(uint8_t *tx, uint8_t *rx, uint16_t len);
void SpiHwReinitForOta(void);

/* Safe default: no-op if you don’t implement abort */
static inline void SpiHwAbort(void) {}

#ifdef __cplusplus
}
#endif
#endif
