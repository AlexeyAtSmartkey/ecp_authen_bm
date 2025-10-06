
#ifndef _NRF_COMM_H_
#define _NRF_COMM_H_

#include <stdint.h>

void NRF_COMM_init(void (*error_callback)(void), void (*read_cmplt_callback)(void), void (*write_cmplt_callback)(void));

void NRF_COMM_reinitForOta(void);

void NRF_COMM_DATA_exchange(uint8_t *tx_data, uint8_t *rx_data, uint16_t size);

#endif // _NRF_COMM_H_
