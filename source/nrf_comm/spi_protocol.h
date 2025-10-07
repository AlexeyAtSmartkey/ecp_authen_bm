#ifndef _NRF_COMM_PROTOCOL_H_
#define _NRF_COMM_PROTOCOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ota.h"
#include "picc_manager.h"
#include "device_manager.h"

#ifndef NRF_COMM_PROTOCOL_BUF_LENGTH
#define NRF_COMM_PROTOCOL_BUF_LENGTH 164
#endif

#ifndef PN_COMM_PROTOCOL_HEADER
#define PN_COMM_PROTOCOL_HEADER 0x4E50
#endif

#ifndef NRF_HEART_BEAT_REQUEST_PERIOD_MS
#define NRF_HEART_BEAT_REQUEST_PERIOD_MS 1000
#endif

typedef enum {
    PN_NFC_READ_DATA       = 0x01,
    PN_HEART_BEAT_STATUS   = 0x02,
    PN_OTA_UPDATE          = 0x03,
    PN_SETTINGS            = 0x04,
    PN_WRITE_CARD          = 0x05,
    PN_CARD_WRITE_FEEDBACK = 0x06,
    PN_GW_READ_DATA_CHUNK  = 0x10,
    PN_GW_READ_DATA_END    = 0x11,
    PN_CARD_READ_ERROR     = 0x81,
} PN_COM_CMD_t;

typedef struct _NRF_STATUS_ {
    uint8_t device_status:1;
    uint8_t card_write_status:1;
    uint8_t settings_status:1;
    uint8_t ota_status:1;
    uint8_t rsvd0:4;
} NRF_Status_t;

/* Safer: load from first payload byte, then access bitfields */
typedef union {
    uint8_t u8;
    NRF_Status_t bits;
} NRF_StatusU;

/* forward declaration — real struct in device_manager.h */
typedef struct _NFC_COMM_STATUS_ NFC_COMM_Status_t;

typedef struct { uint8_t dummy; } PN_Settings_t;
typedef struct { uint8_t dummy; } PN_OTA_Data_t;

/* === Public API === */
void     SpiInit(void);
int      SpiStageIsRx(void);
void     SpiWaitBusFree(void);
void     SpiSend(PN_COM_CMD_t cmd, const uint8_t *data, uint16_t size);
int      SpiIsBusFree(void);
void     SpiTimeout(void);
void     SpiTxComplete(void);
void     SpiRxComplete(void);
void     SpiError(void);
uint16_t Crc16Modbus(const uint8_t *pcBlock, uint16_t len);

/* === Buffers === */
extern uint8_t SpiTxBuf[NRF_COMM_PROTOCOL_BUF_LENGTH];
extern uint8_t SpiTxDummy[NRF_COMM_PROTOCOL_BUF_LENGTH];
extern uint8_t SpiRxBuf[NRF_COMM_PROTOCOL_BUF_LENGTH];
extern volatile uint8_t tx_buf_size;

/* === Backward-compatible aliases === */
// static inline void NRF_COMM_PROTOCOL_init(void) { SpiInit(); }
// static inline void NRF_COMM_PROTOCOL_WaitForBusFree(void) { SpiWaitBusFree(); }
// static inline void NRF_COMM_PROTOCOL_DATA_send(PN_COM_CMD_t c, uint8_t *d, uint16_t s) { SpiSend(c, d, s); }

#ifdef __cplusplus
}
#endif
#endif
