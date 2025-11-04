#include "spi_protocol.h"
#include "spi_comm.h"
#include "SmartLock.h"
#include <phApp_Init.h>
#include <string.h>

/* External parser */
// void NRF_COMM_PROTOCOL_IN_DATA_process(void);

/* === Internal state === */
typedef enum { ST_TX = 0, ST_RX = 1 } SpiStage_t;
typedef enum { BUS_FREE = 0, BUS_BUSY = 1 } SpiBus_t;

uint8_t SpiTxBuf[NRF_COMM_PROTOCOL_BUF_LENGTH]   = {0};
uint8_t SpiTxDummy[NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};
uint8_t SpiRxBuf[NRF_COMM_PROTOCOL_BUF_LENGTH]   = {0};

static SpiStage_t s_stage = ST_TX;
static SpiBus_t   s_bus   = BUS_FREE;

volatile uint8_t tx_buf_size = 0;
static uint8_t s_cmd_sent = 0;

static uint16_t SpiExpectedRxLen(uint8_t cmd);
static void     SpiStartRx(uint16_t rxlen);
static void     SpiProcessRxFrame(void);
static void     SpiHandleResponse(uint8_t cmd, uint8_t *payload, uint16_t payloadLen);

#ifndef DEBUG_PRINTF
#define DEBUG_PRINTF(...)
#endif

int SpiIsBusFree(void) { return tx_buf_size == 0; }

int SpiStageIsRx(void) { return (s_stage == ST_RX); }

void SpiInit(void) { SpiHwInit(SpiError, SpiRxComplete, SpiTxComplete); }

void SpiWaitBusFree(void) {
    while (tx_buf_size) {}
}

/* ===== UUID + "ready to write" state ===== */
static volatile int s_ready_to_write = 0;
static uint8_t s_uuid[NRF_UUID_LEN] = {0};
static uint8_t s_uuid_len = 0;

void PN_SetReadyToWrite(int ready) {
    s_ready_to_write = (ready != 0);
}

int PN_IsReadyToWrite(void) {
    return s_ready_to_write ? 1 : 0;
}

void PN_UUID_set(const uint8_t *uid, uint8_t len) {
    if (!uid) { s_uuid_len = 0; return; }
    if (len > NRF_UUID_LEN) len = NRF_UUID_LEN;
    for (uint8_t i = 0; i < len; i++) s_uuid[i] = uid[i];
    s_uuid_len = len;
}

uint8_t PN_UUID_get(const uint8_t **uid_out) {
    if (uid_out) *uid_out = s_uuid_len ? s_uuid : NULL;
    return s_uuid_len;
}

void SpiSend(PN_COM_CMD_t cmd, const uint8_t *data, uint16_t size) {
    uint16_t idx = 0;

    if (tx_buf_size) return;

    /* 1) Header (0x4E50 little-endian) */
    SpiTxBuf[idx++] = (uint8_t)(PN_COMM_PROTOCOL_HEADER & 0xFF);
    SpiTxBuf[idx++] = (uint8_t)(PN_COMM_PROTOCOL_HEADER >> 8);

    /* 2) Size field = payload + 3 (cmd + size field itself) */
    uint16_t msg_size = (uint16_t)(size + 3U);
    SpiTxBuf[idx++] = (uint8_t)(msg_size & 0xFF);
    SpiTxBuf[idx++] = (uint8_t)(msg_size >> 8);

    /* 3) Spiand */
    SpiTxBuf[idx++] = (uint8_t)cmd;

    /* 4) Payload */
    for (uint16_t i = 0; i < size; i++) SpiTxBuf[idx++] = data[i];

    /* 5) CRC over everything so far */
    uint16_t crc = Crc16Modbus(SpiTxBuf, idx);
    SpiTxBuf[idx++] = (uint8_t)(crc & 0xFF);
    SpiTxBuf[idx++] = (uint8_t)(crc >> 8);

    /* 6) Kick DMA */
    tx_buf_size = (uint8_t)idx;      /* buffer is 164, fits in uint8_t */
    s_cmd_sent  = (uint8_t)cmd;
    s_bus   = BUS_BUSY;
    s_stage = ST_TX;
    // DEBUG_PRINTF("TX len=%u, first bytes: %02X %02X %02X %02X %02X %02X\n", tx_buf_size, SpiTxBuf[0], SpiTxBuf[1], SpiTxBuf[2], SpiTxBuf[3], SpiTxBuf[4], SpiTxBuf[5]);
    SpiHwExchange(SpiTxBuf, SpiRxBuf, tx_buf_size);
}

void SpiError(void) {
    s_bus = BUS_FREE;
    tx_buf_size = 0;
    s_stage = ST_TX;
}

void SpiTxComplete(void) {
    uint16_t rxlen = SpiExpectedRxLen(s_cmd_sent);
    if (!rxlen) {
        s_bus = BUS_FREE;
        tx_buf_size = 0;
        s_stage = ST_TX;
        return;
    }
    SpiStartRx(rxlen);
}

void SpiRxComplete(void) {
    s_bus = BUS_FREE;
    tx_buf_size = 0;
    s_stage = ST_TX;
    SpiProcessRxFrame();
}

static uint16_t SpiExpectedRxLen(uint8_t cmd) {
    switch (cmd) {
        case PN_NFC_READ_DATA:
        case PN_CARD_WRITE_FEEDBACK:
        case PN_CARD_READ_ERROR:
        case PN_GW_READ_DATA_CHUNK:
        case PN_GW_READ_DATA_END:
        case PN_HEART_BEAT_STATUS:      return 8;
        case PN_WRITE_CARD:             return (uint16_t)(NFC_WRITE_DATA_SIZE + 7);
        case PN_SETTINGS:               return (uint16_t)(sizeof(PN_Settings_t) + 7);
        case PN_OTA_UPDATE:             return (uint16_t)(sizeof(PN_OTA_Data_t) + 7);
        default:                        return 0;
    }
}

static void SpiStartRx(uint16_t rxlen) {
    memset(SpiTxDummy, 0x00, rxlen);
    s_stage = ST_RX;
    SpiHwExchange(SpiTxDummy, SpiRxBuf, rxlen);
}

/* SpiProcessRxFrame: validate header + CRC, then handle cmd.
   No external calls, no undefined symbols. */
static void SpiProcessRxFrame(void) {
    // 1) Header
    const uint16_t hdr = (uint16_t)(SpiRxBuf[0] | ((uint16_t)SpiRxBuf[1] << 8));
    if (hdr != PN_COMM_PROTOCOL_HEADER) { DEBUG_PRINTF("RX: bad hdr %04X\n", hdr); return; }

    // 2) Declared message size (payload + cmd + size field itself = size+3 used on TX)
    const uint16_t msg_sz   = (uint16_t)(SpiRxBuf[2] | ((uint16_t)SpiRxBuf[3] << 8));
    const uint16_t totallen = (uint16_t)(msg_sz + 4U); // 2 hdr + 2 size + msg_sz

    // Sanity: totallen must at least hold header/size/cmd/crc
    if (totallen < 7U) { DEBUG_PRINTF("RX: size too small (%u)\n", totallen); return; }

    // 3) CRC check using the existing helper
    const uint16_t calc = Crc16Modbus(SpiRxBuf, (uint16_t)(totallen - 2U));
    const uint16_t got  = (uint16_t)(SpiRxBuf[totallen - 2U] | ((uint16_t)SpiRxBuf[totallen - 1U] << 8));
    if (calc != got) { 
        DEBUG_PRINTF("RX: CRC mismatch calc=%04X got=%04X\n", calc, got); return; }

    // 4) Spiand + payload
    uint8_t  cmd        = SpiRxBuf[4];
    uint8_t *payload    = &SpiRxBuf[5];
    uint16_t payloadLen = (uint16_t)(msg_sz - 3U); // remove size(2)+cmd(1)

    SpiHandleResponse(cmd, payload, payloadLen);
}

static void SpiHandleResponse(uint8_t cmd, uint8_t *payload, uint16_t payloadLen)
{
    switch (cmd)
    {
        case PN_NFC_READ_DATA:
            break;

        case PN_HEART_BEAT_STATUS:
        {
            if (payloadLen < 1U) break;

            NRF_StatusU st; st.u8 = payload[0];

            if (st.bits.card_write_status) {
                /* Send Card Write command to retrieve data */
                SpiSend(PN_WRITE_CARD, NULL, 0);
            }
            else if (st.bits.settings_status) {
                /* Send Settings command to retrieve data */
                SpiSend(PN_SETTINGS, NULL, 0);
            }
            else if (st.bits.ota_status) {
                /* Stop SysTick */
                SysTick->CTRL &= 0xFFFFFFFEu;

                /* Send OTA Update command to retrieve data */
                SpiSend(PN_OTA_UPDATE, NULL, 0);

                OTA_start();
            }
        } break;

        case PN_SETTINGS:
            break;

        case PN_WRITE_CARD:
            if (payloadLen > 0U) {
                PICC_DATA_TO_WRITE_set(payload);      /* payload == &RX[5] */
                DEVICE_MODE_set(NFC_READER_WRITE_MODE);
                PN_SetReadyToWrite(1);
            }
            break;

        default:
            break;
    }
}

void SpiTimeout(void) {
    SpiHwAbort();
    s_bus = BUS_FREE;
    tx_buf_size = 0;
    s_stage = ST_TX;
}

// uint16_t NRF_COMM_PROTOCOL_CRC16_calculate(uint8_t *pcBlock, uint16_t len)
inline uint16_t Crc16Modbus(const uint8_t *pcBlock, uint16_t len) {
    uint16_t crc = 0xFFFF;
    while (len--) {
        crc ^= *pcBlock++ << 8;
        for (uint8_t i = 0; i < 8; i++) crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
    }
    return crc;
}
