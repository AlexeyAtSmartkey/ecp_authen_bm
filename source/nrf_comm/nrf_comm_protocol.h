
#ifndef _NRF_COMM_PROTOCOL_H_
#define _NRF_COMM_PROTOCOL_H_

#include <stdint.h>

// Frame format
// header	-	2 bytes
// size		-	2 bytes = sizeof(cmd) + sizeof(payload) + sizeof(crc16)
// cmd		-	1 byte
// payload	-	n bytes
// crc16	-	2 bytes

#define PN_COMM_PROTOCOL_HEADER				0x4E50 //"PN"

//! PN commands
typedef enum _PN_COM_CMD_ {
	PN_NFC_READ_DATA		   				= 0x01, //!< CU TRM sends its location
	PN_HEART_BEAT_STATUS					= 0x02,
	PN_OTA_UPDATE							= 0x03,
	PN_SETTINGS								= 0x04,
	PN_WRITE_CARD							= 0x05,
	PN_CARD_WRITE_FEEDBACK					= 0x06,
	PN_GW_READ_DATA_CHUNK					= 0x10,
	PN_GW_READ_DATA_END						= 0x11,
	PN_CARD_READ_ERROR						= 0x81
} PN_COM_CMD_t;

typedef enum _NRF_COMM_STAGE_ {
	NRF_COMM_TX_STAGE,
	NRF_COMM_WAIT_STAGE,
	NRF_COMM_RX_STAGE,
	NRF_COMM_PROC_STAGE
}NRF_COMM_Stage_t;

typedef enum _NRF_COMM_BUS_STATE_ {
	NRF_COMM_BUS_FREE,
	NRF_COMM_BUS_BUSY
}NRF_COMM_BUS_State_t;

// Data receive results
typedef enum _NRF_COMM_RESULTS_ {
	NRF_COMM_SUCCESS,
	NRF_COMM_CMD_FAILED,
	NRF_COMM_FAILURE
}NRF_COMM_Results_t;

// NRF cmd execution results
typedef enum _NRF_COMM_CMD_EXEC_RESULTS_ {
	NRF_COMM_CMD_EXEC_SUCCESS,
	NRF_COMM_CMD_EXEC_FAILED,
}NRF_COMM_CMD_EXEC_Results_t;

#pragma pack(push, 1)

typedef struct _NRF_STATUS_ {
	uint8_t device_status:1;
	uint8_t card_write_status:1;
	uint8_t settings_status:1;
	uint8_t ota_status:1;
	uint8_t rsvd0:4;
}NRF_Status_t;

typedef struct _PN_OTA_DATA_ {
	uint8_t active_data_size;
	uint8_t payload[128];

}PN_OTA_Data_t;


typedef struct _PN_SETTINGS_
{
	uint8_t picc_master_key[16];
	uint8_t picc_app_master_key[16];
	uint8_t pn_app_root_key[16];

}PN_Settings_t;

#pragma pack(pop)

#define PN_DATA_WRITE_SIZE_BYTES			16

extern uint8_t HeartbeatReceived;

void NRF_COMM_PROTOCOL_init(void);

void NRF_COMM_PROTOCOL_WaitForBusFree(void);

void NRF_COMM_PROTOCOL_DATA_send(PN_COM_CMD_t cmd, uint8_t *data, uint16_t size);

// void NRF_COMM_PROTOCOL_DATA_sendFromISR(PN_COM_CMD_t cmd, uint8_t *data, uint16_t size);

uint16_t NRF_COMM_PROTOCOL_CRC16_calculate(uint8_t *pcBlock, uint16_t len);

#endif // _NRF_COMM_PROTOCOL_H_
