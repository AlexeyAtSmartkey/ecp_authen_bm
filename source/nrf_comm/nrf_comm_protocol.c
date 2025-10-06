#include <phApp_Init.h>
#include <string.h>
#include <cr_section_macros.h>
#include "nrf_comm_protocol.h"
#include "nrf_comm.h"
#include "nfc_comm.h"
#include "ota.h"
#include "picc_manager.h"
#include "device_manager.h"
#include "SmartLock.h"
#include "taskmanager.h"
#include <stdbool.h>

#define NRF_HEART_BEAT_REQUEST_PERIOD_MS 1000

#define NRF_DELAY_BEFORE_RX_MS           2

#define NRF_COMM_PROTOCOL_BUF_LENGTH     164


static void NRF_COMM_ERROR_handle(void);
static void NRF_COMM_RX_CMPLT_handle(void);
static void NRF_COMM_TX_CMPLT_handle(void);

static NRF_COMM_Results_t NRF_COMM_PROTOCOL_IN_DATA_process(void);

void nrfCommHeartbeatTask(void);

void nrfCommDataExchangeTask(void);

uint8_t HeartbeatReceived = 0;

uint8_t NRF_COMM_PROTOCOL_PACKET_Buf  [NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};

uint8_t NRF_COMM_PROTOCOL_TX_Buf      [NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};
// uint8_t NRF_COMM_PROTOCOL_TX_Buf_ISR[NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};
uint8_t NRF_COMM_PROTOCOL_TX_Buf_dummy[NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};

uint8_t NRF_COMM_PROTOCOL_RX_Buf      [NRF_COMM_PROTOCOL_BUF_LENGTH] = {0};

static NRF_COMM_Stage_t NRF_COMM_Stage = NRF_COMM_TX_STAGE;

static NRF_COMM_BUS_State_t NRF_COMM_BUS_State = NRF_COMM_BUS_FREE;


volatile uint8_t tx_buf_size = 0;
// uint8_t tx_buf_isr_size = 0;

uint8_t *active_buf = 0;

uint8_t cmd_sent;

uint8_t delay_ms_cntr = 0;

//-------------------------------------------------------------
void NRF_COMM_PROTOCOL_init(void) {
	
	NRF_COMM_init(																// Initialize peripheral
		NRF_COMM_ERROR_handle, 
		NRF_COMM_RX_CMPLT_handle, 
		NRF_COMM_TX_CMPLT_handle
	);

	TIME_TASK_create(&nrfCommDataExchangeTask, 1);								// Create exchange control task

	TIME_TASK_create(&nrfCommHeartbeatTask, NRF_HEART_BEAT_REQUEST_PERIOD_MS);	// Send heart beat periodically
}

//-------------------------------------------------------------
void nrfCommHeartbeatTask(void) {
	// NRF_COMM_PROTOCOL_DATA_sendFromISR(											// Send heart beat data request
	// 	PN_HEART_BEAT_STATUS, 
	// 	(uint8_t *)DEVICE_STATUS_get(), 
	// 	sizeof(NFC_COMM_Status_t)
	// );
	// DEBUG_PRINTF("HB\n");
	// NRF_COMM_PROTOCOL_DATA_send(PN_HEART_BEAT_STATUS, (uint8_t *)DEVICE_STATUS_get(), sizeof(NFC_COMM_Status_t));// Send heart beat data request
	HeartbeatReceived = 1;
}

void NRF_COMM_PROTOCOL_WaitForBusFree(void) {
    // spin—and optionally sleep—until the DMA callback clears BUS_BUSY
    // while (
	// 	NRF_COMM_Stage != NRF_COMM_TX_STAGE ||
    //     NRF_COMM_BUS_State == NRF_COMM_BUS_BUSY
	// ) __WFI();
	uint32_t timeout = 1000; // 100 ms timeout
    while (tx_buf_size != 0 && --timeout) __WFI();
}

//-------------------------------------------------------------
void NRF_COMM_PROTOCOL_DATA_send(PN_COM_CMD_t cmd, uint8_t *data, uint16_t size) {
	uint16_t idx = 0;

	if (!size || tx_buf_size) {
		DEBUG_PRINTF("NRF_COMM_PROTOCOL_DATA_send: tx_buf_size %02x or size %02x\n", tx_buf_size, size);
		return;
	}

    uint16_t *header = ((uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf[idx++]);
	*header = PN_COMM_PROTOCOL_HEADER;	                                            // Add header
	idx++;

    uint16_t *msg_size = ((uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf[idx++]);
	*msg_size = size + 3;					                                        // Add size + msg + header
	idx++;

	NRF_COMM_PROTOCOL_TX_Buf[idx++]     = cmd;                  	    			// Add cmd

	for(uint16_t i = 0; i < size; i++) 
        NRF_COMM_PROTOCOL_TX_Buf[idx++] = data[i];                      			// Add payload

    uint16_t *crc = (uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf[idx];
	*crc = NRF_COMM_PROTOCOL_CRC16_calculate(NRF_COMM_PROTOCOL_TX_Buf, idx);         // Add crc16
	idx++;
	idx++;
	tx_buf_size = idx;
}

//-------------------------------------------------------------
// void NRF_COMM_PROTOCOL_DATA_sendFromISR(PN_COM_CMD_t cmd, uint8_t *data, uint16_t size)
// {
// 	uint16_t idx = 0;

// 	if(tx_buf_isr_size != 0)
// 		return;

// 	// Add header
// 	*((uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf_ISR[idx]) = PN_COMM_PROTOCOL_HEADER;
// 	idx += 2;

// 	// Add size
// 	*((uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf_ISR[idx]) = size + 3;
// 	idx += 2;

// 	// Add cmd
// 	NRF_COMM_PROTOCOL_TX_Buf_ISR[idx] = cmd;
// 	idx += 1;

// 	// Add payload
// 	for(uint16_t i = 0; i < size; i++)
// 	{
// 		NRF_COMM_PROTOCOL_TX_Buf_ISR[idx] = data[i];
// 		idx += 1;
// 	}

// 	// Add crc16
// 	*((uint16_t *)&NRF_COMM_PROTOCOL_TX_Buf_ISR[idx]) = NRF_COMM_PROTOCOL_CRC16_calculate(NRF_COMM_PROTOCOL_TX_Buf_ISR, idx);
// 	idx += 2;

// 	tx_buf_isr_size = idx;
// }

//-------------------------------------------------------------
void nrfCommDataExchangeTask(void)
{
	uint16_t bytes_to_receive = 0;

	switch(NRF_COMM_Stage)
	{
		case NRF_COMM_TX_STAGE:

			if(tx_buf_size != 0) {
				// Save active buffer
				active_buf = NRF_COMM_PROTOCOL_TX_Buf;

				// Save cmd was sent
				cmd_sent = NRF_COMM_PROTOCOL_TX_Buf[4];

				// Start data sending
				NRF_COMM_DATA_exchange(NRF_COMM_PROTOCOL_TX_Buf, NRF_COMM_PROTOCOL_RX_Buf, tx_buf_size);

				// Provide 2 ms delay
				delay_ms_cntr = 0;

				NRF_COMM_Stage = NRF_COMM_WAIT_STAGE;
			}/* else if(tx_buf_isr_size != 0) {
				// Save active buffer
				active_buf = NRF_COMM_PROTOCOL_TX_Buf_ISR;

				// Save cmd was sent
				cmd_sent = NRF_COMM_PROTOCOL_TX_Buf_ISR[4];

				// Start data sending
				NRF_COMM_DATA_exchange(NRF_COMM_PROTOCOL_TX_Buf_ISR, NRF_COMM_PROTOCOL_RX_Buf, tx_buf_isr_size);

				// Provide 2 ms delay
				delay_ms_cntr = 0;

				NRF_COMM_Stage = NRF_COMM_WAIT_STAGE;
			}*/

			break;

		case NRF_COMM_WAIT_STAGE:

			if(++delay_ms_cntr >= NRF_DELAY_BEFORE_RX_MS) {
				NRF_COMM_Stage = NRF_COMM_RX_STAGE;
			}

			break;

		case NRF_COMM_RX_STAGE:

			// Start response reception
			uint8_t one_of_cmd = (
				(cmd_sent == PN_NFC_READ_DATA)       || 
				(cmd_sent == PN_CARD_WRITE_FEEDBACK) || 
				(cmd_sent == PN_CARD_READ_ERROR)     ||
				(cmd_sent == PN_GW_READ_DATA_CHUNK)  ||
				(cmd_sent == PN_GW_READ_DATA_END)    ||
				(cmd_sent == PN_HEART_BEAT_STATUS)
			);

			if(one_of_cmd) {
				bytes_to_receive = 8; // header + size + cmd + success byte + crc16
			// } else if(cmd_sent == PN_HEART_BEAT_STATUS) {
			// 	bytes_to_receive = 8; // header + size + cmd + status byte + crc16
			} else if(cmd_sent == PN_WRITE_CARD) {
				bytes_to_receive = NFC_WRITE_DATA_SIZE + 7; // header + size + cmd + bytes to write + crc16
			} else if(cmd_sent == PN_SETTINGS) {
				bytes_to_receive = sizeof(PN_Settings_t) + 7; // header + size + cmd + bytes to write + crc16
			} else if(cmd_sent == PN_OTA_UPDATE) {
				bytes_to_receive = sizeof(PN_OTA_Data_t) + 7; // header + size + cmd + bytes to write + crc16
			} else {
				tx_buf_size = 0; 						// No data to receive
				NRF_COMM_Stage = NRF_COMM_TX_STAGE; 	// Reset stage
				break;
			}

			// Set TX buffer to all 0s as dummy bytes
			for(uint16_t i = 0; i < bytes_to_receive; i++) {
				NRF_COMM_PROTOCOL_TX_Buf_dummy[i] = 0;
			}

			// Start data sending
			NRF_COMM_DATA_exchange(NRF_COMM_PROTOCOL_TX_Buf_dummy, NRF_COMM_PROTOCOL_RX_Buf, bytes_to_receive);

			// Wait for process stage
			NRF_COMM_Stage = NRF_COMM_PROC_STAGE;

			break;

		case NRF_COMM_PROC_STAGE:

			// Mark active buffer as free
			if(active_buf == NRF_COMM_PROTOCOL_TX_Buf) {
				tx_buf_size = 0;
			}/* else if(active_buf == NRF_COMM_PROTOCOL_TX_Buf_ISR) {
				tx_buf_isr_size = 0;
			}*/

			// Process received data
			NRF_COMM_PROTOCOL_IN_DATA_process();

			// Reset stage
			NRF_COMM_Stage = NRF_COMM_TX_STAGE;

			break;

		default:

			break;
	}
}

//-------------------------------------------------------------
NRF_COMM_Results_t NRF_COMM_PROTOCOL_IN_DATA_process(void)
{
	uint16_t header;
	uint16_t size;
	PN_COM_CMD_t cmd;
	NRF_COMM_CMD_EXEC_Results_t cmd_exec_res;
	uint8_t *payload;
	uint16_t crc16;


	header = *((uint16_t *)&NRF_COMM_PROTOCOL_RX_Buf[0]);
	size = *((uint16_t *)&NRF_COMM_PROTOCOL_RX_Buf[2]);

	if(header != PN_COMM_PROTOCOL_HEADER)
	{
		return NRF_COMM_FAILURE;
	}

	crc16 = *((uint16_t *)&NRF_COMM_PROTOCOL_RX_Buf[sizeof(header) + sizeof(size) + size - sizeof(crc16)]);

	if(crc16 != NRF_COMM_PROTOCOL_CRC16_calculate(NRF_COMM_PROTOCOL_RX_Buf, sizeof(header) + sizeof(size) + size - sizeof(crc16)))
	{
		return NRF_COMM_FAILURE;
	}

	cmd_exec_res = NRF_COMM_PROTOCOL_RX_Buf[5];

	if(cmd_exec_res == NRF_COMM_CMD_EXEC_FAILED)
		return NRF_COMM_CMD_FAILED;


	cmd = NRF_COMM_PROTOCOL_RX_Buf[4];

	switch(cmd)
	{
		case PN_NFC_READ_DATA:

			break;

		case PN_HEART_BEAT_STATUS:

			// Check status bits
			if((*(NRF_Status_t *)&NRF_COMM_PROTOCOL_RX_Buf[5]).card_write_status)
			{
				// Send Card Write command to retrieve data
				NRF_COMM_PROTOCOL_DATA_send(PN_WRITE_CARD, NULL, 0);
			}
			else
			if((*(NRF_Status_t *)&NRF_COMM_PROTOCOL_RX_Buf[5]).settings_status)
			{
				// Send Settings command to retrieve data
				NRF_COMM_PROTOCOL_DATA_send(PN_SETTINGS, NULL, 0);
			}
			else
			if((*(NRF_Status_t *)&NRF_COMM_PROTOCOL_RX_Buf[5]).ota_status)
			{
				// Stop SysTick
				SysTick->CTRL &= 0xFFFFFFFE;

				// Send OTA Update command to retrieve data
				// NRF_COMM_PROTOCOL_DATA_sendFromISR(PN_OTA_UPDATE, NULL, 0);
				NRF_COMM_PROTOCOL_DATA_send(PN_OTA_UPDATE, NULL, 0);

				OTA_start();
			}

			break;

		case PN_SETTINGS:

			break;

		case PN_WRITE_CARD:

			// Store data to be written
			PICC_DATA_TO_WRITE_set(&NRF_COMM_PROTOCOL_RX_Buf[5]);

			// Change reader activity
			DEVICE_MODE_set(NFC_READER_WRITE_MODE);

			break;

		default:

			break;
	}

	return NRF_COMM_SUCCESS;
}

//-------------------------------------------------------------
__TEXT(Flash2) uint16_t NRF_COMM_PROTOCOL_CRC16_calculate(uint8_t *pcBlock, uint16_t len)
{
	uint16_t crc = 0xFFFF;
	uint8_t i;

	while (len--)
	{
		crc ^= *pcBlock++ << 8;

		for (i = 0; i < 8; i++)
			crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
	}

	return crc;
}

//-------------------------------------------------------------
void NRF_COMM_ERROR_handle(void)
{

}

//-------------------------------------------------------------
void NRF_COMM_RX_CMPLT_handle(void)
{
	NRF_COMM_BUS_State = NRF_COMM_BUS_FREE;
}

//-------------------------------------------------------------
void NRF_COMM_TX_CMPLT_handle(void)
{
	NRF_COMM_BUS_State = NRF_COMM_BUS_FREE;
}




