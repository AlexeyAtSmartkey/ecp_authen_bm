#include <phApp_Init.h>
#include "device_manager.h"

// Variable store mode NFC reader works in
static NFC_READER_Mode_t NFC_READER_Mode = NFC_READER_READ_MODE;

// Status of NFC that is sent each heart beat
static NFC_COMM_Status_t NFC_COMM_Status;


//-------------------------------------------------------------
void DEVICE_MODE_set(NFC_READER_Mode_t new_mode)
{
	uint8_t tmp;

	NFC_READER_Mode = new_mode;

	// Clear status
	tmp = *(uint8_t *)&NFC_COMM_Status;
	tmp = tmp & 0xF0;
	*(uint8_t *)&NFC_COMM_Status = tmp;

	// Set appropriate bit in status register
	if(new_mode == NFC_READER_READ_MODE) {NFC_COMM_Status.nfc_read_mode = 1;}
	else if (new_mode == NFC_READER_WRITE_MODE) {NFC_COMM_Status.nfc_write_mode = 1;}
	else if (new_mode == NFC_READER_OTA_MODE) {NFC_COMM_Status.nfc_ota_mode = 1;}
	else if (new_mode == NFC_READER_SETTINGS_MODE) {NFC_COMM_Status.nfc_settings_mode = 1;}
}

//-------------------------------------------------------------
NFC_READER_Mode_t DEVICE_MODE_get(void)
{
	return NFC_READER_Mode;
}

//-------------------------------------------------------------
NFC_COMM_Status_t *DEVICE_STATUS_get(void)
{
	return &NFC_COMM_Status;
}
