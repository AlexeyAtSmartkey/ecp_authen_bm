
#ifndef _DEVICE_MANAGER_H_
#define _DEVICE_MANAGER_H_

typedef enum _NFC_READER_MODE_
{
	NFC_READER_READ_MODE,
	NFC_READER_WRITE_MODE,
	NFC_READER_OTA_MODE,
	NFC_READER_SETTINGS_MODE
}NFC_READER_Mode_t;

// Structure containing NFC reader status
typedef struct _NFC_COMM_STATUS_
{
	uint8_t nfc_read_mode:1;
	uint8_t nfc_write_mode:1;
	uint8_t nfc_ota_mode:1;
	uint8_t nfc_settings_mode:1;
	uint8_t bit4:1;
	uint8_t bit5:1;
	uint8_t bit6:1;
	uint8_t bit7:1;

}NFC_COMM_Status_t;

void DEVICE_MODE_set(NFC_READER_Mode_t new_mode);
NFC_READER_Mode_t DEVICE_MODE_get(void);

NFC_COMM_Status_t *DEVICE_STATUS_get(void);

#endif // _DEVICE_MANAGER_H_

