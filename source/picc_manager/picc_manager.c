
#include <phApp_Init.h>
#include "SmartLock.h"
#include "picc_manager.h"
#include "nfc_comm.h"
#include "key_manager.h"
#include "device_manager.h"
#include "spi_protocol.h"





// Buffer to store command data from message buffer
static uint8_t cmdBuffer[PROTOCOL_MSG_LENGTH_MAX];

// Buffer to store read data to be sent to NRF
static uint8_t respBuffer[36];


// First level buffer to store data read from PICC
static uint8_t test_data[32];

// Application ID
static uint8_t picc_app_id[3] = {0x12, 0xE4, 0x85};

// Default file number
static uint8_t picc_file_number = 1;

// Data offset in file on PICC
static uint8_t picc_file_data_offset = 0;

// Array which are used for AuthenticateEV2 routine (actually reserved for new possible functionality of NXP PICCs)
static uint8_t PCDcap2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t PCDcap2In[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t PDcap2In[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};



//-------------------------------------------------------------
phStatus_t PICC_DATA_read(void *pDataParams)
{
	phStatus_t status = PH_ERR_INTERNAL_ERROR;

	uint8_t * pRxData = test_data;
	uint16_t wRxLen = 0;
	uint16_t wKeyNo = KEY_get(MASTER_KEY_PICC)->key_address;
	uint16_t wKeyVer = KEY_get(MASTER_KEY_PICC)->key_version;
	uint8_t data_length = NFC_WRITE_DATA_SIZE;
	uint8_t aTMC[4] = {0};
	uint8_t aTMV[8] = {0};
	uint8_t err_code;

	// Authenticate PICC Master Application with AES128 key new_aAES128Key for EV2 communication mode
	// status = phalMfdfEVx_AuthenticateEv2(pDataParams, PHAL_MFDFEVX_AUTH_FIRST, PHAL_MFDFEVX_NO_DIVERSIFICATION,
	// 		wKeyNo, wKeyVer, PICC_MASTER_KEY, NULL, 0, 0, PCDcap2, PCDcap2In, PDcap2In);

	// if(status != 0)
	// {
	// 	// Send command with error code
	// 	err_code = NFC_READ_PICC_AUT_ERR;
	// 	SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

	// 	return status;
	// }

	// Select application
	status = phalMfdfEVx_SelectApplication(pDataParams, 0x00, picc_app_id, NULL);

	if(status != 0)
	{
		// Send command with error code
		err_code = NFC_READ_APP_SELECT_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

		return status;
	}

	// Authenticate Application Master Application with AES128 key new_aAES128Key for EV2 communication mode
	status = phalMfdfEVx_AuthenticateEv2(pDataParams, PHAL_MFDFEVX_AUTH_FIRST, PHAL_MFDFEVX_NO_DIVERSIFICATION,
			wKeyNo, wKeyVer, APP_MASTER_KEY, NULL, 0, 0, PCDcap2, PCDcap2In, PDcap2In);

	if(status != 0)
	{
		// Send command with error code
		err_code = NFC_READ_APP_AUT_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

		return status;
	}

	// Authenticate file
	status = phalMfdfEVx_AuthenticateEv2(pDataParams, PHAL_MFDFEVX_AUTH_NONFIRST, PHAL_MFDFEVX_NO_DIVERSIFICATION,
			wKeyNo, wKeyVer, APP_MASTER_KEY, NULL, 0, 0, PCDcap2, PCDcap2In, PDcap2In);


	if(status != 0)
	{
		// Send command with error code
		err_code = NFC_READ_FILE_AUT_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

		return status;
	}

	// Read data
	status = phalMfdfEVx_ReadData(pDataParams, PHAL_MFDFEVX_COMMUNICATION_ENC,
			PHAL_MFDFEVX_ISO_CHAINING, picc_file_number, &picc_file_data_offset, &data_length, &pRxData, &wRxLen);

	if(status != 0)
	{
		// Send command with error code
		err_code = NFC_READ_DATA_READ_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

		return status;
	}

	// Copy read data to buffer to send
	for(uint16_t i = 0; i < data_length; i++)
	{
		respBuffer[i] = pRxData[i];
	}

	// Send data
	SpiSend(PN_NFC_READ_DATA, respBuffer, data_length);

	return status;
}


//-------------------------------------------------------------
void PICC_DATA_TO_WRITE_set(uint8_t *data)
{
	for(uint16_t i = 0; i < NFC_WRITE_DATA_SIZE; i++)
	{
		cmdBuffer[i] = data[i];
	}
}


