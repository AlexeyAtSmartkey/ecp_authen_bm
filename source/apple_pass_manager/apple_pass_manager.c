#include <phApp_Init.h>
#include "SmartLock.h"
#include "nfc_comm.h"
#include "spi_protocol.h"
#include "key_manager.h"
#include "device_manager.h"
#include "phpalI14443p4_Sw.h"

// Array which are used for AuthenticateEV2 routine (actually reserved for new possible functionality of NXP PICCs)
// uint8_t PCDcap2[6]   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
// uint8_t PCDcap2In[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
// uint8_t PDcap2In[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static uint8_t test_data[32];

// "df6664fb-7870-f95e-71be-92ebe5c6adad"
static uint8_t respBuffer[36] =
{
	0x64, 0x66, 0x36, 0x36, 0x36, 0x34, 0x66, 0x62, 0x2d, 0x37, 0x38, 0x37,
	0x30, 0x2d, 0x66, 0x39, 0x35, 0x65, 0x2d, 0x37, 0x31, 0x62, 0x65, 0x2d,
	0x39, 0x32, 0x65, 0x62, 0x65, 0x35, 0x63, 0x36, 0x61, 0x64, 0x61, 0x64

};

//-------------------------------------------------------------
phStatus_t APPLE_PASS_read(void *pDataParams, phacDiscLoop_Sw_DataParams_t *discLoop)
{
	phStatus_t status = PH_ERR_INTERNAL_ERROR;
	uint8_t apId[3] = {0x01, 0x64, 0xF5};
	uint8_t aTMC[4] = {0};
	uint8_t aTMV[8] = {0};
	uint8_t data_offset[3] = {0x00, 0x00, 0x00};
	uint8_t data_length[3] = {0x20, 0x00, 0x00};
	uint8_t * pRxData = test_data;
	uint16_t wRxLen = 0;
	uint8_t err_code;

	status = phalMfdfEVx_SelectApplication(pDataParams, 0x00, apId, NULL);

	if(status != 0)
	{
		// Send command with error code
		err_code = NFC_READ_APP_SELECT_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));

		return status;
	}

	status = phalMfdfEVx_AuthenticateEv2(pDataParams, PHAL_MFDFEVX_AUTH_FIRST, PHAL_MFDFEVX_NO_DIVERSIFICATION,
			KEY_get(ACCESSGRID_READ_KEY_ID)->keyno,
			KEY_get(ACCESSGRID_READ_KEY_ID)->version,
			0, NULL, 0, 0, PCDcap2, PCDcap2In, PDcap2In);

	if(status != 0) {
		err_code = NFC_READ_APP_AUT_ERR;
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code)); // Send command with error code
		return status;
	}

	// Read data
	status = phalMfdfEVx_ReadData(pDataParams, /*PHAL_MFDFEVX_COMMUNICATION_PLAIN*/PHAL_MFDFEVX_COMMUNICATION_ENC,
			PHAL_MFDFEVX_ISO_CHAINING,
			/*0x03*/0x00, data_offset, data_length, &pRxData, &wRxLen);

	if(status != 0) {
		err_code = NFC_READ_DATA_READ_ERR;												// Send command with error code
		SpiSend(PN_CARD_READ_ERROR, &err_code, sizeof(err_code));
		return status;
	}

//	// Copy read data to buffer to send
	size_t offset = 0;
	for(uint16_t i = 0; i < 32; i++) {
		if (i < 16) {
			if (respBuffer[offset] == '-') offset++;
			respBuffer[offset++] = (pRxData[i] >> 4) + ((pRxData[i] >> 4) < 10 ? '0' : 'a' - 0x0a);
			respBuffer[offset++] = (pRxData[i] & 0xF) + ((pRxData[i] & 0xF) < 10 ? '0' : 'a' - 0x0a);
		}
	}
	// DEBUG_PRINTF("\n");
	// DEBUG_PRINTF("\t");
	// for(uint16_t i = 0; i < 36; i++) DEBUG_PRINTF("%02X ", respBuffer[i]);
	// DEBUG_PRINTF("\n");

	// Secret apple command
	uint8_t endCmd[] = { 0x90, 0xEE, 0x00, 0x00, 0x00 };
	uint8_t *pRxBuffer1;
	uint16_t wRxLen1 = 4;

    // **Proprietary Apple Last Command Indicator (LCI) Command**
    uint8_t lciCommand[] = { 0x90, 0xEE, 0x00, 0x00, 0x00 };
    status = phpalMifare_ExchangeL4(
		((phalMfdfEVx_Sw_DataParams_t *)(pDataParams))->pPalMifareDataParams,
		PH_EXCHANGE_DEFAULT,
        lciCommand,
        sizeof(lciCommand),
        &pRxBuffer1, &wRxLen1
	);
	if(status != 0) return status;


	((phpalI14443p4_Sw_DataParams_t *)(discLoop->pPal14443p4DataParams))->bCidEnabled = 0;
	status = phpalI14443p4_Sw_Deselect(discLoop->pPal14443p4DataParams);

	// Send data
	SpiSend(PN_NFC_READ_DATA, respBuffer, NFC_WRITE_DATA_SIZE);

	return status;
}
