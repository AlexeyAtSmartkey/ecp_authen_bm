/*----------------------------------------------------------------------------*/
/* Copyright 2025 Smartphonekey System Inc.                                   */
/*                                                                            */
/* Smartphonekey System Inc. Confidential. This software is owned or          */
/* controlled by Smartphonekey System Inc. and may only be used strictly      */
/* in accordance with the applicable license terms.                           */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms.  															  */
/* If you do not agree to be bound by the applicable license   				  */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* Source for Google Wallet pass read
*
*
* $Author:   $(Smartphonekey System Inc.)
* $Revision: $(v01.00.00)
* $Date:     $(2025-07-20)
*/

/**
* Reader Library Headers
*/
#include <google_pass_manager.h>

/*******************************************************************************
**   Definitions
*******************************************************************************/


int SendChunckedData(uint8_t *pData, size_t wDataLen, const size_t wDataChunkLen, const bool final) {
    size_t  wDataChunkRest = wDataLen % wDataChunkLen;
    size_t  chunks         = (wDataLen / wDataChunkLen);
    int     iResult        = 0;
    uint8_t cmd            = PN_GW_READ_DATA_CHUNK;
    for (int chunk = 0; chunk < chunks; chunk++) {
        cmd = (final && chunk == (chunks - 1) && !wDataChunkRest) ? PN_GW_READ_DATA_END : PN_GW_READ_DATA_CHUNK;
        SpiWaitBusFree();
        SpiSend(cmd, pData + (chunk * wDataChunkLen), wDataChunkLen);
    }
    if (!wDataChunkRest) return iResult;
    cmd = final ? PN_GW_READ_DATA_END : PN_GW_READ_DATA_CHUNK;
    SpiWaitBusFree();
    SpiSend(cmd, pData + (chunks * wDataChunkLen), wDataChunkRest);
    return iResult;
}

phStatus_t ProcessGoogleWallet(phacDiscLoop_Sw_DataParams_t *pDiscLoop) {
    phStatus_t           status;
    SmartTapSessionData *g_smartTapData = GetSessionSmartTapData();
    uint8_t             *pRxBuffer;
    uint16_t             wRxBufferLen;

	// Step 1: Select PPSE
    status = SelectSmartTapOse(pDiscLoop);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Select Smart Tap failed. Status: 0x%X\n")

	// Step 2: Select Smart Tap Application - Optional step (could be skipped)
    if (!g_smartTapData->skip_second_select) {
    	for (int retry = 3; retry > 0; retry--) {
    		status = SelectSmartTap(pDiscLoop);
    		if (status != PH_ERR_USE_CONDITION) {
    			CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Failed to select Smart Tap application. Status: 0x%04X\n")
    			break;
    		}
    	}
    }

	InitSmartTapSession(g_smartTapData, 4);
    // Step 3: Negotiate Secure Sessions
	for (int retry = 3; retry > 0; retry--) {
		status = NegotiateSmartTapSecureSession(pDiscLoop);
		if (status != PH_ERR_USE_CONDITION) {
			CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Secure session negotiation failed. Status: 0x%X\n")
			break;
		}
        DEBUG_PRINTF("Status: 0x%X. Retrying secure session negotiation...\n", status);
		g_smartTapData->sequence_number++;
	}

    // Step 4: Get data
	for (int retry = 3; retry > 0; retry--) {
		status = GetSmartTapData(pDiscLoop, &pRxBuffer, &wRxBufferLen);

        if (status == PH_ERR_PARAMETER_OVERFLOW) return PH_ERR_PARAMETER_OVERFLOW;

        if (status != PH_ERR_USE_CONDITION) {
			CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Getting data failed. Status: 0x%X\n")
	        bool addData = false;
			while (pRxBuffer[wRxBufferLen-2] == 0x91 && pRxBuffer[wRxBufferLen-1] == 0x00) {
				addData = true;
				status = GetSmartTapAddData(pDiscLoop, &pRxBuffer, &wRxBufferLen);
				if (status != PH_ERR_USE_CONDITION) {
					CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Getting addition data failed. Status: 0x%X\n")
					if (pRxBuffer[wRxBufferLen-2] != 0x91 || pRxBuffer[wRxBufferLen-1] != 0x00) {
						return PH_ERR_USE_CONDITION;                        // Now we do not handle large amount of data - only for tests
					}
				}
			}
			if (!addData) break;
		}
	}

    // DEBUG_PRINTF("Sending terminal private key\n");
    SendChunckedData(g_smartTapData->terminal_private_key, sizeof(g_smartTapData->terminal_private_key), sizeof(g_smartTapData->terminal_private_key), false);
    // DEBUG_PRINT_ARR("Terminal private key:", g_smartTapData->terminal_private_key, sizeof(g_smartTapData->terminal_private_key));
    SendChunckedData(g_smartTapData->mobile_compressed_public_key, sizeof(g_smartTapData->mobile_compressed_public_key), sizeof(g_smartTapData->mobile_compressed_public_key), false);
    // DEBUG_PRINT_ARR("Mobile compressed public key:", g_smartTapData->mobile_compressed_public_key, sizeof(g_smartTapData->mobile_compressed_public_key));
    SendChunckedData(g_smartTapData->terminal_nonce, SIGNED_SESSION_DATA_LEN, 32, false);
    // DEBUG_PRINT_ARR("Terminal nonce:", g_smartTapData->terminal_nonce, SIGNED_SESSION_DATA_LEN);
    SendChunckedData((uint8_t*)&(g_smartTapData->der_signature_len), g_smartTapData->der_signature_len + 1, 32, false);
    // DEBUG_PRINT_ARR("DER signature:", g_smartTapData->der_signature, g_smartTapData->der_signature_len);
    SendChunckedData(pRxBuffer, wRxBufferLen, 32, true);
    // DEBUG_PRINT_ARR("Data:", pRxBuffer, wRxBufferLen);

	// status = phhalHw_FieldOn(pHal);

	return PH_ERR_SUCCESS;  // Return success status
}

