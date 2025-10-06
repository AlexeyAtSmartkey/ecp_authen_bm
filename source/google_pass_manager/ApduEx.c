#include "ApduEx.h"

SmartTapSessionData g_smartTapData = {
	.session_id          = {0x00},
    .sequence_number     = 0x00, 			 // Default sequence number
    .collector_id        = {0x00}, 			 // Google Wallet test Collector ID
    .status_byte         = 0x01,     		 // OK status
    .authentication_byte = 0x01, 			 // Live authentication
	.skip_second_select  = 0x00,			 // Allow skipping second select
    .merchant_long_term_key_version = {0x00} // Key version
};


SmartTapSessionData* GetSessionSmartTapData(void) {
	return &g_smartTapData;
}

phStatus_t CheckFci(uint8_t *data, size_t data_l) {
	size_t offset = 0;
	uint16_t MinVer = 2;
	uint16_t MaxVer = 0;
	uint16_t cnt = 0;

	if (data[offset++] != 0x6F) {
        DEBUG_PRINTF("ERROR: Wrong FCI header.\n");
        return PH_ERR_INVALID_PARAMETER;
	}
	if (data[offset++] >= 0x80) {
		offset++;
	}

	bool nothingFound = false;
	while (!nothingFound && data[offset] != 0xa5) {
		switch (data[offset++]) {
		case 0x50:
			cnt++;
			if (data[offset++] != 0x0a) {
		        DEBUG_PRINTF("ERROR: FCI App name unexpected length %02x.\n", data[offset - 1]);
			} /* else if (strncmp(data + offset, "AndroidPay", data[offset - 1]) != 0) {
		        DEBUG_PRINTF("ERROR: FCI App name not AndroidPay.\n");
			} */
			offset += data[offset - 1];
			break;
		case 0xC0:
			cnt++;
			if (data[offset++] != 0x02) {
		        DEBUG_PRINTF("ERROR: Unexpected FCI version length %02x.\n", data[offset - 1]);
			}
			offset += data[offset - 1];
			break;
		case 0xC1:
			cnt++;
			if (data[offset++] != 0x08) {
		        DEBUG_PRINTF("ERROR: Unexpected FCI transaction details length %02x.\n", data[offset - 1]);
			}
			offset += data[offset - 1];
			break;
		case 0xC2:
			cnt++;
			if (data[offset++] != 0x20) {
		        DEBUG_PRINTF("ERROR: Unexpected Nonce length %02x.\n", data[offset - 1]);
			} else {
				memcpy(g_smartTapData.mobile_nonce, &(data[offset]), data[offset - 1]);
			}
			offset += data[offset - 1];
			break;
		case 0xC3:
			cnt++;
			if (data[offset++] != 0x21) {
		        DEBUG_PRINTF("ERROR: Unexpected pub key length %02x.\n", data[offset - 1]);
			} else {
				memcpy(g_smartTapData.mobile_compressed_public_key, &(data[offset]), data[offset - 1]);
			}
			offset += data[offset - 1];
			break;
		default:
			nothingFound = true;
			break;
		}
	}

	if (data[offset] != 0xa5) {
        DEBUG_PRINTF("ERROR: FCI proprietary template is absent.\n");
	} else {
		offset += 2;
	}
	if (data[offset] != 0xbf || data[offset + 1] != 0x0c) {
        DEBUG_PRINTF("ERROR: FCI PPSE data is absent.\n");
	} else {
		offset += 3;
	}
	if (data[offset] != 0x61) {
        DEBUG_PRINTF("ERROR: Directory entry 1 is absent.\n");
        return PH_ERR_INVALID_PARAMETER;
	}

	while (data[offset] == 0x61) {
		offset += 2;
		size_t entrySize = offset + data[offset - 1];
		if (data[offset++] != 0x4f) {
			DEBUG_PRINTF("ERROR: ADF name is absent.\n");
			return PH_ERR_INVALID_PARAMETER;
		}
		offset++;
		offset += data[offset - 1];
		while (offset < entrySize) {
			if (data[offset] != 0x73) {
				if (data[offset] != 0x61) {
					offset += 2;
					offset += data[offset - 1];
				}
			} else {
				offset += 2;
				cnt = 0;
				while (data[offset] == 0xdf) {
					offset++;
					switch (data[offset++]) {
					case 0x4d:								// Max version
						cnt++;
						if (data[offset++] != 0x02) {
							DEBUG_PRINTF("ERROR: Unexpectable min version length.\n");
							return PH_ERR_INVALID_PARAMETER;
						}
						MaxVer = data[offset++] * 16 + data[offset++];
						break;
					case 0x62:								// Capabilities bitmap
						cnt++;
						if (data[offset++] != 0x01) {
							DEBUG_PRINTF("ERROR: Unexpected capabilities bitmap length.\n");
							return PH_ERR_INVALID_PARAMETER;
						}
						g_smartTapData.skip_second_select = data[offset++] & 0x01;
						break;
					case 0x6b:								// Ephemeral key
						cnt++;
						if (data[offset++] != 0x21) {
							DEBUG_PRINTF("ERROR: Unexpected ephemeral key length.\n");
						} else {
							memcpy(g_smartTapData.mobile_compressed_public_key, &(data[offset]), data[offset - 1]);
						}
						offset += data[offset - 1];
						break;
					case 0x6d:								// Min version
						cnt++;
						if (data[offset++] != 0x02) {
							DEBUG_PRINTF("ERROR: Unexpected min version length.\n");
							return PH_ERR_INVALID_PARAMETER;
						}
						MinVer = data[offset++] * 16 + data[offset++];
						break;
					case 0x6e:								// Nonce
						cnt++;
						if (data[offset++] != 0x20) {
							DEBUG_PRINTF("ERROR: Unexpected Nonce length.\n");
						} else {
							memcpy(g_smartTapData.mobile_nonce, &(data[offset]), data[offset - 1]);
						}
						offset += data[offset - 1];
						break;
					default:
						DEBUG_PRINTF("WARNING: Unexpectable Discretionary template code 0xdf%02x.\n", data[offset++]);
						size_t l = data[offset++];
						offset += l;
						break;
					}
				}
			}
		}
	}

	if (MinVer > 1 || 1 > MaxVer ) {
        DEBUG_PRINTF("ERROR: Wrong Smart Tap version. min: %02x, max: %02x\n", MinVer, MaxVer);
        return PH_ERR_INVALID_PARAMETER;
	}

	return PH_ERR_SUCCESS;
}

phStatus_t SelectSmartTapOse(phacDiscLoop_Sw_DataParams_t *pDiscLoop) {
    phStatus_t status;
    uint8_t SELECT_PPSE[] = CREATE_APDU_SELECT('O', 'S', 'E', '.', 'V', 'A', 'S', '.', '0', '1');
    uint8_t *pRxBuffer;
    uint16_t wRxBufferLen = 32;

    if (pPal14443p4 == NULL)
    {
        DEBUG_PRINTF("ERROR: pPal14443p4DataParams is NULL\n");
        return PH_ERR_INVALID_PARAMETER;
    }

	// Step 1: Select PPSE
    DEFAULT_EXCHANGE(status, pPal14443p4, SELECT_PPSE, pRxBuffer, wRxBufferLen);
	CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Google Wallet Detection Failed (Status: 0x%X)\n")
	// Properly check for valid response
	if (CHECK_RESPONSE_STATUS(pRxBuffer, wRxBufferLen)) {
//		DEBUG_PRINTF(" \tGoogle Wallet did not respond with success.\n");
		return PH_ERR_INVALID_PARAMETER;  // ✅ Return failure status
	}
//	DEBUG_PRINT_ARR("OSE: \n", pRxBuffer, wRxBufferLen)
	status= CheckFci(pRxBuffer, wRxBufferLen);
	CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Google Wallet FCI check Failed (Status: 0x%X)\n")

	return status;
}

phStatus_t SelectSmartTap(phacDiscLoop_Sw_DataParams_t *pDiscLoop) {
    phStatus_t status;
    // ---    select Smart Tap 2
    uint8_t SELECT_SMART_TAP[] = CREATE_APDU_SELECT(0xA0, 0x00, 0x00, 0x04, 0x76, 0xD0, 0x00, 0x01, 0x11);
    uint8_t *pRxBuffer;
    uint16_t wRxBufferLen      = 32;

    if (pPal14443p4 == NULL)
    {
        DEBUG_PRINTF("ERROR: pPal14443p4DataParams is NULL\n");
        return PH_ERR_INVALID_PARAMETER;
    }

	// Step 1: Select PPSE
    DEFAULT_EXCHANGE(status, pPal14443p4, SELECT_SMART_TAP, pRxBuffer, wRxBufferLen);
//	DEBUG_PRINT_ARR("Smart Tap Application Selected response:\n", pRxBuffer, wRxBufferLen);
	if (CHECK_RESPONSE_STATUS(pRxBuffer, wRxBufferLen))
	{
		DEBUG_PRINTF(" \tGoogle Wallet did not respond with success.\n");
		if (pRxBuffer[wRxBufferLen-2] == 0x92 && pRxBuffer[wRxBufferLen-1] == 0xff) return PH_ERR_USE_CONDITION;  // ✅ Return failure status
		return PH_ERR_UNKNOWN;  // ✅ Return failure status
	}
	if (pRxBuffer[4] != 0xDC)
	{
		DEBUG_PRINTF(" \tGoogle Wallet responded with incorrect response (Byte 4 not 0xDC).\n");
		return PH_ERR_INVALID_PARAMETER;  // ✅ Return failure status
	}
	if (pRxBuffer[5] != 0x03 || pRxBuffer[7] != 0x03)
	{
		DEBUG_PRINTF(" \tGoogle Wallet responded with incorrect response (Byte 5 or 7 not 0x03).\n");
		return PH_ERR_INVALID_PARAMETER;  // ✅ Return failure status
	}
	if (pRxBuffer[6] < 0x20)
	{
		DEBUG_PRINTF(" \tGoogle Wallet responded with incorrect NONCE length (Expected > 32).\n");
		return PH_ERR_INVALID_PARAMETER;  // ✅ Return failure status
	}
	memcpy(g_smartTapData.mobile_nonce, (&(pRxBuffer[0x0F])), pRxBuffer[6]);
//	DEBUG_PRINT_ARR("Google Wallet Nonce:\n", (&(pRxBuffer[0x0F])), 32);

	return status;
}

phStatus_t NegotiateSmartTapSecureSession(phacDiscLoop_Sw_DataParams_t *pDiscLoop) {
    phStatus_t status;
    uint8_t   *pRxBuffer;
    uint16_t   wRxBufferLen;
    uint8_t    apdu_request[250];

//    g_smartTapData.sequence_number++;

    apdu_request[0] = 0x90;                                           /* CLA */
    apdu_request[1] = 0x53;                                           /* INS */   // NEGOTIATE_SECURE_SESSION
    apdu_request[2] = 0x00;                                           /* P1  */
    apdu_request[3] = 0x00;                                           /* P2  */
    ConstructNegotiateNDEF(&g_smartTapData, &(apdu_request[5]), &(apdu_request[4]));   /* apdu_request[4] - Lc, apdu_request[5] - data */
    apdu_request[apdu_request[4] + 5] = 0;                            /* Le  */

    DEFAULT_EXCHANGE_SZ(status, pPal14443p4, apdu_request, apdu_request[4] + 6, pRxBuffer, wRxBufferLen);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Secure session negotiation Failed (Status: 0x%X)\n")
    g_smartTapData.sequence_number = pRxBuffer[20];		// Session sequence number
//	DEBUG_PRINT_ARR("NGT: \n", pRxBuffer, wRxBufferLen)
//
//    DEBUG_PRINT_ARR("Smart Tap Negotiate Secure Session Request:\n", apdu_request, apdu_request[4] + 6);
//    DEBUG_PRINT_ARR("Smart Tap Negotiate Secure Session Response:\n", pRxBuffer, wRxBufferLen);

    if (wRxBufferLen < 2 || (pRxBuffer[wRxBufferLen - 2] & 0xF0) != 0x90 || pRxBuffer[wRxBufferLen - 1] != 0x00) {
		if (pRxBuffer[wRxBufferLen-2] == 0x92 && pRxBuffer[wRxBufferLen-1] == 0xff) return PH_ERR_USE_CONDITION;  // ✅ Return failure status
        DEBUG_PRINTF("Error: Smart Tap Secure Session Negotiation Failed - Invalid Status Code!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }
    if (wRxBufferLen > 2 && pRxBuffer[wRxBufferLen - 2] == 0x95) {
        DEBUG_PRINTF("Error: Smart Tap Secure Session Negotiation passed but not authorized!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }
//    DEBUG_PRINTF("Smart Tap Secure Session Negotiation Successful (Status 9x 00)\n");

    return PH_ERR_SUCCESS;
}

phStatus_t GetSmartTapData(phacDiscLoop_Sw_DataParams_t *pDiscLoop, uint8_t **ppRxBuffer, uint16_t *pwRxBufferLen) {
    phStatus_t status;
    uint8_t   *pRxBuffer = NULL;
    uint16_t   wRxBufferLen;
    uint8_t    apdu_request[170];

    g_smartTapData.sequence_number++;

    // --- 1. FORM THE GET DATA REQUEST ---
    apdu_request[0] = 0x90;  // GET DATA
    apdu_request[1] = 0x50;
    apdu_request[2] = 0x00;
    apdu_request[3] = 0x00;
    ConstructGetDataNDEF(&g_smartTapData, apdu_request + 5, &(apdu_request[4]));
    apdu_request[apdu_request[4] + 5] = 0; // Le

    DEFAULT_EXCHANGE_SZ(status, pPal14443p4, apdu_request, apdu_request[4] + 6, pRxBuffer, wRxBufferLen);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: GET DATA request failed! (Status: 0x%X)\n");
    *ppRxBuffer    = pRxBuffer;
    *pwRxBufferLen = wRxBufferLen;
    size_t headSizeExt = pRxBuffer[0] & NDEF_FLAG_SR ? 0 : 3;
    g_smartTapData.sequence_number = pRxBuffer[headSizeExt + 20];		// Session sequence number
//	DEBUG_PRINT_ARR("GSTD: \n", pRxBuffer, wRxBufferLen)

    // --- 2. CHECK RESPONSE STATUS ---
    if (wRxBufferLen < 2 ) {
        DEBUG_PRINTF("Error: GET DATA request failed - Invalid response length!\n");
        return PH_ERR_LENGTH_ERROR;
    }
    if ((pRxBuffer[wRxBufferLen - 2] & 0xF0) != 0x90) {
        DEBUG_PRINTF("Error: GET DATA request failed - Invalid Status Code first byte!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }
    if (pRxBuffer[wRxBufferLen - 1] > 0x01) {
    	if (pRxBuffer[wRxBufferLen-2] == 0x92 && pRxBuffer[wRxBufferLen-1] == 0xff) return PH_ERR_USE_CONDITION;  // ✅ Return failure status
    	if (pRxBuffer[wRxBufferLen-2] == 0x93 && pRxBuffer[wRxBufferLen-1] == 0x02) return PH_ERR_PARAMETER_OVERFLOW;  // ✅ Return failure status
    	DEBUG_PRINTF("Error: GET DATA request failed - Invalid Status Code second byte!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }

    return PH_ERR_SUCCESS;
}

phStatus_t GetSmartTapAddData(phacDiscLoop_Sw_DataParams_t *pDiscLoop, uint8_t **ppRxBuffer, uint16_t *pwRxBufferLen) {
    phStatus_t status;
    uint8_t   *pRxBuffer;
    uint16_t   wRxBufferLen;
    uint8_t    apdu_request[10];

//    g_smartTapData.sequence_number++;

    // --- 1. FORM THE GET DATA REQUEST ---
    apdu_request[0] = 0x90;  // GET DATA
    apdu_request[1] = 0xC0;
    apdu_request[2] = 0x00;
    apdu_request[3] = 0x00;
    apdu_request[4] = 0x00;
    apdu_request[5] = 0x00; // Le

    DEFAULT_EXCHANGE_SZ(status, pPal14443p4, apdu_request, 5, pRxBuffer, wRxBufferLen);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: Get addition data request failed! (Status: 0x%X)\n");
    *ppRxBuffer    = pRxBuffer;
    *pwRxBufferLen = wRxBufferLen;
//    g_smartTapData.sequence_number = pRxBuffer[20];		// Session sequence number

    // --- 2. CHECK RESPONSE STATUS ---
    if (wRxBufferLen < 2 ) {
        DEBUG_PRINTF("Error: Get addition data request failed - Invalid response length!\n");
        return PH_ERR_LENGTH_ERROR;
    }
    if ((pRxBuffer[wRxBufferLen - 2] & 0xF0) != 0x90) {
        DEBUG_PRINTF("Error: Get addition data request failed - Invalid Status Code first byte!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }
    if (pRxBuffer[wRxBufferLen - 1] > 0x01) {
    	if (pRxBuffer[wRxBufferLen-2] == 0x92 && pRxBuffer[wRxBufferLen-1] == 0xff) return PH_ERR_USE_CONDITION;  // ✅ Return failure status
    	DEBUG_PRINTF("Error: Get addition data request failed - Invalid Status Code second byte!\n");
        return PH_ERR_PROTOCOL_ERROR;
    }

    return PH_ERR_SUCCESS;
}

phStatus_t GetSmartTapProcessingOptions(phacDiscLoop_Sw_DataParams_t *pDiscLoop)
{
    phStatus_t status;
    uint8_t *pRxBuffer;
    uint16_t wRxBufferLen;
    uint8_t apdu_request[250];
    uint16_t apduLen;

    // --- Construct GET PROCESSING OPTIONS APDU command ---
    // Format: CLA | INS | P1 | P2 | Lc | [Data] | Le
    // For GET PROCESSING OPTIONS we use:
    //   CLA = 0x80, INS = 0xA8, P1 = 0x00, P2 = 0x00, Lc = 0x00 (no PDOL), Le = 0x00
    apdu_request[0] = 0x00;  // CLA
    apdu_request[1] = 0xA8;  // INS (GET PROCESSING OPTIONS)
    apdu_request[2] = 0x00;  // P1
    apdu_request[3] = 0x00;  // P2
    apdu_request[4] = 0x02;  // Lc = 0 (no data)
    apdu_request[5] = 0x83;  // Data
    apdu_request[6] = 0x00;  // Data
    apdu_request[7] = 0x00;  // Le = 0

    apduLen = 8;           // Total APDU length

    // --- Send the APDU ---
    DEFAULT_EXCHANGE_SZ(status, pPal14443p4, apdu_request, apduLen, pRxBuffer, wRxBufferLen);
    if (status != PH_ERR_SUCCESS)
    {
        DEBUG_PRINTF("Error: GET PROCESSING OPTIONS exchange failed (Status: 0x%X)\n", status);
        return status;
    }

    // --- Check response status ---
    if (CHECK_RESPONSE_STATUS(pRxBuffer, wRxBufferLen))
    {
        DEBUG_PRINTF("Error: GET PROCESSING OPTIONS response invalid (Status: 0x%X%X)\n",
                     pRxBuffer[wRxBufferLen - 2], pRxBuffer[wRxBufferLen - 1]);
        return PH_ERR_PROTOCOL_ERROR;
    }

    // --- Parse the response ---
    // For this example we assume the uncompressed ECC public key is provided
    // in a TLV element (for example, with tag DF8124) that starts at a fixed offset.
    // Here we assume the value starts at offset 5 and is 65 bytes long.
    if (wRxBufferLen < 5 + 65 + 2)
    {
        DEBUG_PRINTF("Error: GET PROCESSING OPTIONS response too short\n");
        return PH_ERR_PROTOCOL_ERROR;
    }

    // Copy the uncompressed public key (0x04|X|Y) into our SmartTapSessionData structure.
//    memcpy(g_smartTapData.mobile_uncompressed_public_key, &pRxBuffer[5], 65);

    // Optionally update session parameters (e.g. sequence number)
    if (wRxBufferLen > 21)
    {
        g_smartTapData.sequence_number = pRxBuffer[21];
    }

    return PH_ERR_SUCCESS;
}

