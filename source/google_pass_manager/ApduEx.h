#include <NdefEx.h>

#ifndef APDU_EX_H_INC
#define APDU_EX_H_INC


// Response should be longer then 2 bytes and contains 0x90, 0x00 status code
#   define CHECK_RESPONSE_STATUS(buf, len) \
		len < 2 || buf[len - 2] != 0x90 || buf[len - 1] != 0x00


// -- APDU CMD format
// CLA
// INS
// P1
// P2
// Lc
// Data
// Le
#define APDU_CLA 0
#define APDU_INS 1
#define APDU_P1 2
#define APDU_P2 3
#define APDU_LC 4
#define APDU_DATA 5
#define APDU_LE 0

#define CREATE_APDU_SELECT(...) \
    { \
        0x00, /* CLA */ \
        0xA4, /* INS */ \
        0x04, /* P1 */ \
        0x00, /* P2 */ \
        sizeof((char[]){__VA_ARGS__}), /* Lc */ \
		__VA_ARGS__, /* Data */ \
        0x00 /* Le */ \
    }

#define CREATE_APDU_SECURE(...) \
    { \
        0x90, /* CLA */ \
        0x53, /* INS */ \
        0x00, /* P1 */ \
        0x00, /* P2 */ \
        sizeof((char[]){__VA_ARGS__}), /* Lc */ \
		__VA_ARGS__, /* Data */ \
        0x00 /* Le */ \
    }


#define DEFAULT_EXCHANGE(wStatus, pspalI14443p4, pTxBuffer, pRxBuffer, RxLength) \
    wStatus = phpalI14443p4_Exchange( \
        pspalI14443p4, \
        PH_EXCHANGE_DEFAULT, \
        pTxBuffer, \
        sizeof(pTxBuffer), \
        &pRxBuffer, \
        &RxLength \
    );

#define DEFAULT_EXCHANGE_SZ(wStatus, pspalI14443p4, pTxBuffer, TxBufferLen, pRxBuffer, RxLength) \
    wStatus = phpalI14443p4_Exchange( \
        pspalI14443p4, \
        PH_EXCHANGE_DEFAULT, \
        pTxBuffer, \
		TxBufferLen, \
        &pRxBuffer, \
        &RxLength \
    );

#define pPal14443p4 pDiscLoop->pPal14443p4DataParams			// Cutting down string

SmartTapSessionData* GetSessionSmartTapData(void);
phStatus_t SelectSmartTapOse(phacDiscLoop_Sw_DataParams_t *pDiscLoop);
phStatus_t SelectSmartTap(phacDiscLoop_Sw_DataParams_t *pDiscLoop);
phStatus_t NegotiateSmartTapSecureSession(phacDiscLoop_Sw_DataParams_t *pDiscLoop);
phStatus_t GetSmartTapData(phacDiscLoop_Sw_DataParams_t *pDiscLoop, uint8_t **pRxBuffer, uint16_t *wRxBufferLen);
phStatus_t GetSmartTapAddData(phacDiscLoop_Sw_DataParams_t *pDiscLoop, uint8_t **pRxBuffer, uint16_t *wRxBufferLen);
phStatus_t GetSmartTapProcessingOptions(phacDiscLoop_Sw_DataParams_t *pDiscLoop);


#endif

