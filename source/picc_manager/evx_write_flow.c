#include "evx_write_flow.h"
#include "nfc_debug_helpers.h"

#include <string.h>
#include <phApp_Init.h>
#include "nfc_comm.h"   /* for NFC_READ_Params, NFC_COMM_MODE_set, NFC_READER_READ_MODE */

/* --- Externs provided elsewhere in the project --- */
extern void *palMfdfEVx;
extern uint8_t PCDcap2[6], PCDcap2In[6], PDcap2In[6];
// extern uint8_t PICC_MASTER_KEY[16];      /* adjust length if DES */
// extern uint8_t APP_MASTER_KEY[16];
// extern uint8_t aAES128Key[16];
// extern uint8_t new_aAES128Key[16];
static uint8_t aAES128Key[]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t new_aAES128Key[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

/* --- Local defaults (guarded to avoid redefinition if already defined) --- */
#ifndef TMAC_FILE
#define TMAC_FILE                0x00     /* adjust to your desired file number */
#endif
#ifndef STDDATAFILE1
#define STDDATAFILE1             0x01
#endif
// #ifndef AES128_KEY_ADDRESS
// #define AES128_KEY_ADDRESS       0x0004   /* keystore slot for AES key */
// #endif
// #ifndef AES128_KEY_VERSION
// #define AES128_KEY_VERSION       0x01
// #endif
// #ifndef NEW_AES128_KEY_ADDRESS
// #define NEW_AES128_KEY_ADDRESS   0x0004
// #endif
// #ifndef NEW_AES128_KEY_VERSION
// #define NEW_AES128_KEY_VERSION   0x01
// #endif
// #ifndef DES_KEY_ADDRESS
// #define DES_KEY_ADDRESS          0x0001
// #endif
// #ifndef DES_KEY_VERSION
// #define DES_KEY_VERSION          0x00
// #endif
#ifndef DES3K3_KEY_ADDRESS
#define DES3K3_KEY_ADDRESS       0x0002
#endif

static uint8_t pISOFileName[16] = "AFCAPPLICATION";
static uint8_t bISOFileLen;
// Structure containing PICC read parameters
NFC_READ_Params_t NFC_READ_Params = {
		{0x12, 0xE4, 0x85},		// Application ID
		3,						// Key number
		0,						// Key version
		new_aAES128Key,			// Key
		1,						// File number
		{0x00, 0x00, 0x00},		// Offset in file
		{0x24, 0x00, 0x00}		// must equls NFC_WRITE_DATA_SIZE in PN7642_SmartphoneKey.h
};

static inline phStatus_t ensure_len_fits(uint32_t file_size, uint8_t *_write_len) {
    uint32_t write_len = ((uint32_t)NFC_READ_Params.data_length[2] << 16) |
                         ((uint32_t)NFC_READ_Params.data_length[1] << 8)  |
                         ((uint32_t)NFC_READ_Params.data_length[0]);
    return (write_len <= file_size) ? PH_ERR_SUCCESS : PH_ERR_RESOURCE_ERROR;
}

/* Forward decls (also in header) */
phStatus_t NFC_COMM_createApp(void * pAlMfdfEVx, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t *aid);
phStatus_t NFC_COMM_PICC_format_createAPP_write(uint8_t *data);

/* ------------------------------------------------------------- */
phStatus_t MifareDESFireEVx_process(uint8_t *data, uint32_t data_len) {
    phStatus_t status;

    (void)data_len; /* currently unused; bounds are checked against NFC_READ_Params below */

    /* 1) Try EV2 auth with the new PICC AES key (fast path) */
    status = phalMfdfEVx_AuthenticateEv2(
        palMfdfEVx,
        PHAL_MFDFEVX_AUTH_FIRST,
        PHAL_MFDFEVX_NO_DIVERSIFICATION,
        KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
        PICC_MASTER_KEY,
        NULL, 0, 
        sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In
    );

    if (status != PH_ERR_SUCCESS) {
        /* 2) Fallback: legacy auth with default PICC Master (DES), then swap to AES */
        status = phalMfdfEVx_Authenticate(
            palMfdfEVx,
            PHAL_MFDFEVX_NO_DIVERSIFICATION,
            DES_KEY_ADDRESS, DES_KEY_VERSION,
            PICC_MASTER_KEY, NULL, 0
        );
        if (status != PH_ERR_SUCCESS) return status;

        /* Change PICC Master key from DES -> AES (bit7 set changes key type) */
        status = phalMfdfEVx_ChangeKey(
            palMfdfEVx,
            PHAL_MFDFEVX_NO_DIVERSIFICATION,
            DES_KEY_ADDRESS, DES_KEY_VERSION,
            KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
            0x80,                      /* change key type */
            NULL, 0
        );
        if (status != PH_ERR_SUCCESS) return status;

        /* Re-auth EV2 with new AES PICC Master */
        status = phalMfdfEVx_AuthenticateEv2(
            palMfdfEVx,
            PHAL_MFDFEVX_AUTH_FIRST,
            PHAL_MFDFEVX_NO_DIVERSIFICATION,
            KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
            PICC_MASTER_KEY,
            NULL, 0, 
            sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In
        );
        if (status != PH_ERR_SUCCESS) return status;
    }

    /* 3) Format, create app/files, write data */
    status = NFC_COMM_PICC_format_createAPP_write(data);
    if (status != PH_ERR_SUCCESS) return status;

    /* 4) Switch to reader mode (if this is your app’s state machine) */
    // NFC_COMM_MODE_set(NFC_READER_READ_MODE);

    return PH_ERR_SUCCESS;
}

/* ------------------------------------------------------------- */
/* Format PICC, create app/files, write payload, commit */
phStatus_t NFC_COMM_PICC_format_createAPP_write(uint8_t *data) {
    phStatus_t status;
    uint8_t macFileAccessRights[2] = {0xF0, 0x0F}; /* adjust per policy */
    uint8_t IsoFileID[2]           = {0x78, 0x56}; /* LSB first => 0x5678 */
    uint8_t fileOption             = PHAL_MFDFEVX_FILE_OPTION_ENC;
    uint8_t srdFileAccessRights[2] = {0x00, 0x00}; /* all ops via key 0 (intentional?) */
    uint8_t fileSize[3]            = {0x00, 0x04, 0x00}; /* 0x000400 = 1024 bytes */
    uint8_t aTMC[4] = {0};
    uint8_t aTMV[8] = {0};

    /* 1) Format whole PICC */
    status = phalMfdfEVx_Format(palMfdfEVx);
    if (status != PH_ERR_SUCCESS) return status;

    /* 2) Create + select app, migrate App MK to NEW_AES128, end with EV2 session open */
    status = NFC_COMM_createApp(palMfdfEVx, KEY_get(APPLICATION_KEY_PICC)->keyno, KEY_get(APPLICATION_KEY_PICC)->version, NFC_READ_Params.aid);
    if (status != PH_ERR_SUCCESS) return status;

    /* 3) Create Transaction MAC file (EV2) */
    status = phalMfdfEVx_CreateTransactionMacFile(
        palMfdfEVx,
        0xFFFF,                     /* no ISO FID for TMAC */
        TMAC_FILE,
        0x00,                       /* TMAC options */
        macFileAccessRights,
        KEY_get(APPLICATION_KEY_PICC)->keyno,
        0x02,                       /* TMAC length (multiplier) – check SDK! */
        KEY_get(APPLICATION_KEY_PICC)->key,                 /* base for derivation if required by your SDK */
        KEY_get(APPLICATION_KEY_PICC)->version,
        NULL, 0
    );
    if (status != PH_ERR_SUCCESS) return status;

    /* 4) Create a standard data file */
    status  = phalMfdfEVx_CreateStdDataFile(
        palMfdfEVx,
        0x00,                       /* communication settings in file config */
        STDDATAFILE1,
        IsoFileID,
        fileOption,                 /* ENC */
        srdFileAccessRights,
        fileSize
    );
    if (status != PH_ERR_SUCCESS) return status;

    /* 5) We already have an EV2 session (AUTH_FIRST from createApp). No need to re-auth NONFIRST here. */

    /* 6) Bounds check against fileSize (LSB first -> 0x000400 = 1024) */
    uint32_t max_file_bytes = (uint32_t)fileSize[0] | ((uint32_t)fileSize[1] << 8) | ((uint32_t)fileSize[2] << 16);
    phStatus_t fit = ensure_len_fits(max_file_bytes, NFC_READ_Params.data_length);
    if (fit != PH_ERR_SUCCESS) return fit;

    /* 7) Write data (ENC) */
    status = phalMfdfEVx_WriteData(
        palMfdfEVx,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        0x00,                       /* option = 0x00 (std write). Use 0x01 only if your SDK expects it. */
        NFC_READ_Params.file_number,
        NFC_READ_Params.data_offset,
        data,
        NFC_READ_Params.data_length
    );
    if (status != PH_ERR_SUCCESS) return status;

    /* 8) Commit transaction (EV2) */
    status = phalMfdfEVx_CommitTransaction(palMfdfEVx, 0x01, aTMC, aTMV);
    if (status != PH_ERR_SUCCESS) return status;

    return PH_ERR_SUCCESS;
}

/* ------------------------------------------------------------- */
/* Create + select app, authenticate, change App MK to NEW_AES128, end with EV2 session */
phStatus_t NFC_COMM_createApp(void * pAlMfdfEVx, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t *aid) {
    phStatus_t status;
    uint8_t  bOption       = 0x00;         /* set 0x03 if you want both ISO FID and DF name */
    uint8_t  bKeySettings1 = 0x0F;         /* changeable, file ops need auth, free directory, MK changeable */
    uint8_t  bKeySettings2 = 0x82;         /* AES crypto + 2-byte ISO FIDs + up to 6 keys */
    uint8_t  bKeySettings3 = 0x00;
    uint8_t  bKeySetValues[4] = {0xAA, 0x00, 0x00, 0x00};
    uint8_t  bISOFileId[2] = {0x12, 0x34}; /* LSB first = 0x1234 */
    const uint8_t bAppName[] = "AFCAPPLICATION";
    void* pKeyStore = getKeyStore();

    bISOFileLen = (uint8_t)(sizeof(bAppName) - 1U);
    memcpy(pISOFileName, bAppName, bISOFileLen);

    DEBUG_PRINTF("\t\tbOption: 0x%02x \n", bOption);
    DEBUG_PRINTF("\t\tbKeySettings1: 0x%02x \n", bKeySettings1);
    DEBUG_PRINTF("\t\tbKeySettings2: 0x%02x \n", bKeySettings2);
    DEBUG_PRINTF("\t\tbKeySettings3: 0x%02x \n", bKeySettings3);
    DEBUG_PRINTF("\t\tbKeySetValues: 0x%02x 0x%02x 0x%02x 0x%02x \n", bKeySetValues[0], bKeySetValues[1], bKeySetValues[2], bKeySetValues[3]);
    DEBUG_PRINTF("\t\tbISOFileId: 0x%02x 0x%02x \n", bISOFileId[0], bISOFileId[1]);
    DEBUG_PRINTF("\t\tbISOFileName: %s \n", pISOFileName);
    DEBUG_PRINTF("\t\tbISOFileLen: %d \n", bISOFileLen);

    /* Create App */
    status = phalMfdfEVx_CreateApplication(
        pAlMfdfEVx,
        bOption,
        aid,
        bKeySettings1, bKeySettings2, bKeySettings3,
        bKeySetValues,
        bISOFileId,
        pISOFileName, bISOFileLen
    );
    if (status != PH_ERR_SUCCESS) return status;

    /* Select App */
    status = phalMfdfEVx_SelectApplication(pAlMfdfEVx, 0x00, aid, NULL);
    if (status != PH_ERR_SUCCESS) return status;

    /* Authenticate current App MK (AES in your design) */
    // status = phalMfdfEVx_AuthenticateAES(
    //     pAlMfdfEVx,
    //     PHAL_MFDFEVX_NO_DIVERSIFICATION,
    //     wKeyNo, wKeyVer,
    //     APP_MASTER_KEY, NULL, 0
    // );
    // status = phalMfdfEVx_AuthenticateEv2(
    //     pAlMfdfEVx,
    //     PHAL_MFDFEVX_AUTH_FIRST,
    //     PHAL_MFDFEVX_NO_DIVERSIFICATION,
    //     wKeyNo, wKeyVer,
    //     APP_MASTER_KEY,
    //     NULL, 0, 
    //     sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In
    // );
    // if (status != PH_ERR_SUCCESS) return status;
    PH_CHECK_SUCCESS_FCT(status,
        dbg_AuthenticateEv2(pKeyStore, pAlMfdfEVx,
            PHAL_MFDFEVX_AUTH_FIRST,
            APPLICATION_KEY_PICC,          // old app key slot
            /*cardKeyNo*/ 0x00,
            /*capsLen*/ sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In));

    /* Rotate App MK to NEW_AES128 */
    // status = phalMfdfEVx_ChangeKey(
    //     pAlMfdfEVx,
    //     PHAL_MFDFEVX_NO_DIVERSIFICATION,
    //     wKeyNo, wKeyVer,
    //     KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
    //     0x00,                     /* keep key type = AES */
    //     NULL, 0
    // );
    // if (status != PH_ERR_SUCCESS) return status;
    // status = phalMfdfEVx_ChangeKeyEv2(
    //     pAlMfdfEVx,
    //     PHAL_MFDFEVX_NO_DIVERSIFICATION,
    //     wKeyNo, wKeyVer,
    //     KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
    //     0x00,
    //     0x00,                     /* keep key type = AES */
    //     NULL, 0
    // );
    // if (status != PH_ERR_SUCCESS) return status;
    PH_CHECK_SUCCESS_FCT(status,
        dbg_ChangeKeyEv2(pKeyStore, pAlMfdfEVx,
            APPLICATION_KEY_PICC,          // old
            MASTER_KEY_PICC,               // new
            /*set*/ 0x00, /*card key#*/ 0x00));

    /* Reset the secure session context */
    // PH_CHECK_SUCCESS_FCT(status, phalMfdfEVx_SelectApplication(pAlMfdfEVx, 0x00, aid, NULL));
    // status = phalMfdfEVx_SelectApplication(pAlMfdfEVx, 0x00, aid, NULL);
    // if (status != PH_ERR_SUCCESS) {
    //     DEBUG_PRINTF("\tApp re-selection after MK change FAILED with code 0x%04x! \n", status);
    //     return status;
    // }

    /* Open EV2 session for the app (first in the chain) */
    // status = phalMfdfEVx_AuthenticateEv2(
    //     pAlMfdfEVx,
    //     PHAL_MFDFEVX_AUTH_FIRST,
    //     PHAL_MFDFEVX_NO_DIVERSIFICATION,
    //     KEY_get(MASTER_KEY_PICC)->keyno, KEY_get(MASTER_KEY_PICC)->version,
    //     APP_MASTER_KEY,
    //     NULL, 0, 
    //     sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In
    // );
    // if (status != PH_ERR_SUCCESS) {
    //     DEBUG_PRINTF("\tApp authentication with new PICC Master FAILED with code 0x%04x! \n", status);
    //     return status;
    // }
    // PH_CHECK_SUCCESS_FCT(status,
    //     dbg_AuthenticateEv2(pKeyStore, pAlMfdfEVx,
    //         PHAL_MFDFEVX_AUTH_FIRST,
    //         MASTER_KEY_PICC,               // must match what you wrote in step B
    //         0x00,
    //         sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In));
    status = dbg_AuthenticateEv2(pKeyStore, pAlMfdfEVx,
            PHAL_MFDFEVX_AUTH_FIRST,
            MASTER_KEY_PICC,               // must match what you wrote in step B
            0x00,
            sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In);
    if (status != PH_ERR_SUCCESS) {
        DEBUG_PRINTF("\tApp authentication with new PICC Master FAILED with code 0x%04x! \n", status);
        status = dbg_AuthenticateEv2(pKeyStore, pAlMfdfEVx,
                PHAL_MFDFEVX_AUTH_FIRST,
                APPLICATION_KEY_PICC,               // must match what you wrote in step B
                0x00,
            sizeof(PCDcap2In), PCDcap2, PCDcap2In, PDcap2In);
        if (status != PH_ERR_SUCCESS) {
            DEBUG_PRINTF("\tApp authentication with APPLICATION_KEY_PICC also FAILED with code 0x%04x! \n", status);
            return status;
        }
    }

    DEBUG_PRINTF("\tApp authentication with new PICC Master DONE! \n");

    return PH_ERR_SUCCESS;
}
