
#include <phApp_Init.h>
#include "nfc_comm.h"
#include "key_manager.h"


KEY_Params_t aKeys[] = {
    {AES128_KEY_ADDRESS,                   AES128_KEY_VERSION,                   AES128_KEY_POS,                   (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}, // Application Master Key
    {PICC_AES128_KEY_ADDRESS,              PICC_AES128_KEY_VERSION,              PICC_AES128_KEY_POS,              (uint8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"}, // PICC AES128 Key
    {APPLE_PASS_AES128_KEY_ADDRESS,        APPLE_PASS_AES128_KEY_VERSION,        APPLE_PASS_AES128_KEY_POS,        (uint8_t *)"\xF2\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"}, // Apple Pass AES128 Key
    {APPLE_PASS_APP2_AES128_KEY_1_ADDRESS, APPLE_PASS_APP2_AES128_KEY_1_VERSION, APPLE_PASS_APP2_AES128_KEY_1_POS, (uint8_t *)"\xF6\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06"}, // Apple Pass App2 AES128 Key 1
    {APPLE_PASS_APP2_AES128_KEY_2_ADDRESS, APPLE_PASS_APP2_AES128_KEY_2_VERSION, APPLE_PASS_APP2_AES128_KEY_2_POS, (uint8_t *)"\x0C\x15\xE9\xED\xA2\xEA\x82\x24\x92\xD8\x13\x9A\xC3\x4F\x56\xAF"}  // Apple Pass App2 AES128 Key 2
};

// Transport keys
#ifdef NXPBUILD__PHHAL_HW_PN7642
#if defined PN7642EV_C100
uint8_t aTPT_KEY_AES128[16]                  = { 0x4B, 0x3C, 0xEA, 0xED, 0x37, 0xCB, 0x6C, 0x03, 0xDB, 0x32, 0x2B, 0xB4, 0x83, 0x88, 0x84, 0x74 };
uint8_t aTPT_KEY_AES256[32]                  = { 0x7B, 0x98, 0x66, 0x46, 0xE1, 0x1B, 0x4D, 0xC5, 0x5B, 0xBF, 0x1D, 0x35, 0xF2, 0xB0, 0x0C, 0xAC,
                                                 0xBA, 0x0A, 0xE0, 0xE8, 0x22, 0xD7, 0x0E, 0x89, 0xEA, 0xB9, 0x58, 0x25, 0xBA, 0x84, 0x3B, 0x82 };
#elif defined PN7642EV_C101
uint8_t aTPT_KEY_AES128[16]                  = { 0xA6, 0x66, 0xB9, 0x71, 0x0B, 0x9A, 0x7A, 0xD0, 0x83, 0x1B, 0x32, 0xC7, 0xD3, 0x3D, 0xBF, 0x72};
uint8_t aTPT_KEY_AES256[32]                  = { 0xE0, 0x5B, 0x44, 0xF8, 0xF3, 0xC2, 0x5A, 0x71, 0x6E, 0xD8, 0xAE, 0x84, 0x75, 0x29, 0xDA, 0xF3,
                                                 0x17, 0xE0, 0x92, 0xE5, 0xFC, 0x64, 0x3D, 0x94, 0x6C, 0x73, 0x2D, 0x62, 0xF4, 0x2F, 0x72, 0x29 };
#elif defined PN7642EV_INT
uint8_t aTPT_KEY_AES128[16]                  = { 0x9C, 0x2F, 0xEB, 0x25, 0xDF, 0x9D, 0xD1, 0x93, 0x36, 0xA3, 0xB1, 0x85, 0x38, 0x2A, 0xA2, 0x5A };
uint8_t aTPT_KEY_AES256[32]                  = { 0xC1, 0xF6, 0x5F, 0x45, 0xAB, 0x73, 0xC4, 0x52, 0xBC, 0xC3, 0x92, 0xB5, 0x13, 0x55, 0x5B, 0x6B,
                                                 0x9A, 0xA0, 0x25, 0x5E, 0x37, 0x18, 0x36, 0xEE, 0x0B, 0xD2, 0xC3, 0xCE, 0xDA, 0xCB, 0x95, 0x42 };

#else
#define aTPT_KEY_AES128     NULL
#define aTPT_KEY_AES256     NULL
#endif /* PN7642EV_C100 */
#endif /* NXPBUILD__PHHAL_HW_PN7642 */


static uint8_t aAPP_ROOT_KEY_AES128[]        = { 0x46, 0xF3, 0xD1, 0x11, 0x30, 0xD8, 0x8C, 0x3C, 0x96, 0xF2, 0xF5, 0x98, 0xFB, 0x9C, 0x0F, 0x51 };
static uint8_t aAPP_ROOT_KEY_AES256[]        = { 0x20, 0x7D, 0x74, 0xCF, 0x3E, 0xED, 0x13, 0xAE, 0x13, 0x73, 0xD6, 0x1E, 0x13, 0x45, 0x92, 0xF2,
	                                             0x26, 0xAE, 0x11, 0x12, 0x59, 0x04, 0x61, 0x62, 0x3C, 0xF7, 0x6E, 0xB2, 0x7E, 0xF9, 0xB5, 0x5C };

static uint8_t aExpDecData[]                 = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

static uint8_t aDerivMsg_Dec[]               = { 0x01, 0x23, 0x45, 0x67, 0x09, 0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	                                             0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };

static uint8_t aWIV[]                        = { 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44 };

static uint8_t default_aes128_key[]          = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* AES PICC key */
static uint8_t aPICC_MasterKey_DES[]         = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*
// Default key for transaction MAC
static uint8_t aAES128Key[]                  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
// PICC master key
static uint8_t picc_aAES128Key[]             = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
// Apple test pas application 1 key
static uint8_t applePass_aAES128Key[]        = { 0xF2, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
// Apple test pas application 2 key 1
static uint8_t applePass_app2_aAES128Key_1[] = { 0xF6, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 };
// Apple test pas application 2 key 2
// Cert Apple test key
// static uint8_t applePass_app2_aAES128Key_2[] = { 0xF7, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07 };
// Access grid test
// static uint8_t applePass_app2_aAES128Key_2[] = { 0x18, 0x69, 0xe1, 0xe4, 0x7a, 0xf0, 0x74, 0xf4, 0xfc, 0xf7, 0x6a, 0x4b, 0xa9, 0xcf, 0x07, 0x09	};
// SPK from access grid
static uint8_t applePass_app2_aAES128Key_2[] = { 0x0c, 0x15, 0xe9, 0xed, 0xa2, 0xea, 0x82, 0x24, 0x92, 0xd8, 0x13, 0x9a, 0xc3, 0x4f, 0x56, 0xaf };
*/

void*                                    pKeyStore;
phKeyStore_PN76XX_Provision_DataParams_t stKeyStore_Prov;
phCryptoSym_mBedTLS_DataParams_t         stCryptoSym;
// KEY_Params_t                             currentKey;

static phStatus_t StoreKeysInKeyStore(void *pKeyStore);
static phStatus_t AddToKeyStore(void *pKeyStore, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyPos, uint16_t wKeyType, uint8_t * pKey);
static phStatus_t ConfigHwSamV3(uint16_t wKeyType);

void* getKeyStore(void) {
    return pKeyStore;
}

//-------------------------------------------------------------
phStatus_t KEY_MANAGER_init(void) {
	phStatus_t status = PH_ERR_INTERNAL_ERROR;
	pKeyStore = phNfcLib_GetDataParams(PH_COMP_KEYSTORE);
	status = StoreKeysInKeyStore(pKeyStore);
	return status;
}

//-------------------------------------------------------------
// KEY_Params_t *KEY_get(KEY_Type_e key_type) {
//     KEY_Params_t* retKey = NULL;
//     uint8_t       n      = {0xff};
//     uint8_t       v      = {0xff};
// 	switch(key_type) {
// 		case MASTER_KEY_PICC:            n = PICC_AES128_KEY_ADDRESS;              v = PICC_AES128_KEY_VERSION;              break;
// 		case APPLICATION_KEY_PICC:       n = AES128_KEY_ADDRESS;                   v = AES128_KEY_VERSION;                   break;
// 		case APPLICATION_KEY_APPLE_PASS: n = APPLE_PASS_APP2_AES128_KEY_1_ADDRESS; v = APPLE_PASS_APP2_AES128_KEY_1_VERSION; break;
// 		case ACCESSGRID_READ_KEY_ID:     n = APPLE_PASS_APP2_AES128_KEY_2_ADDRESS; v = APPLE_PASS_APP2_AES128_KEY_2_VERSION; break;
// 		case MASTER_KEY_PICC_DEFAULT:
// 		case PICC_WRITE_KEY:
// 		default:                                                                                                             break;
// 	}
//     if (n != 0xff && v != 0xff) {
//         currentKey.keyno   = n;
//         currentKey.version = v;
//         retKey = &currentKey;
//     }
//     return retKey;
// }
KEY_Params_t *KEY_get(KEY_Type_e key_type) {
    KEY_Params_t* retKey = NULL;
	switch(key_type) {
		case MASTER_KEY_PICC:            retKey = &aKeys[1]; break;
		case APPLICATION_KEY_PICC:       retKey = &aKeys[0]; break;
		case APPLICATION_KEY_APPLE_PASS: retKey = &aKeys[3]; break;
		case ACCESSGRID_READ_KEY_ID:     retKey = &aKeys[4]; break;
		case MASTER_KEY_PICC_DEFAULT:
		case PICC_WRITE_KEY:
		default:                                                                                                             break;
	}
    return retKey;
}

//-------------------------------------------------------------
uint8_t *TRANSACTION_MAC_KEY_get(void) { return aKeys[0].key/*aAES128Key*/; }

//-------------------------------------------------------------
static phStatus_t StoreKeysInKeyStore(void *pKeyStore)
{
    phStatus_t status;

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX
    /* Initialize CryptoSym component for provisioning the Keys. */
    status = phCryptoSym_mBedTLS_Init(&stCryptoSym, sizeof(phCryptoSym_mBedTLS_DataParams_t), NULL);
    CHECK_STATUS(status);

    /* Initialize KeyCtore component to provision the keys. */
    status = phKeyStore_PN76XX_Provision_Init(
        &stKeyStore_Prov, sizeof(phKeyStore_PN76XX_Provision_DataParams_t), &stCryptoSym,
        PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_ENABLED, 
        aTPT_KEY_AES128, aTPT_KEY_AES256, 
        aAPP_ROOT_KEY_AES128, aAPP_ROOT_KEY_AES256, 
        aExpDecData, aDerivMsg_Dec, aWIV);
    CHECK_STATUS(status);

    for (uint32_t i = 0; i < sizeof(aKeys)/sizeof(KEY_Params_t); i++) {
        status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, aKeys[i].position, PH_KEYSTORE_KEY_TYPE_AES128, aKeys[i].key);
        CHECK_SUCCESS(status);
    }
    /* DeInitialize KeyCtore component to provision the keys. */
    phKeyStore_PN76XX_Provision_DeInit(&stKeyStore_Prov);
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */

    /* Set the default PICC Master key in the key store */
    status = AddToKeyStore(pKeyStore, DES_KEY_ADDRESS, DES_KEY_VERSION, DES_KEY_POS, PH_KEYSTORE_KEY_TYPE_DES, aPICC_MasterKey_DES);
    CHECK_SUCCESS(status);

    for (uint32_t i = 0; i < sizeof(aKeys)/sizeof(KEY_Params_t); i++) {
        // status = AddToKeyStore(pKeyStore, aKeys[i].address, aKeys[i].version, aKeys[i].position, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
        status = AddToKeyStore(pKeyStore, aKeys[i].keyno, aKeys[i].version, aKeys[i].position, PH_KEYSTORE_KEY_TYPE_AES128, aKeys[i].key);
        CHECK_SUCCESS(status);
    }

    return status;
}

//-------------------------------------------------------------
static phStatus_t AddToKeyStore(void *pKeyStore, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyPos, uint16_t wKeyType, uint8_t * pKey) {
    phStatus_t status;
    // phStatus_t status = ConfigHwSamV3(wKeyType);
    // CHECK_SUCCESS(status)
    PH_CHECK_SUCCESS_FCT(status, ConfigHwSamV3(wKeyType));

    // status = phKeyStore_FormatKeyEntry(pKeyStore, bKeyNo, wKeyType);
    // CHECK_SUCCESS(status);
    PH_CHECK_SUCCESS_FCT(status, phKeyStore_FormatKeyEntry(pKeyStore, bKeyNo, wKeyType));

    // status = phKeyStore_SetKeyAtPos(pKeyStore, bKeyNo, bKeyPos, wKeyType, pKey, bKeyVer);
    // CHECK_SUCCESS(status);
    PH_CHECK_SUCCESS_FCT(status, phKeyStore_SetKeyAtPos(pKeyStore, bKeyNo, bKeyPos, wKeyType, pKey, bKeyVer));

    return status;
}

static phStatus_t ConfigHwSamV3(uint16_t wKeyType) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SAM_NONX
    phStatus_t status = PH_ERR_SUCCESS;
    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_AUTH_KEY, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_LOCK_KEY, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEYCLASS, 0x01);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CEK, 0xFE);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CEK, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_ENCRYPTION, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_DECRYPTION, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_VERIFY_MAC, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_GENERATE_MAC, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DF_KEY_NO, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_PL_KEY, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_MANDATE_KEY_DIVERSIFICATION, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_RESERVED_SAM_PRESONALIZATION, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEY_USAGE_INT_HOST, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEY_CHANGE_INT_HOST, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_SESSION_KEY_USAGE_INT_HOST, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY_INT_HOST, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY_INT_HOST, 0x0);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_AEK, 0xFE);
    CHECK_STATUS(status);

    status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEYV_AEK, 0x0);
    CHECK_STATUS(status);

    switch(wKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_DES:
            status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV, 0x0);
            CHECK_STATUS(status);

            status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DES_KEY_OPTION, 0x0);
            CHECK_STATUS(status);
            break;

        case PH_KEYSTORE_KEY_TYPE_3K3DES:
            status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_DES_KEY_OPTION, 0x01);
            CHECK_STATUS(status);

            status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV, 0x1);
            CHECK_STATUS(status);
            break;

        default:
            status = phKeyStore_SamAV3_SetConfig(pKeyStore_SamAv3, PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV, 0x1);
            CHECK_STATUS(status);
            break;
    }
    return status;
#else
    return PH_ERR_SUCCESS;
#endif /* NXPBUILD__PHAL_MFDFEVX_SAM_NONX */
}
