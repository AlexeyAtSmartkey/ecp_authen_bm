
#include <phApp_Init.h>
#include "nfc_comm.h"
#include "key_manager.h"

#define AES128_KEY_ADDRESS      					3U
#define AES128_KEY_VERSION      					00
#define AES128_KEY_POS          					16U

#define PICC_AES128_KEY_ADDRESS  					4U
#define PICC_AES128_KEY_VERSION  					1U
#define PICC_AES128_KEY_POS      					17U

#define APPLE_PASS_AES128_KEY_ADDRESS				5U
#define APPLE_PASS_AES128_KEY_VERSION				1U
#define APPLE_PASS_AES128_KEY_POS					18U

#define APPLE_PASS_APP2_AES128_KEY_1_ADDRESS		6U
#define APPLE_PASS_APP2_AES128_KEY_1_VERSION		0U
#define APPLE_PASS_APP2_AES128_KEY_1_POS			19U

#define APPLE_PASS_APP2_AES128_KEY_2_ADDRESS		7U
#define APPLE_PASS_APP2_AES128_KEY_2_VERSION		0U
#define APPLE_PASS_APP2_AES128_KEY_2_POS			20U

// Transport keys
#ifdef NXPBUILD__PHHAL_HW_PN7642
#if defined PN7642EV_C100
uint8_t aTPT_KEY_AES128[16]      = { 0x4B, 0x3C, 0xEA, 0xED, 0x37, 0xCB, 0x6C, 0x03, 0xDB, 0x32, 0x2B, 0xB4, 0x83, 0x88, 0x84, 0x74 };
uint8_t aTPT_KEY_AES256[32]      = { 0x7B, 0x98, 0x66, 0x46, 0xE1, 0x1B, 0x4D, 0xC5, 0x5B, 0xBF, 0x1D, 0x35, 0xF2, 0xB0, 0x0C, 0xAC,
                                     0xBA, 0x0A, 0xE0, 0xE8, 0x22, 0xD7, 0x0E, 0x89, 0xEA, 0xB9, 0x58, 0x25, 0xBA, 0x84, 0x3B, 0x82 };
#elif defined PN7642EV_C101
uint8_t aTPT_KEY_AES128[16]      = { 0xA6, 0x66, 0xB9, 0x71, 0x0B, 0x9A, 0x7A, 0xD0, 0x83, 0x1B, 0x32, 0xC7, 0xD3, 0x3D, 0xBF, 0x72};
uint8_t aTPT_KEY_AES256[32]      = { 0xE0, 0x5B, 0x44, 0xF8, 0xF3, 0xC2, 0x5A, 0x71, 0x6E, 0xD8, 0xAE, 0x84, 0x75, 0x29, 0xDA, 0xF3,
                                     0x17, 0xE0, 0x92, 0xE5, 0xFC, 0x64, 0x3D, 0x94, 0x6C, 0x73, 0x2D, 0x62, 0xF4, 0x2F, 0x72, 0x29 };
#elif defined PN7642EV_INT
uint8_t aTPT_KEY_AES128[16]      = { 0x9C, 0x2F, 0xEB, 0x25, 0xDF, 0x9D, 0xD1, 0x93, 0x36, 0xA3, 0xB1, 0x85, 0x38, 0x2A, 0xA2, 0x5A };
uint8_t aTPT_KEY_AES256[32]      = { 0xC1, 0xF6, 0x5F, 0x45, 0xAB, 0x73, 0xC4, 0x52, 0xBC, 0xC3, 0x92, 0xB5, 0x13, 0x55, 0x5B, 0x6B,
                                     0x9A, 0xA0, 0x25, 0x5E, 0x37, 0x18, 0x36, 0xEE, 0x0B, 0xD2, 0xC3, 0xCE, 0xDA, 0xCB, 0x95, 0x42 };

#else
#define aTPT_KEY_AES128     NULL
#define aTPT_KEY_AES256     NULL
#endif /* PN7642EV_C100 */
#endif /* NXPBUILD__PHHAL_HW_PN7642 */


uint8_t aAPP_ROOT_KEY_AES128[16] =
{
	0x46, 0xF3, 0xD1, 0x11, 0x30, 0xD8, 0x8C, 0x3C, 0x96, 0xF2, 0xF5, 0x98, 0xFB, 0x9C, 0x0F, 0x51
};

uint8_t aAPP_ROOT_KEY_AES256[32] =
{
	0x20, 0x7D, 0x74, 0xCF, 0x3E, 0xED, 0x13, 0xAE, 0x13, 0x73, 0xD6, 0x1E, 0x13, 0x45, 0x92, 0xF2,
	0x26, 0xAE, 0x11, 0x12, 0x59, 0x04, 0x61, 0x62, 0x3C, 0xF7, 0x6E, 0xB2, 0x7E, 0xF9, 0xB5, 0x5C
};

uint8_t aExpDecData[16] =
{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

uint8_t aDerivMsg_Dec[24] =
{
	0x01, 0x23, 0x45, 0x67, 0x09, 0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

uint8_t aWIV[16] =
{
	0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44
};




static uint8_t default_aes128_key[24] =
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Default key for transaction MAC
static uint8_t aAES128Key[24] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// PICC master key
static uint8_t picc_aAES128Key[24] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

// Apple test pas application 1 key
static uint8_t applePass_aAES128Key[24] = {
		0xF2, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
};

// Apple test pas application 2 key 1
static uint8_t applePass_app2_aAES128Key_1[24] = {
		0xF6, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06
};

// Apple test pas application 2 key 2
static uint8_t applePass_app2_aAES128Key_2[24] = {
//		0xF7, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
//		0x18, 0x69, 0xe1, 0xe4, 0x7a, 0xf0, 0x74, 0xf4, 0xfc, 0xf7, 0x6a, 0x4b, 0xa9, 0xcf, 0x07, 0x09	// Access grid test
		0x0c, 0x15, 0xe9, 0xed, 0xa2, 0xea, 0x82, 0x24, 0x92, 0xd8, 0x13, 0x9a, 0xc3, 0x4f, 0x56, 0xaf  // SPK from access grid
};




static phStatus_t StoreKeysInKeyStore(void *pKeyStore);

static phStatus_t AddToKeyStore(void *pKeyStore, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyPos,
    uint16_t wKeyType, uint8_t * pKey);


void *pKeyStore;
phKeyStore_PN76XX_Provision_DataParams_t stKeyStore_Prov;
phCryptoSym_mBedTLS_DataParams_t         stCryptoSym;


KEY_Params_t currentKey;


//-------------------------------------------------------------
phStatus_t KEY_MANAGER_init(void)
{
	phStatus_t status = PH_ERR_INTERNAL_ERROR;

	pKeyStore = phNfcLib_GetDataParams(PH_COMP_KEYSTORE);

	status = StoreKeysInKeyStore(pKeyStore);

	return status;
}

//-------------------------------------------------------------
KEY_Params_t *KEY_get(KEY_Type_e key_type)
{
	switch(key_type)
	{
		case MASTER_KEY_PICC_DEFAULT:

			break;

		case MASTER_KEY_PICC:

			currentKey.key_address = PICC_AES128_KEY_ADDRESS;
			currentKey.key_version = PICC_AES128_KEY_VERSION;

			return &currentKey;

			break;

		case APPLICATION_KEY_PICC:

			currentKey.key_address = AES128_KEY_ADDRESS;
			currentKey.key_version = AES128_KEY_VERSION;

			return &currentKey;

			break;

		case PICC_WRITE_KEY:

			break;

		case APPLICATION_KEY_APPLE_PASS:

			currentKey.key_address = APPLE_PASS_APP2_AES128_KEY_1_ADDRESS;
			currentKey.key_version = APPLE_PASS_APP2_AES128_KEY_1_VERSION;

			return &currentKey;

			break;

		case ACCESSGRID_READ_KEY_ID:

			currentKey.key_address = APPLE_PASS_APP2_AES128_KEY_2_ADDRESS;
			currentKey.key_version = APPLE_PASS_APP2_AES128_KEY_2_VERSION;

			return &currentKey;

			break;

		default:

			return NULL;

			break;
	}

	return NULL;
}

//-------------------------------------------------------------
uint8_t *TRANSACTION_MAC_KEY_get(void)
{
	return aAES128Key;
}

//-------------------------------------------------------------
static phStatus_t StoreKeysInKeyStore(void *pKeyStore)
{
    phStatus_t status;

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX
        /* Initialize CryptoSym component for provisioning the Keys. */
        status = phCryptoSym_mBedTLS_Init(&stCryptoSym, sizeof(phCryptoSym_mBedTLS_DataParams_t), NULL);
        CHECK_STATUS(status);

        /* Initialize KeyCtore component to provision the keys. */
        status = phKeyStore_PN76XX_Provision_Init(&stKeyStore_Prov, sizeof(phKeyStore_PN76XX_Provision_DataParams_t), &stCryptoSym,
            PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_ENABLED, aTPT_KEY_AES128, aTPT_KEY_AES256, aAPP_ROOT_KEY_AES128,
            aAPP_ROOT_KEY_AES256, aExpDecData, aDerivMsg_Dec, aWIV);
        CHECK_STATUS(status);
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */


#ifdef NXPBUILD__PH_KEYSTORE_PN76XX

	status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, aAES128Key);
	CHECK_SUCCESS(status);

	status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, PICC_AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, picc_aAES128Key);
	CHECK_SUCCESS(status);

    status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, APPLE_PASS_AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, applePass_aAES128Key);
	CHECK_SUCCESS(status);

	status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, APPLE_PASS_APP2_AES128_KEY_1_POS, PH_KEYSTORE_KEY_TYPE_AES128, applePass_app2_aAES128Key_1);
	CHECK_SUCCESS(status);

	status = phKeyStore_PN76XX_Provision_AppFixedKeys(&stKeyStore_Prov, APPLE_PASS_APP2_AES128_KEY_2_POS, PH_KEYSTORE_KEY_TYPE_AES128, applePass_app2_aAES128Key_2);
	CHECK_SUCCESS(status);

    /* Initialize KeyCtore component to provision the keys. */
    phKeyStore_PN76XX_Provision_DeInit(&stKeyStore_Prov);
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */

    status = AddToKeyStore(pKeyStore, AES128_KEY_ADDRESS, AES128_KEY_VERSION, AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
	CHECK_SUCCESS(status);

    status = AddToKeyStore(pKeyStore, PICC_AES128_KEY_ADDRESS, PICC_AES128_KEY_VERSION, PICC_AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
	CHECK_SUCCESS(status);

    status = AddToKeyStore(pKeyStore, APPLE_PASS_AES128_KEY_ADDRESS, APPLE_PASS_AES128_KEY_VERSION, APPLE_PASS_AES128_KEY_POS, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
	CHECK_SUCCESS(status);

	status = AddToKeyStore(pKeyStore, APPLE_PASS_APP2_AES128_KEY_1_ADDRESS, APPLE_PASS_APP2_AES128_KEY_1_VERSION, APPLE_PASS_APP2_AES128_KEY_1_POS, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
	CHECK_SUCCESS(status);

	status = AddToKeyStore(pKeyStore, APPLE_PASS_APP2_AES128_KEY_2_ADDRESS, APPLE_PASS_APP2_AES128_KEY_2_VERSION, APPLE_PASS_APP2_AES128_KEY_2_POS, PH_KEYSTORE_KEY_TYPE_AES128, default_aes128_key);
	CHECK_SUCCESS(status);

    return status;
}

//-------------------------------------------------------------
static phStatus_t AddToKeyStore(void *pKeyStore, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyPos,
    uint16_t wKeyType, uint8_t * pKey)
{
    phStatus_t status = PH_ERR_SUCCESS;

#ifdef NXPBUILD__PHAL_MFDFEVX_SAM_NONX
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
#endif /* NXPBUILD__PHAL_MFDFEVX_SAM_NONX */

    status = phKeyStore_FormatKeyEntry(pKeyStore, bKeyNo, wKeyType);
    CHECK_SUCCESS(status);

    status = phKeyStore_SetKeyAtPos(pKeyStore, bKeyNo, bKeyPos, wKeyType, pKey, bKeyVer);
    CHECK_SUCCESS(status);

    return status;
}
