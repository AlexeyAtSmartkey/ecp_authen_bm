/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                    */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* Example Source for NfcrdlibEx2_ECP, that uses Discovery loop implementation to
* demonstrate Enhanced Contactless polling as per Specification v2.0.
* By default Discovery Loop will start polling as per Compatibility mode (similar to
* PN7150) using NFC Forum v1.0 Mode i.e. setting as per NFC Forum Activity Specification v1.0
* will be followed for Collision resolution and activation and both POLL and LISTEN (only
* for Universal device) modes of discovery loop will be enabled.
*
* Displays detected tag information(like UID, SAK, Product
* Type) and prints information when it gets activated as a target by an external Initiator/reader.
*
* By default "ENABLE_ECP_COMPATIBILITY_MODE" macro is enabled to start polling as per
* ECP specification v2.0 and NFC Forum Activity Specification v2.2 to start the polling
* sequence in-line with PN7150 behavior.
*
* NFC Forum Mode: Whenever multiple technologies are detected, example will select first
* detected technology to resolve. Example will activate device at index zero whenever multiple
* device is detected.
*
* For EMVCo profile, this example provide VAS polling in EMVCo polling loop.
*
* Please refer Readme.txt file for Hardware Pin Configuration, Software Configuration and steps to build and
* execute the project which is present in the same project directory.
*
* $Author$
* $Revision$ (v07.10.00)
* $Date$
*/

/**
* Reader Library Headers
*/
#include <nfc_comm.h>
#include <phApp_Init.h>

#include "SmartLock.h"
#include "key_manager.h"
#include "picc_manager.h"
#include "apple_pass_manager.h"
#include "google_pass_manager.h"
#include "delay_ms.h"
/* Local headers */
#include "phpalI14443p4_Sw.h"


/*******************************************************************************
**   Definitions
*******************************************************************************/
/* Enabled the required Transport Keys. */
#ifdef NXPBUILD__PH_KEYSTORE_PN76XX
	#ifdef NXPBUILD__PHHAL_HW_PN7640
		/* #define PN7640EV_C100 */
		/* #define PN7640EV_C101 */
		/* #define PN7640EV_C102 */
	#endif /* NXPBUILD__PHHAL_HW_PN7640 */

	#ifdef NXPBUILD__PHHAL_HW_PN7642
		/* #define PN7642EV_C100 */
		/* #define PN7642EV_C101 */	#define PN7642EV_C100
		/* #define PN7642EV_INT */
	#endif /* NXPBUILD__PHHAL_HW_PN7642 */
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */

phacDiscLoop_Sw_DataParams_t       * pDiscLoop;       /* Pointer to Discovery loop component data-parameter */

/* The below variables needs to be initialized according to example requirements by a customer during Listen mode operation */
uint8_t  sens_res[2]     = {0x04, 0x00};              /* ATQ bytes - needed for anti-collision */
uint8_t  nfc_id1[3]      = {0xA1, 0xA2, 0xA3};        /* user defined bytes of the UID (one is hardcoded) - needed for anti-collision */
uint8_t  poll_res[18]    = {0x01, 0xFE, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0x23, 0x45 };
uint8_t  sel_res         = 0x40;
uint8_t  nfc_id3         = 0xFA;                      /* NFC3 byte - required for anti-collision */

/* The below array shall define the Technology polling sequence used by Discovery Loop in NFC Forum Mode.
 * Array size should be equals to PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED.
 * Note: User need to use ph_NxpBuild_App.h file to disable any technology or shall use Discovery Loop
 * phacDiscLoop_SetConfig "PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG" to enable/disable polling technologies mentioned in the below array.
 * As this array is only used to determine the Polling sequence that shall be used by Discovery Loop.
 */
#ifndef ENABLE_ECP_COMPATIBILITY_MODE
uint8_t baPasTechPollSeq[] = {
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_A,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_B,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F212,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F424,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_V,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_18000P3M3,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_VAS
};
#endif

/* The below array shall define the Technology polling sequence used by Discovery Loop in NFC Forum Mode as per
 * ECP Compatibility mode.
 * The below structure shall define the Technology polling sequence used by Discovery Loop in NFC Forum Mode.
 * Array size should be equals to PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED.
 * Note: User need to use ph_NxpBuild_App.h file to disable any technology or shall use Discovery Loop
 * phacDiscLoop_SetConfig "PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG" to enable/disable polling technologies mentioned in the below array.
 * As this array is only used to determine the Polling sequence that shall be used by Discovery Loop.
 */
uint8_t baPasTechPollSeq_Comp_Mode[] = {
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_A,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_B,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F212,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F424,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_V,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_18000P3M3,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_VAS
};

#ifdef PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION
uint32_t aECPTaskBuffer[ECP_DEMO_TASK_STACK];
#else /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
#define aECPTaskBuffer    NULL
#endif /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */

#ifdef PH_OSAL_FREERTOS
const uint8_t bTaskName[configMAX_TASK_NAME_LEN] = {"ECP"};
#else
const uint8_t bTaskName[] = {"ECP"};
#endif /* PH_OSAL_FREERTOS */

/*******************************************************************************
**   Static Defines
*******************************************************************************/

/* This is used to save restore Poll Config.
 * If in case application has update/change PollCfg to resolve Tech
 * when Multiple Tech was detected in previous poll cycle
 */
static uint16_t bSavePollTechCfg;

static volatile uint8_t bInfLoop = 1U;

/* Enable ECP Compatibility mode with NFC Forum Activity v2.2 configuration.
 * Disabling this macro shall enable Polling as per ECP Specification v2.0
 * using NFC Forum Activity Specification v2.2. */
#define ENABLE_ECP_COMPATIBILITY_MODE

/* ECP VASUP-A Format 1 as per ECP v1.0 */
#define VASUP_A_FORMAT_VERSION_1  1U
/* ECP VASUP-A Format 2 as per ECP v2.0 */
#define VASUP_A_FORMAT_VERSION_2  2U

/* Configure the ECP VASUP-A command format version (either 1 or 2). */
#define VASUP_A_FORMAT_SELECTION  VASUP_A_FORMAT_VERSION_2

/* VAS Command used in Polling sequence. */
#if VASUP_A_FORMAT_SELECTION == VASUP_A_FORMAT_VERSION_1
static uint8_t  aVASCmd[3]  = {0xC3, 0x00, 0x00};
#else
static uint8_t  aVASCmd[] = {0xC3, 0x02, 0x02, 0x02, 0x4D, 0x22};
#endif

/* By default Discovery Loop shall be configured in NFC Forum Mode.
 * To enable EMVCO profile, assign EX2_DISCLOOP_PROFILE macro with 'PHAC_DISCLOOP_PROFILE_EMVCO'.
*/
#define EX2_DISCLOOP_PROFILE    PHAC_DISCLOOP_PROFILE_NFC    /* PHAC_DISCLOOP_PROFILE_NFC - NFC Profile and PHAC_DISCLOOP_PROFILE_EMVCO - EMVCo Profile */

uint16_t has_to_be_removed = 0;

static const uint16_t techMaskSeq[] = {
    PHAC_DISCLOOP_POS_BIT_MASK_A,
    PHAC_DISCLOOP_POS_BIT_MASK_B,
    PHAC_DISCLOOP_POS_BIT_MASK_F212,
    PHAC_DISCLOOP_POS_BIT_MASK_F424,
    PHAC_DISCLOOP_POS_BIT_MASK_V,
    PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3,
    PHAC_DISCLOOP_POS_BIT_MASK_VAS
};

static const char *techMaskName[] = {
    " \tType A detected... \n",
    " \tType B detected... \n",
    " \tType F detected with baud rate 212... \n",
    " \tType F detected with baud rate 424... \n",
    " \tType V / ISO 15693 / T5T detected... \n",
    " \tType ISO 18000-3M3 detected... \n",
    " \tType VAS detected... \n"
};

phalMfdfEVx_Sw_DataParams_t    *palMfdfEVx;
phpalI14443p3a_Sw_DataParams_t *ppalI14443p3a;
phpalI14443p4_Sw_DataParams_t  *ppalI14443p4;


/*******************************************************************************
**   Prototypes
*******************************************************************************/

static uint16_t   ProcessDiscLoopStatus(uint16_t wEntryPoint, phStatus_t DiscLoopStatus);
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile);

/*******************************************************************************
**   Code
*******************************************************************************/
phStatus_t NFC_COMM_init (void) {
	phStatus_t status = PH_ERR_INTERNAL_ERROR;
	phNfcLib_Status_t     dwStatus;
#ifdef PH_PLATFORM_HAS_ICFRONTEND
        phNfcLib_AppContext_t AppContext = {0};
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

#ifndef PH_OSAL_NULLOS
        phOsal_ThreadObj_t Ex2_ECP;
#endif /* PH_OSAL_NULLOS */

	/* Perform OSAL Initialization. */
	(void)phOsal_Init();

	DEBUG_PRINTF("\n Enhanced Contactless Polling(ECP): \n");

#ifdef PH_PLATFORM_HAS_ICFRONTEND
	status = phbalReg_Init(&sBalParams, sizeof(phbalReg_Type_t));
	CHECK_STATUS(status);

	AppContext.pBalDataparams = &sBalParams;
	dwStatus = phNfcLib_SetContext(&AppContext);
	CHECK_NFCLIB_STATUS(dwStatus);
#endif

	/* Initialize library */
	dwStatus   = phNfcLib_Init();
	CHECK_NFCLIB_STATUS(dwStatus);
	if(dwStatus != PH_NFCLIB_STATUS_SUCCESS) return status;

	/* Set the generic pointer */
	pHal       = phNfcLib_GetDataParams(PH_COMP_HAL);
	pDiscLoop  = phNfcLib_GetDataParams(PH_COMP_AC_DISCLOOP);
	status     = KEY_MANAGER_init();
	CHECK_STATUS(status);

	palMfdfEVx = (phalMfdfEVx_Sw_DataParams_t *)phNfcLib_GetDataParams(PH_COMP_AL_MFDFEVX);

	/* Initialize other components that are not initialized by NFCLIB and configure Discovery Loop. */
	status     = phApp_Comp_Init(pDiscLoop);
	CHECK_STATUS(status);
	if(status != PH_ERR_SUCCESS) return status;

	/* Perform Platform Init */
	status     = phApp_Configure_IRQ();
	CHECK_STATUS(status);
	if(status != PH_ERR_SUCCESS) return status;

	/* Load selected profile for Discovery loop. */
    LoadProfile((phacDiscLoop_Profile_t)EX2_DISCLOOP_PROFILE);

	/* Save the Poll Configuration */
	status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, &bSavePollTechCfg);
	CHECK_STATUS(status);

    return status;
}

/**
* This function shall perform ECP Polling and shall detect and reports the NFC technology type detected.
*
* \param   pDataParams  The discovery loop data parameters
* \note                 This function will never return
*/
void NFC_COMM_process(void) {
    static uint16_t  wEntryPoint= PHAC_DISCLOOP_ENTRY_POINT_POLL; /* Start in poll mode */
    CHECK_STATUS(phhalHw_FieldOff(pHal)); /* Switch off RF field */
    CHECK_STATUS(phhalHw_Wait(pHal, PHHAL_HW_TIME_MICROSECONDS, 5100)); /* Wait for field-off time-out */
    // CHECK_STATUS(phhalHw_Wait(pHal, PHHAL_HW_TIME_MILLISECONDS, 500)); /* Wait for field-off time-out */
    CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION)); /* Before polling set Discovery Poll State to Detection, as later in the code it can be changed to e.g. PHAC_DISCLOOP_POLL_STATE_REMOVAL*/
    wEntryPoint = ProcessDiscLoopStatus(wEntryPoint, phacDiscLoop_Run(pDiscLoop, wEntryPoint)); /* Start discovery loop operation. */
    CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, bSavePollTechCfg)); /* Restore Poll Configuration */
    // CHECK_STATUS(phhalHw_FieldOff(pHal));
    // delay_ms(100);
}

static uint16_t ProcessCard() {
    phStatus_t    status;
    status = APPLE_PASS_read(palMfdfEVx, pDiscLoop);
    if(status != 0) {
        if (APP_InitMbedCrypto() == PN76_STATUS_SUCCESS) { status = ProcessGoogleWallet(pDiscLoop); }
        else {
            DEBUG_PRINTF("Crypto initialization failure\n");
            status = -1;
        }
        APP_DeInitMbedCrypto();
        if(status != 0) { status = PICC_DATA_read(palMfdfEVx); }
    }
    return status;
}

static uint16_t ProcessDiscLoopStatus_EntryPointPoll(uint16_t wEntryPoint, phStatus_t DiscLoopStatus) {
    // phStatus_t status;
    uint16_t   wTechDetected = 0;
    uint16_t   wNumberOfTags = 0;
    uint16_t   wValue;
    uint8_t    bIndex;
    uint16_t   wReturnEntryPoint;

    if(DiscLoopStatus == PHAC_DISCLOOP_MULTI_TECH_DETECTED) {                   /* Multiple Technology is detected in Technology detection phase of Discovery Loop. */
        DEBUG_PRINTF (" \n Multiple technology detected: \n");
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected));
        for (size_t i = 0; i < sizeof(techMaskSeq)/sizeof(*techMaskSeq); i++) {
            uint16_t mask = techMaskSeq[i];
            if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, mask)) {
                DEBUG_PRINTF(techMaskName[i]);                
                phStatus_t st;
                PH_CHECK_SUCCESS_FCT(st, phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, mask)); /* only poll this tech next */
                DEBUG_PRINTF("  Resolving "); phApp_PrintTech(mask); DEBUG_PRINTF("...\n");
                PH_CHECK_SUCCESS_FCT(st, phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION)); /* move straight to collision‐resolution state */
                DiscLoopStatus = phacDiscLoop_Run(pDiscLoop, wEntryPoint); /* restart the loop so it only does VAS now */
                break;
            }
        }
        /* Print the technology resolved */
        // phApp_PrintTech((1 << bIndex));
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION)); /* Set Discovery Poll State to collision resolution */
        DiscLoopStatus = phacDiscLoop_Run(pDiscLoop, wEntryPoint); /* Restart discovery loop in poll mode from collision resolution phase */
    }

    /* Multiple Cards/Peers are detected in Technology detection phase of Discovery Loop. */
    switch (DiscLoopStatus) {
    case PHAC_DISCLOOP_MULTI_DEVICES_RESOLVED:
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected)); /* Get Detected Technology Type */
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags)); /* Get number of tags detected */
        DEBUG_PRINTF (" \n Multiple cards resolved: %d cards \n",wNumberOfTags);
        phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);
        if (wNumberOfTags > 1) {
            /* Get 1st Detected Technology and Activate device at index 0 */
            phStatus_t status = 0;
            for(bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++) {
                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, (1 << bIndex))) {
                    DEBUG_PRINTF("\t Activating one card...\n");
                    status = phacDiscLoop_ActivateCard(pDiscLoop, bIndex, 0) & PH_ERR_MASK;
                    break;
                }
            }
            if (
                (status == PHAC_DISCLOOP_DEVICE_ACTIVATED)         ||
                (status == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) ||
                (status == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND)
            ) {
                CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected)); /* Get Detected Technology Type */
                phApp_PrintTagInfo(pDiscLoop, 0x01, wTechDetected);
            } else {
                PRINT_INFO("\t\tCard activation failed...\n");
            }
        }
        break;

    case PHAC_DISCLOOP_MERGED_SEL_RES_FOUND:
        DEBUG_PRINTF (" \n Device having T4T and NFC-DEP support detected... \n");
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected)); /* Get Detected Technology Type */
        phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);
        break;
    
    case PHAC_DISCLOOP_DEVICE_ACTIVATED:
        // DEBUG_PRINTF (" \n Card detected and activated successfully... \n");
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags));
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected)); /* Get Detected Technology Type */
        if (has_to_be_removed == 0) ProcessCard();
        has_to_be_removed = 10;
        CHECK_STATUS(phhalHw_FieldReset(pHal));
        break;

    case PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED:  DEBUG_PRINTF (" \n Active target detected... \n");  break;
    case PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED:
        DEBUG_PRINTF (" \n Passive target detected... \n");
        CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected)); /* Get Detected Technology Type */
        phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);
        break;

    default:
        if (has_to_be_removed > 0) has_to_be_removed--;
        if (DiscLoopStatus == PHAC_DISCLOOP_FAILURE) {
            CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue));
            DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
        } else {
            DEBUG_ERROR_PRINT(PrintErrorInfo(status));
        }
        break;
    }
    return wEntryPoint;
}

static uint16_t ProcessDiscLoopStatus(uint16_t wEntryPoint, phStatus_t DiscLoopStatus) {
    uint16_t   wValue;
    uint16_t   wReturnEntryPoint;

    DiscLoopStatus &= PH_ERR_MASK;

    /* Process Discovery Loop status based on Entry Mode. */
    if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL) {
        wReturnEntryPoint = ProcessDiscLoopStatus_EntryPointPoll(wEntryPoint, DiscLoopStatus);
        /* Switch to LISTEN mode after POLL mode. Update the Entry point to LISTEN mode. */
        // wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
    } else {
        if(DiscLoopStatus == PHAC_DISCLOOP_EXTERNAL_RFOFF) {
            /*
             * Enters here if in the target/card mode and external RF is not available
             * Wait for LISTEN timeout till an external RF is detected.
             * Application may choose to go into standby at this point.
             */
            CHECK_STATUS(phhalHw_FieldOff(pHal));
            CHECK_STATUS(phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_RFON_INTERRUPT, PH_ON));
            wReturnEntryPoint = (phhalHw_EventWait(pHal, LISTEN_PHASE_TIME_MS) & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT
                ? PHAC_DISCLOOP_ENTRY_POINT_POLL 
                : PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
        } else {
            switch (DiscLoopStatus)
            {
            case PHAC_DISCLOOP_ACTIVATED_BY_PEER: DEBUG_PRINTF (" \n Device activated in listen mode... \n"); break;
            case PH_ERR_INVALID_PARAMETER: /* In case of Front end used is RC663, then listen mode is not supported.
                                         * Switch from listen mode to poll mode. */                           break;
            
            default:
                if(DiscLoopStatus == PHAC_DISCLOOP_FAILURE) {
                    CHECK_STATUS(phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue));
                    DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
                } else {
                    DEBUG_ERROR_PRINT(PrintErrorInfo(status));
                }
                break;
            }
            wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL; /* On successful activated by Peer, try to switch to Poll mode. */
        }
    }
    return wReturnEntryPoint;
}

/**
* This function will load/configure Discovery loop with default values based on interested profile
 * Application can read these values from EEPROM area and load/configure Discovery loop via SetConfig
* \param   bProfile      Reader Library Profile
* \note    Values used below are default and is for demonstration purpose.
*/
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile) {
    // phStatus_t status = PH_ERR_SUCCESS;
    uint16_t   wPasPollConfig = 0;
    uint16_t   wActPollConfig = 0;  /* Disable the Active Mode Poll configuration. */
    uint16_t   wPasLisConfig  = 0;
    uint16_t   wActLisConfig  = 0;  /* Disable the Active Mode Listen configuration. */

    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
    #endif
    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_B;
    #endif
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_VAS;

    CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG, wActPollConfig)); /* Set Active poll bitmap config. */
    CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, wActLisConfig)); /* Set Active listen bitmap config. */
    pDiscLoop->sVASTargetInfo.pCmdBytes    = aVASCmd;                   /* Configure the VAS Command bytes that need to be sent as per ECP Spec. */
    pDiscLoop->sVASTargetInfo.bLenCmdBytes = sizeof(aVASCmd);
    CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_VASUP_A_FORAMT_BYTE, VASUP_A_FORMAT_SELECTION)); /* Configure the VAS Format selection bytes that need to be sent as per ECP Spec. */

    /* Based on Discovery Loop Profile, configuration shall be performed. */
    if(bProfile == PHAC_DISCLOOP_PROFILE_NFC) {
        #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
        wPasPollConfig |= (PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424);
        #endif
        #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
        wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_V;
        #endif
        #ifdef NXPBUILD__PHPAL_I18000P3M3_SW
        wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3;
        #endif
        #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE
        wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
        #endif
        #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE
        wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
        #endif
        #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE
        wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
        #endif

        
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, (PHAC_DISCLOOP_POS_BIT_MASK_A | PHAC_DISCLOOP_POS_BIT_MASK_B |
            PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424))); /* Enable the Bailout bitmap configuration for Type A, B and F technology. */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, wPasPollConfig)); /* Set Passive poll bitmap config. */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig)); /* Set Passive listen bitmap config. */
        #ifdef ENABLE_ECP_COMPATIBILITY_MODE
        CHECK_STATUS(phacDiscLoop_CfgPollSeq(pDiscLoop, baPasTechPollSeq_Comp_Mode)); /* Configure the Polling sequence as per Compatibility mode (similar to PN7150) */
        #else /* ENABLE_ECP_COMPATIBILITY_MODE */
        CHECK_STATUS(phacDiscLoop_CfgPollSeq(pDiscLoop, baPasTechPollSeq)); /* Configure the Polling sequence as per NFC Forum Activity 2.2 and ECP Specification v2.0. */
        #endif /* ENABLE_ECP_COMPATIBILITY_MODE */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_NFC)); /* Set Discovery loop Operation mode */
    } else if (bProfile == PHAC_DISCLOOP_PROFILE_EMVCO) {
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, wPasPollConfig)); /* passive Poll bitmap config. */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig)); /* Passive Listen bitmap config. */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTVAS_VALUE_US, PH_NXPNFCRDLIB_CONFIG_TYPEA_GT)); /* Configure Guard Time for VAS TypeA technology Polling */
        CHECK_STATUS(phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_EMVCO)); /* Configure reader library mode */
    } else { /* Do Nothing */ }
    return PH_ERR_SUCCESS;
}
