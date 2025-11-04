/*----------------------------------------------------------------------------*/
/* Copyright 2014,2015,2023-2024 NXP                                          */
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

#ifndef SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PH_NXPCTBUILD_H_
#define SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PH_NXPCTBUILD_H_

/* *****************************************************************************************************************
 * MACROS/Defines
 * **************************************************************************************************************** */

#define NXPBUILD__PHHAL_HW_GOC_7642
//#define NXPBUILD__PHHAL_HW_PALLAS

#ifdef NXPBUILD__PSP_SW_MODE_ENABLE /* Disable PN7642 CT component if it is not required in PSP build. */
#undef NXPBUILD__PHHAL_HW_GOC_7642
#endif

/**
 * Maximum contact interface supported per board
 * */
#if defined(NXPBUILD__PHHAL_HW_PN7462AU)
      #define PHAPP_MAX_CT_SLOT_SUPPORTED                 0x01U
#elif defined(NXPBUILD__PHHAL_HW_GOC_7642)
      #ifndef PHAPP_MAX_CT_SLOT_SUPPORTED /* Do not define MAX CT SLOT here if application already defined the same. */
          #define PHAPP_MAX_CT_SLOT_SUPPORTED             0x02U
      #endif
#elif defined(NXPBUILD__PHHAL_HW_PALLAS)
      #define PHAPP_MAX_CT_SLOT_SUPPORTED                 0x03U
#endif

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/**
 * This enum is used select the slot (Main slot or auxillary slot)
*/
typedef enum phhalCt_SlotType
{
      E_AUX_SLOT1    = 0x00,      /**< Selection for auxiliary slot of the CT interface with TDA */
      E_AUX_SLOT2    = 0x01,      /**< Selection for auxiliary slot of the CT interface with TDA */
      E_AUX_SLOT3    = 0x02,      /**< Selection for auxiliary slot of the CT interface with TDA */
      E_MAIN_SLOT    = 0x03,      /**< Selection for Main slot of the CT interface */
      E_AUX_LAST,                 /**< For Last slot check */
      E_AUX_INVALID  = 0xFF       /**< default value */

}phhalCt_SlotType_t;

/** Run time configurable parameters.  @sa phpalCt_SetConfig */
typedef enum
{
    E_ISO7816_ENABLE = 0,         /**< [in] If Logic 1 EMVCo standard in use, else 7816.*/
    E_EMVCO_ENABLE = 1,           /**< [in] If Logic 1 EMVCo standard in use, else 7816.*/
    E_COMP_LAST
} phAppCt_ComplianceType_t;


/** Run time configurable parameters.  @sa phpalCt_SetConfig */
typedef enum
{
    E_CONF_COMPLIANCE = 0,
    E_CONF_CARD_PRESENCE,
    E_CONF_ACTIVATION_STATE,
    E_CONF_SELECT_SLOT,
    E_CONF_PROTOCOL,
    E_CONF_IFSC,
    E_CONF_MAX_IFSD,
    E_CONF_TIMER,
    E_CONF_LAST

} phAppCt_Configs_t;
#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
#endif /* SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PH_NXPCTBUILD_H_ */
