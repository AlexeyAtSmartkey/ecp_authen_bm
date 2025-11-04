/*----------------------------------------------------------------------------*/
/* Copyright 2014, 2015, 2022  NXP                                                        */
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
 * TDA Abstraction Layer APIs should be used by HAL only
 * $Author:  $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 */

#ifndef SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_TDA_H_
#define SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_TDA_H_
/* *****************************************************************************************************************
 * Includes
 * *****************************************************************************************************************.*/
#include "ph_NxpCTBuild.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)

/* *****************************************************************************************************************
 * MACROS/Defines
 * *****************************************************************************************************************.*/

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * *****************************************************************************************************************.*/

/**
 * Context Structure consists of TDA8035 specific control lines and for each slot saves the state of its pin
 */
typedef struct
{
      uint8_t  bCmdvccn ;           /**< cmd Vccn used to control for Activation & Deactivation */
      uint8_t  bRstin ;             /**< TDA Reset line used to control for activation and deactivation */
      uint8_t  bClkdiv1 ;           /**< TDA Clock divider 1 */
      uint8_t  bClkdiv2 ;           /**< TDA clock divider 2 */
      uint8_t  bEn5v3vn ;           /**< Class or voltage selection */
      uint8_t  bEn1v8n ;            /**< Class or voltage selection */
      uint8_t  bChipselect ;        /**< Chip Select pin for TDA */
      uint8_t  bIscardPresent;      /**< State to save card presence */
      uint8_t  bIscardActive;       /**< State to save card activated or deactivated */
}phhalTda_DATAParams_t;

/**
 * TDA control pins mapped enums
 */
typedef enum
{
      eCMDVccn = 1,
      eRSTIN,
      eCLKDIV1,
      eCLKDIV2,
      e5V3VN,
      e1V8N,
      eCS,
      eCPresent,
      eCActive
}phhalTda_HCPins_t;
/* *****************************************************************************************************************
 * Extern Variables
 * *****************************************************************************************************************.*/

/* *****************************************************************************************************************
 * Function Prototypes
 * *****************************************************************************************************************.*/
/**
 * Initiates TDA control pins to its default state
 * @param     none
 *
 * @retval    #PH_ERR_SUCCESS        TDA pin configured
 */
phStatus16_t phhalTda_Init(void);

/**
 * TDA Cmd Vccn and Reset pins are sequentialised to make activate TDA and further card voltages
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @retval    #PH_ERR_SUCCESS      ACtivation sequence triggered
 */
phStatus16_t phhalTda_Activation( void * phhalCt_Params );

/**
 * TDA slot specific pins states are saved as default
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 * @param[in]  SlotNum           Slot number to selected as current transacting slot
 * @retval    none
 */
void phhalTda_SlotParamsInit( phhalTda_DATAParams_t * pTda_Params, phhalCt_SlotType_t Slot_type );

/**
 * Set a specific TDA pin context to its new changed state
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 * @param[in]  pin               TDA pin to be updated
 * @param[in]  state             new state to be set set/ clear
 *
 * @retval    none
 */
void phhalTda_SetContext( phhalTda_DATAParams_t * pTda_Params, phhalTda_HCPins_t pin, uint8_t state );

/**
 * Get a specific TDA pin context state
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 * @param[in]  pin               TDA pin state to be read
 * @param[out]  pstate            state returned as set/ clear
 *
 * @retval    none
 */
void phhalTda_GetContext( phhalTda_DATAParams_t * pTda_Params, phhalTda_HCPins_t pin, uint8_t * pstate );

/**
 * On every switching of slot, all respective TDA pin states has to be restored to its last pin state
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 *
 * @retval    none
 */
void phhalTda_RestoreContext(phhalTda_DATAParams_t * pTda_Params);

/**
 * returns selected slot/ TDA card activation state
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 *
 * @retval    low
 * @retval    high
 */
uint8_t phhalTda_CheckCardActive(phhalTda_DATAParams_t * pTda_Params);

/**
 * returns selected slot/ TDA card presence state
 * @param[in/out] pTda_Params    HAL slot specific context structure pointer
 *
 * @retval    low
 * @retval    high
 */
uint8_t phhalTda_CheckCardPres(phhalTda_DATAParams_t * pTda_Params);

/**
 * Selects and set combination of 5V3 & 1V8 pins to provide respective class voltage
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[in]  bVccSel           Voltage 5V, 3.3V, 1.8V or class A, B, C type
 *
 * @retval    none
 */
void phhalTda_SelectClassVcc( void * phhalCt_Params, uint8_t bVccSel );

#endif /* SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_TDA_H_ */

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */
