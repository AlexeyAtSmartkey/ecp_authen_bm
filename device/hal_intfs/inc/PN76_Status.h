/*----------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                    */
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
 * Implementation of interface functions for non-secure code execution
 * $Author: $
 * $Revision: $ (02.02.00)
 *
 * History:
 *
 */

#ifndef _PN76_STATUS_H_
#define _PN76_STATUS_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "ph_Registers.h"

/** @addtogroup CommonError Common Error Codes
*
* @brief Common Error Codes
*
* @{
*/

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************************************************************/
/*   GLOBAL DEFINES                                                                                                  */
/*********************************************************************************************************************/

/*! @brief Common Error Codes. */
typedef enum PN76_Status_e
{
    PN76_STATUS_SUCCESS                      = 0x00, /**< Returned in case of no error. */
    PN76_STATUS_TIMEOUT                      = 0x01, /**< No reply received. */
    PN76_STATUS_BUFFER_OVERFLOW              = 0x04, /**< Buffer Overflow error. */
    PN76_STATUS_AUTH_ERROR                   = 0x07, /**< Authentication error. */
    PN76_STATUS_MEMORY_ERROR                 = 0x08, /**< Wrong EEPROM Read/Write . */
	PN76_STATUS_UNSUPPORTED                  = 0x09, /**< Invalid memory area accessed. */
    PN76_STATUS_NO_RF_FIELD                  = 0x0A, /**< NO/Error in internal RF */
    PN76_STATUS_CRC_ERROR                    = 0x0B, /**< CRC check failed. */
    PN76_STATUS_RESOURCE_ERROR               = 0x0D, /**< An resource error. */
    PN76_STATUS_EXTERNAL_FIELD               = 0x10, /**< External RF present/ERROR */
    PN76_STATUS_USER_CANCELLED               = 0x12,
    PN76_STATUS_PARAMETER_ERROR              = 0x14, /**< Value to be returned in case of wrong parameter. */

    PN76_STATUS_PLL_ERROR                    = 0x15, /**< The PLL did not start */
    PN76_STATUS_RECOVERY_ERROR               = 0x16, /**< Unable to recover from an ERROR, example memory error. */
    PN76_STATUS_PRNG_CHISQUARE_ERROR         = 0x17, /**< Error from RNG when RNR is compromised */
    PN76_STATUS_TXLDO_ERROR                  = 0x1C, /**< TXLDO Error */
    PN76_STATUS_NO_LOADRF_CFGS               = 0x1D, /**< Error in case RF ON is triggered w/o applying proper Load Rf configurations */
    PN76_STATUS_GPADC_ERROR                  = 0x1E, /**< GPADC Error during GPADC Initialization procedure */

    PN76_STATUS_HIF_TX_ONGOING                = 0x20, /**< Previous transmission is still ongoing */
    PN76_STATUS_HIF_RX_ONGOING                = 0x21, /**< Reception is ongoing */
    PN76_STATUS_HIF_TX_BUFFER_LOCKED          = 0x22, /**< TX Buffer is locked by the H/w */
    PN76_STATUS_HIF_RX_BUFFER_LOCKED          = 0x23, /**< RX Buffer is locked by the H/w */
    PN76_STATUS_HIF_TX_PREFETCH_FAILED        = 0x24, /**< Prefetch Failed while initiating transmission */
    PN76_STATUS_HIF_RX_BUFFER_ALREADY_ENABLED = 0x25, /**< RX Buffer is already enabled */
    PN76_STATUS_HIF_RX_BUFFER_OVERFLOWED      = 0x26, /**< RX Buffer Overflow */
    PN76_STATUS_HIF_RX_BUFFER_NOTAVAILABLE    = 0x27, /**< RX Buffers not available, when datawas received from Host */
    PN76_STATUS_COMM_ERROR                    = 0x28, /**< Generic erroneous frames, physical channel/bus errors */

    PN76_STATUS_INTERNAL_ERROR               = 0x7F, /**< Value to be returned in case of an internal error or
                                                          an error which is not specified in more detail. */

    PN76_STATUS_BUSY                         = 0xBC, /**< Device or resource busy. */

    PN76_STATUS_SKM_BUSY                     = 0xA8,    /**< SKM is busy or internal error */
    PN76_STATUS_SKM_PARAMETER_ERROR          = 0xA9,    /**< Invalid parameters provided */

    PN76_STATUS_SKM_SKTU_ERROR               = 0xB0,    /**< Internal SKTU error */
    PN76_STATUS_SKM_SKTU_AUTH_ERROR          = 0xB7,    /**< Authentication error */
    
    PN76_STATUS_SKM_LOCKED                   = 0xE0,    /**< SKM is locked */
    PN76_STATUS_SKM_SESSION_NOT_OPEN         = 0xE1,    /**< SKM Session is not open for provisioning of keys */
    PN76_STATUS_SKM_KEY_ERROR                = 0xE2,    /**< Key is either already provisioned or not present */
    PN76_STATUS_SKM_APP_ROOT_KEY_LOCKED      = 0xE3,    /**< Provisioning of APP_ROOT_KEY is locked  */
    PN76_STATUS_SKM_NOT_INITIALIZED          = 0xE4,    /**< SKM is not initialized */
    PN76_STATUS_SKM_INTEGRITY_ERROR          = 0xE5,    /**< SKM Key configuration integrity error */
    PN76_STATUS_SKM_ASYMM_HW_ACC_ERROR       = 0xE6,    /**< Asymmetric key HW acceleration error */
    PN76_STATUS_SKM_DP_NOT_SET               = 0xE7,    /**< Domain parameters are not set */
    PN76_STATUS_SKM_APP_ROOT_KEY_PROVISION   = 0xE8,    /**< APP_ROOT_KEY provision error */
    PN76_STATUS_NO_TAG_DETECTED              = 0xF1,    /**< Tag NOT detected during ULPCD */
    PN76_STATUS_TAG_DETECTED                 = 0xF2,    /**< Tag detected during ULPCD */

    PN76_STATUS_LOW_POWER_ENTRY_PREVENTED    = 0xF3,    /**< Entry into Low power is prevented. */
    PN76_STATUS_FAILED                       = 0xFE,    /**< Returned in case of ERROR. */
    PN76_STATUS_MODEL_ID_UNDETERMINED        = 0xFF,    /**< Model ID of the PN76xx IC is undetermined. */

    PN76_STATUS_STARTED                      = 0xFA,    /**< If Autocoll is already running . */

} PN76_Status_t;

/** \name Status error check macros
 * @{
 */
/**
 * Macro which checks a given status against #PN76_STATUS_SUCCESS. If the status is not equal to #PN76_STATUS_SUCCESS then
 * the current function is left with the given status code as return value.
 */
#define STATUS_CHECK_SUCCESS(status)         do {if ((status) != PN76_STATUS_SUCCESS) {return (status);}} while (0)
/**
 * Macro which executes a function and checks the return value against #PN76_STATUS_SUCCESS. If the calling function does not
 * return #PN76_STATUS_SUCCESS then the caller is also left with the callee's status code as return value.
 */
#define STATUS_CHECK_SUCCESS_FCT(status,fct) do {(status) = (fct); STATUS_CHECK_SUCCESS(status);} while (0)
/**
 * @}
 */

/*********************************************************************************************************************/
/*   GLOBAL FUNCTION PROTOTYPES                                                                                      */
/*********************************************************************************************************************/


#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_STATUS_H_ */


