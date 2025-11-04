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


/** @file
 *
 * Implementation of CHIP INFO HAL interface functions.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_CHIPINFO_H_
#define _PN76_CHIPINFO_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/** @addtogroup PN76SYSHALChipInfo
 *
 * @brief Chip Info HAL APIs
 *
 * This module implements PN76SYSHALChipInfo interface, specific to Chip Info module.
 *
 * @{
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/*!
 * @brief PN76XX Version information.
 */
typedef struct
{
    uint8_t bHw_Version;                              /**< Hardware version of PN76XX. */
    uint8_t bROM_Version;                             /**< ROM version of PN76XX. */
    uint16_t wFW_Version;                             /**< Firmware version of PN76XX.
                                                           |Bits  | Values   |     Description
                                                           |------|: -------:| :--------------------------------------------------------------
                                                           |[15:8]|          | Consists of FW version Major number
                                                           |[7:0] |          | Consists of FW version Minor number

                                                         */
}phhalHw_Pn76xx_Version_t;

/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/

/*!
 * @brief This instruction retrieves the DieID of the PN76XX CHIP.
 *
 * Buffer size of 16 bytes shall by provided by the user
 * to read DieId information.
 *
 * @param   *pDie_Id   Pointer to uint8_t to store the DieID of the PN76xx IC. The DieId would be 16-bytes.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 */
PN76_Status_t PN76_Sys_GetDieid(
            uint8_t * pDie_Id                                            /**< Die ID of PN76XX. */
            );

/*!
 * @brief This instruction retrieves Hw Version, ROM Version and FW version. 
 *
 * Buffer of size N + 1 bytes shall be provided by the user,
 * where N is the number of byte required for version information.
 *
 * @param   *sVersion   Pointer to \ref phhalHw_Pn76xx_Version_t to store the version information of HW/ROM/FW.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR Authentication Error.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 */
PN76_Status_t PN76_Sys_GetVersion(
            phhalHw_Pn76xx_Version_t * sVersion                          /**< Structure pointer to get 4 byte Version Information from PN76XX. */
            );

/*!
 * @brief This API will return the part id of the PN76xx IC.
 * Data sheet refers to the mapping of the return values of this API to corresponding part id of PN76xx IC.
 *
 * @param   *pPart_Id   Pointer to uint8_t to store the part id of the PN76xx IC.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 *
 * @note    Below table specifices the mapping of the part Id value return v/s PN76xx IC part number.
 *
              | *pPart_Id value | PN76xx part number
              |----------------:| :--------------------
              |0x00             | PN7642EV/C100
			  |0x01             | PN7642EV/C101
 *
 */
PN76_Status_t PN76_Sys_GetPartId(
            uint8_t * pPart_Id                                            /**< Part ID of PN76XX. */
            );


#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _PN76_CHIPINFO_H_ */


