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
 * Implementation of EEPROM interface functions.
 *
 * $Author: $
 * $Revision: $ (01.01.00)
 *
 */

#ifndef _PN76_EEPROM_H_
#define _PN76_EEPROM_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/** @addtogroup PN76SYSHALEeprom
 *
 * @brief Provides the interfaces to configure user configuration settings in IC as well as protocol area.
 *
 * This module implements the interfaces to configure user configuration settings in IC as well as protocol area.
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
/** @brief This enum contains the different areas in EEPROM to configure the user configuration settings. */
typedef enum PN76_EEPROM_Config_Enum
{
   E_PN76_EEPROM_USER_AREA = 0,           /**< User Area */
   E_PN76_EEPROM_SECURE_LIB_CONFIG,       /**< User Configurable Settings Region */
   E_PN76_EEPROM_IC_CONFIG                /**< IC Configurations */
} PN76_EEPROM_Config_t;

/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/


/*!
 * @brief Write values sequentially to E2PROM.
 *
 * This function is used to write one or more values to E2PROM.
 * \p pDataToWrite shall contain the data to be written to E2PROM starting at
 * the address \p wE2PromAddress. The data is written in sequential order.
 *
 * @param pDataToWrite Pointer to address of Data to be written.
 * @param wE2PromAddress Start address within E2PROM.
 * @param wDataLength Number of bytes to be written.
 * @eConfig Region to be Written. \ref PN76_EEPROM_Config_t
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
 */
PN76_Status_t PN76_WriteEeprom(
     uint8_t * pDataToWrite,
     uint16_t wE2PromAddress,
     uint16_t wDataLength,
     PN76_EEPROM_Config_t eConfig
);

/*!
 * @brief Write values sequentially to E2PROM UserArea and Protocol Area.
 *
 * This function is used to write one or more values to E2PROM.
 * \p pDataToWrite shall contain the data to be written to E2PROM starting at
 * the address \p wE2PromAddress. The data is written in sequential order.
 *
 * @param pDataToWrite Pointer to address of Data to be written.
 * @param wE2PromAddress Start address within E2PROM.
 * @param wDataLength Number of bytes to be written.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
 */
PN76_Status_t PN76_WriteEeprom_ProtocolUserArea(
            uint8_t * pDataToWrite,
            uint16_t  wE2PromAddress,
            uint16_t wDataLength
);

/*!
 * @brief Read values sequentially to E2PROM.
 *
 * This function is used to read one or more values from E2PROM.
 * \p pReadData shall contain the data that is read from E2PROM Address starting at
 * the address \p wE2PromAddress. The data is read in sequential order.
 *
 * @param pReadData Pointer to address where read Data will be stored.
 * @param wE2PromAddress Start address within E2PROM.
 * @param wDataLength Number of bytes to be read.
 * @eConfig Region to be Read. \ref PN76_EEPROM_Config_t
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pReadData is incorrect.
 */
PN76_Status_t PN76_ReadEeprom(
         uint8_t * pReadData,
         uint16_t wE2PromAddress,
         uint16_t wDataLength,
         PN76_EEPROM_Config_t eConfig
);

/*!
 * @brief Read values sequentially from E2PROM Protocol and User Area.
 *
 * This function is used to read one or more values from E2PROM.
 * \p pReadData shall contain the data that is read from E2PROM Address starting at
 * the address \p wE2PromAddress. The data is read in sequential order.
 *
 * @param pReadData Pointer to address where read Data will be stored.
 * @param wE2PromAddress Start address within E2PROM.
 * @param wDataLength Number of bytes to be written.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pReadData is incorrect.
 */
PN76_Status_t PN76_ReadEeprom_ProtocolUserArea(
            uint8_t * pReadData,
            uint16_t wE2PromAddress,
            uint16_t wDataLength
);


/*!
 * @brief Write values sequentially to E2PROM.
 *
 * This function is used to Check Integrity of the EEPROM region.
 * @note Integrity check for USER_AREA always returns a SUCCESS, since USER Area has no CRC.
 *
 * @eConfig Region Integrity to be checked. The regions can be found in the enum \ref PN76_EEPROM_Config_t
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM region is provided.
 * @retval PN76_STATUS_CRC_ERROR. Integrity check of the EEPROM region failed
 */
PN76_Status_t PN76_Eeprom_CheckIntegrity(PN76_EEPROM_Config_t eRegion);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _PN76_EEPROM_H_ */
