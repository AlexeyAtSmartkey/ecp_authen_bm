/*----------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                    */
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
 * Implementation of CRC HAL interface functions.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_CRC_H_
#define _PN76_CRC_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/** @addtogroup PN76SYSHALCRC
 *
 * @brief CRC HAL APIs
 *
 * This module implements PN76SYSHALCRC interface, specific to CRC module.
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

/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief This function initialize CRC interface part of the HAL..
 * Enables the clock for CRC Module.
 *
 * @retval Nothing.
 */
void PN76_Sys_Hal_CRC_Init(void);

/*!
 * @brief This function uninitialize CRC interface part of the HAL.
 * Disables the clock for CRC Module.
 *
 * @retval Nothing.
 */
void PN76_Sys_Hal_Crc_DeInit(void);


/*!
 * @brief This function calculate CRC32 or CRC16 on selected data area.
 *
 * This function is protected by semaphore.
 * Functions that are protected by semaphores must not be called in interrupts.
 * CRC will always calculate MSB first, this will be set internally
 *
 * @param dwCrcPreload : Value of pre-load DATA for CRC calculation
 * @param pBuffer :Pointer to data message structure on which CRC will be calculated.
 * @param dwDataLength : Length of \a pBuffer in bytes Note - Len must match with Buffer size.
 * @param pCrcValue : Pointer on calculated CRC value
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
 * @retval PN76_STATUS_BUSY
 * @retval PN76_STATUS_INTERNAL_ERROR
 */
PN76_Status_t PN76_Sys_Hal_CRC_CalculateCrc32(
            uint32_t dwCrcPreload,
            uint8_t *pBuffer,
            uint32_t dwDataLength,
            uint32_t *pCrcValue );
/*!
* @brief This function check CRC16 calculation on buffer with calculated CRC value.
* \note It is assumed that CRC16 result is part of the buffer (usually last two bytes, after data on which CRC is calculated )
* \note Function is protected by semaphore
* \note Functions that are protected by semaphores must not be called in interrupts
* \note CRC will always calculate MSB first, this will be set internally
* @param wCrcPreload : Value of pre-load DATA for CRC calculation
* @param pBuffer :Pointer to data message structure on which CRC will be calculated.
* @param dwDataLength : Length of \a pBuffer in bytes Note - Len must match with Buffer size.
* @retval PN76_STATUS_SUCCESS Operation Successful.
* @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
* @retval PN76_STATUS_BUSY
* @retval PN76_STATUS_INTERNAL_ERROR
*/
PN76_Status_t PN76_Sys_Hal_CRC_CheckCrc16( uint16_t wCrcPreload, uint8_t *pBuffer, uint32_t dwDataLength);

/*!
* @brief This function calculate CRC16 on selected FW buffer area.
* \note Function is protected by semaphore
* \note Functions that are protected by semaphores must not be called in interrupts
* \note CRC will always calculate lsb first and byte by byte, but pBuffer doesn't have to be aligned
* @param wCrcPreload : Value of pre-load DATA for CRC calculation
* @param pBuffer :Pointer to data message structure on which CRC will be calculated.
* @param dwDataLength : Length of \a pBuffer in bytes Note - Len must match with Buffer size.
* @param pCrcValue : Pointer on calculated CRC value
* @retval PN76_STATUS_SUCCESS Operation Successful.
* @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
* @retval PN76_STATUS_BUSY
* @retval PN76_STATUS_INTERNAL_ERROR
*/
PN76_Status_t PN76_Sys_Hal_CRC_CalculateHDLLCrc16( uint16_t wCrcPreload, uint8_t *pBuffer, uint32_t dwDataLength,
            uint16_t *pCrcValue );

/*!
* @brief This function check CRC16 calculation on incoming frame buffer with calculated CRC value.
* \note It is assumed that CRC16 result is part of the buffer (usually last two bytes, after data on which CRC is calculated )
* \note Function is protected by semaphore
* \note Functions that are protected by semaphores must not be called in interrupts
* \note CRC will always calculate lsb first and byte by byte, but pBuffer doesn't have to be aligned
* @param wCrcPreload : Value of pre-load DATA for CRC calculation
* @param pBuffer :Pointer to data message structure on which CRC will be calculated.
* @param dwDataLength : Length of \a pBuffer in bytes Note - Len must match with Buffer size.
* @retval PN76_STATUS_SUCCESS Operation Successful.
* @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
* @retval PN76_STATUS_BUSY
* @retval PN76_STATUS_INTERNAL_ERROR
*/
PN76_Status_t PN76_Sys_Hal_CRC_CheckHDLLCrc16( uint16_t wCrcPreload, uint8_t *pBuffer, uint32_t dwDataLength);

/*!
* @brief This function calculates the CRC on selected FW buffer area using the CRC HW.
* \note CRC will always calculate lsb first and byte by byte, but pBuffer doesn't have to be aligned
* @param pBuf :Pointer to data message structure on which CRC will be calculated.
* @param dwLen : Length of \a pBuffer in bytes Note - Len must match with Buffer size.
* @retval PN76_STATUS_SUCCESS Operation Successful.
* @retval PN76_STATUS_PARAMETER_ERROR Unknown EEPROM address or address pointed by \p pDataToWrite is incorrect.
* @retval PN76_STATUS_BUSY
* @retval PN76_STATUS_INTERNAL_ERROR
*/
PN76_Status_t PN76_Sys_Hal_CRC_Calc( uint8_t* pBuf, uint32_t dwLen );

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _PN76_CHIPINFO_H_ */


