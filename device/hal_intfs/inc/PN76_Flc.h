/*----------------------------------------------------------------------------*/
/* Copyright 2019-2022 NXP                                                    */
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
 * System Service In Application Programming Interfaces.
 *
 * $Author: $
 * $Revision: $
 * $Date: $
 *
 */

#ifndef _PN76_FLC_H_
#define _PN76_FLC_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup PN76SYSIapInterfaces
 *
 * @brief System Services for programming/Reading of Non-secure Flash area and for 
 * setting Code/Data area sizes for downloading through USB download.
 *
 * @{
 *
 */

/*********************************************************************************************************************/
/*   GLOBAL DEFINES                                                                                                  */
/*********************************************************************************************************************/

/*********************************************************************************************************************/
/*   GLOBAL FUNCTION PROTOTYPES                                                                                      */
/*********************************************************************************************************************/

/*!
 * @brief Programs the flash with given buffer and length provided.
 *
 * @details This interface will write to flash with the given buffer contents
 *          at the respective address provided.
 *
 * @param pBuffer Pointer to data buffer whose contents to be stored in flash
 * @param pFlash Pointer to the start address of flash location, from where flash to be programmed
 * @param wData_Length Length of the data buffer to be programmed into flash
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_PARAMETER_ERROR Invalid parameters provided
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
__TEXT(Flash2) PN76_Status_t PN76_Flc_WriteBuffer(
    uint8_t *pBuffer,
    uint8_t *pFlash,
    uint16_t wData_Length
    );

/*!
 * @brief Updates the given buffer with contents of flash till the length provided.
 *
 * @details This interface will read from flash and updates the given buffer contents.
 *
 * @param pBuffer Pointer to data buffer to read the flash content
 * @param pFlash Pointer to the start address of flash location to be read
 * @param wData_Length Length of the data buffer to be read from flash
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_PARAMETER_ERROR Invalid parameters provided
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Flc_ReadBuffer(
    uint8_t *pBuffer,
    uint8_t *pFlash,
    uint16_t wData_Length
    );

/*!
 * @brief Set the USB mass storage code/data area/file sizes.
 *
 * @details Make sure the code area and data area fits in USB storage size.
 * NOTE: Make sure code & data area are not overlapping.
 *
 * @param dwCodeAreaStartAddr Start Address of Code Area.
 * @param dwCodeAreaLength Length of Code Area.
 * @param dwDataAreaStartAddr Start Address of Data Area.
 * @param dwDataAreaLength Length of Data Area.
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_PARAMETER_ERROR Invalid parameters provided
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Usb_SetUsbStorageArea(
	uint32_t dwCodeAreaStartAddr,
	uint32_t dwCodeAreaLength,
	uint32_t dwDataAreaStartAddr,
	uint32_t dwDataAreaLength);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _PN76_FLC_H_ */


