/*----------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                    */
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
 * Implementation of System Service Register Interface functions.
 *
 * $Author: $
 * $Revision: $ (01.01.00)
 *
 */

#ifndef _PN76_REG_INTERFACES_H_
#define _PN76_REG_INTERFACES_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"


/** @addtogroup PN76SYSRegInterfaces
 *
 * @brief System Service Register Interface to work with PN76XX Software Registers.
 *
 * @{
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************************************************************/
/*   GLOBAL DEFINES                                                                                                  */
/*********************************************************************************************************************/

/*! @brief Write Register Multiple Type. */
typedef enum PN76_WriteMultiple_RegType{
    PN76_WRITE_REG          = 1U,               /**< Time in microseconds (us).*/
    PN76_WRITE_REG_OR_MASK  = 2U,               /**< Time in milliseconds (ms).*/
    PN76_WRITE_REG_AND_MASK = 3U                /**< Time in milliseconds (ms).*/
}PN76_WriteMultiple_RegType_t;

/*! @brief Write Register Multiple data format. */
typedef struct __attribute__ ((__packed__))
{
   uint32_t dwRegVal;                           /**< Value to be updated in the register */
   uint16_t wRegAddr;                           /**< Address of the register */
   uint16_t wtype;                              /**< Write Reg type \ref PN76_WriteMultiple_RegType_t */
} PN76_RegIntf_t;

/*********************************************************************************************************************/
/*   GLOBAL FUNCTION PROTOTYPES                                                                                      */
/*********************************************************************************************************************/

/*!
 * @brief Write a 32 bit value (little endian) to a logical register.
 *
 * @param wRegister Address of the logical register.
 * @param dwValue 32 Bit register value which has to be written.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
 */
PN76_Status_t PN76_Sys_WriteRegister(
    uint16_t  wRegister,
    uint32_t dwValue);

/*!
 * @brief Perform a logical OR operation on a register using provided mask.
 *
 * This function is used to modify the content of register using a logical OR
 * operation. The content of the register is read and a logical OR operation
 * is performed with the provided mask. The modified content is written back
 * to the register.
 *
 * @param wRegister Address of the logical register.
 * @param dwMask Bit-mask used as operand for logical OR operation.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
 */
PN76_Status_t PN76_Sys_WriteRegisterOrMask(
    uint16_t  wRegister,
    uint32_t dwMask
    );

/*!
 * @brief Perform a logical AND operation on a register using provided mask.
 *
 * This function is used to modify the content of register using a logical
 * AND operation. The content of the register is read and a logical AND
 * operation is performed with the provided mask. The modified content is
 * written back to the register.
 *
 * @param wRegister Address of the logical register.
 * @param dwMask Bit-mask used as operand for logical AND operation.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
 */
PN76_Status_t PN76_Sys_WriteRegisterAndMask(
    uint16_t  wRegister,
    uint32_t dwMask
    );

/*!
 * @brief Perform a normal/logical Write operation on one or more registers.
 *
 * This function is used to modify the content of register using normal/logical
 * WRITE operation on one or more registers.
 *
 * @param psaRegSet Structure to write to MULTIPLE register.
 * @param wNumOfRegSets Number of Write Register sets.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
 */
PN76_Status_t PN76_Sys_WriteRegisterMultiple(
    PN76_RegIntf_t  *psaRegSet,
    uint16_t wNumOfRegSets
    );
/*!
* @brief Perform a Read operation on one or more registers.
*
* @param pRegisterSet Set of Registers to Read.
* @param pValue Pointer to a 32 bit variable, where the result (value of the read out register) shall be written.
* @param bNumOfRegs Number of Registers to perform Read.
*
* @retval PN76_STATUS_SUCCESS Operation Successful.
* @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
*/
PN76_Status_t PN76_Sys_ReadRegisterMultiple(
    uint16_t *pRegisterSet,
    uint8_t *pValue,
    uint8_t bNumOfRegs
    );

/*!
 * @brief Read back the content of a logical register.
 *
 * This function is used to read back the content of a logical register whose
 * address is given by \p wRegister.
 * The content is available in output parameter \p pValue.
 *
 * @param wRegister Address of the logical register.
 *
 * @retval Register contents for Operation Successful.
 * @retval 0xABBADEADUL for unknown register address.
 */
uint32_t PN76_Sys_ReadRegister(uint16_t  wRegister);

/*!
 * @brief Perform a write operation on a register to specific field using provided mask.
 *
 * This function is used to modify the content of register using Mask value.
 * The content of the register is read and a specific field is set, this
 * operation is performed with the provided mask. The modified content is
 * written back to the register.
 *
 * @param wRegister Address of the logical register.
 * @param dwMask Bit-mask if the register field to be written.
 * @param dwValue  Value to be written in the mask location.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Unknown register address.
 */
PN76_Status_t PN76_Sys_WriteRegisterField(
    uint16_t wRegister,
    uint32_t dwMask,
    uint32_t dwValue
    );


/**
 * \brief Create a boolean for testing
 * !(!(0)) -> !(TRUE) -> FALSE
 * !(!(non zero)) -> !(FALSE) -> TRUE
 */
#define PN76_HALREG_BOOL(x) (!(!(x)))

/**
 * \brief Read a 32 bit value from the HW register
 */
#define PN76_HALREG_GET_REG(REG)                     (PN76_Sys_ReadRegister(REG##_R))

/**
 * \brief Write a 32 bit value to the HW register
 */
#define PN76_HALREG_SET_REG(REG, regValue)           (PN76_Sys_WriteRegister(REG##_W, regValue))

/**
 *  \brief Perform a logical OR operation on a register using provided mask.
 */
#define PN76_HALREG_SET_REG_OR_MASK(REG, dwMask)     (PN76_Sys_WriteRegisterOrMask((REG##_W | REG##_R), dwMask))

/**
 * \brief Perform a logical AND operation on a register using provided mask.
 */
#define PN76_HALREG_SET_REG_AND_MASK(REG, dwMask)    (PN76_Sys_WriteRegisterAndMask((REG##_W | REG##_R), dwMask))

/**
 * \brief Perform a write operation on a register to specific field using provided mask.
 */
#define PN76_HALREG_SET_FIELD(REG, dwMask, dwValue)  (PN76_Sys_WriteRegisterField((REG##_W | REG##_R), dwMask, dwValue))

/**
 * \brief  Read a register and mask the requested fields
 */
#define PN76_HALREG_GETFIELD(REG, regMask)           ((PN76_HALREG_GET_REG(REG)) & ((uint32_t)(regMask)) )

/**
 * \brief Read a register and mask the requested fields then shift to lsb
 */
#define PN76_HALREG_GETFIELDSHIFT(REG, regMask, bitPos) ( ( (PN76_HALREG_GET_REG(REG)) & ((uint32_t)(regMask)) ) >> (bitPos))

/**
 * \brief Test bit at bitPos : if 1 return TRUE else return FALSE
 */
#define PN76_HALREG_TESTBITN(REG, bitPos)             PN76_HALREG_BOOL((PN76_HALREG_GET_REG(REG)) & (1UL << (bit)))

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_REG_INTERFACES_H_ */
