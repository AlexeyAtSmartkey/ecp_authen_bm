/*----------------------------------------------------------------------------*/
/* Copyright 2016-2022 NXP                                                    */
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
 * Registers access.
 * $Author: NXP $
 * $Revision: $ (01.01.00)
 * $Date: $
 *
 */

#ifndef PH_REGISTERS_H
#define PH_REGISTERS_H

/** \defgroup phRegisters Registers access.
 * \ingroup types
 * \brief Contains various macros to read/write HW 32 bits registers.
 *
 *
 * @{
 */

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/
#include "ph_Datatypes.h"

/*********************************************************************************************************************/
/*   TOOLS                                                                                                           */
/*********************************************************************************************************************/
#ifndef __preg32_t_defined
#define __preg32_t_defined
/**
 * \brief Pointer to a 32 bits register
 */
typedef volatile uint32_t *pReg32_t;
#endif
/**
 * \brief Create a boolean for testing
 * !(!(0)) -> !(TRUE) -> FALSE
 * !(!(non zero)) -> !(FALSE) -> TRUE
 */
#define PH_HALREG_BOOL(x) (!(!(x)))

/**
 * \brief Bit position shift
 */
#define PH_HALREG_BITMSK(bit) (1UL << (bit))

/*********************************************************************************************************************/
/*   GLOBAL VARIABLES                                                                   */
/*********************************************************************************************************************/


/*********************************************************************************************************************/
/*   REGISTERS  MANIPULATION                                                                                         */
/*********************************************************************************************************************/
#if (PHFL_CONFIG_TARGET_PLATFORM == PHFL_CONFIG_TARGET_PLATFORM_ARM) || __QAC__
/**
 * \brief Read a 32 bit value from the HW register
 */
#define PH_HALREG_GETREG(regAddr) (*((pReg32_t)(regAddr)))

/**
 * \brief  Read a register and mask the requested fields
 */
#define PH_HALREG_GETFIELD(regAddr, regMask) ((PH_HALREG_GETREG(regAddr)) & ((uint32_t)(regMask)))

/**
 * \brief Read a register and mask the requested fields then shift to lsb
 */
#define PH_HALREG_GETFIELDSHIFT(regAddr, regMask, bitPos) \
    (((PH_HALREG_GETREG(regAddr)) & ((uint32_t)(regMask))) >> (bitPos))

/**
 * \brief Write a 32 bit value to the HW register
 */
#define PH_HALREG_SETREG(regAddr, regValue) ((PH_HALREG_GETREG(regAddr)) = ((uint32_t)(regValue)))

/**
 * \brief  Write a 32 bit value to the HW register and preserve out-of-field bits
 */
#define PH_HALREG_SETFIELD(regAddr, regMask, regValue)                                         \
    ((PH_HALREG_GETREG(regAddr)) = (((PH_HALREG_GETREG(regAddr)) & (~((uint32_t)(regMask)))) | \
                                    (((uint32_t)(regValue)) & ((uint32_t)(regMask)))))

/**
 * \brief  Write a 32 bit lsb positioned value to the HW register and preserve out-of-field bits
 */
#define PH_HALREG_SETFIELDSHIFT(regAddr, regMask, bitPos, regValue)                            \
    ((PH_HALREG_GETREG(regAddr)) = (((PH_HALREG_GETREG(regAddr)) & (~((uint32_t)(regMask)))) | \
                                    (((uint32_t)(regValue) << (bitPos)) & ((uint32_t)(regMask)))))

#define PH_HALREG_ANDREG(regAddr, regValue) ((PH_HALREG_GETREG(regAddr)) &= ((uint32_t)(regValue)))

#define PH_HALREG_ORREG(regAddr, regValue) ((PH_HALREG_GETREG(regAddr)) |= ((uint32_t)(regValue)))

/*********************************************************************************************************************/
/*   REGISTERS MANIPULATION AT A PROVIDED BIT POSITION                                                               */
/*********************************************************************************************************************/
/**
 * \brief Set bit at bitPos to 1
 */
#define PH_HALREG_SETBITN(regAddr, bitPos) ((PH_HALREG_GETREG(regAddr)) |= PH_HALREG_BITMSK(bitPos))

/**
 * \brief Clear bit at bitPos (set to 0)
 */
#define PH_HALREG_CLEARBITN(regAddr, bitPos) ((PH_HALREG_GETREG(regAddr)) &= ~PH_HALREG_BITMSK(bitPos))

/**
 * \brief Flip bit at bitPos
 */
#define PH_HALREG_FLIPBITN(regAddr, bitPos) ((PH_HALREG_GETREG(regAddr)) ^= PH_HALREG_BITMSK(bitPos))

/**
 * \brief Test bit at bitPos : if 1 return TRUE else return FALSE
 */
#define PH_HALREG_TESTBITN(regAddr, bitPos) PH_HALREG_BOOL((PH_HALREG_GETREG(regAddr)) & PH_HALREG_BITMSK(bitPos))
#else

#endif

/**
 * \brief These macros report the lowest bit position set
 * \note  ASSUMPTION is that at least one 1-bit is set.
 */
#define PH_HALREG_LWSTBITPOS2(value) (((value)&0x1) ? 0 : 1)
#define PH_HALREG_LWSTBITPOS4(value) \
    (((value)&0x3) ? PH_HALREG_LWSTBITPOS2(value) : (2 + PH_HALREG_LWSTBITPOS2(((value) >> 2))))
#define PH_HALREG_LWSTBITPOS8(value) \
    (((value)&0xF) ? PH_HALREG_LWSTBITPOS4(value) : (4 + PH_HALREG_LWSTBITPOS4(((value) >> 4))))
#define PH_HALREG_LWSTBITPOS16(value) \
    (((value)&0xFF) ? PH_HALREG_LWSTBITPOS8(value) : (8 + PH_HALREG_LWSTBITPOS8(((value) >> 8))))
#define PH_HALREG_LWSTBITPOS32(value) \
    (((value)&0xFFFF) ? PH_HALREG_LWSTBITPOS16(value) : (16 + PH_HALREG_LWSTBITPOS16(((value) >> 16))))

#endif /* PH_REGISTERS_H */
