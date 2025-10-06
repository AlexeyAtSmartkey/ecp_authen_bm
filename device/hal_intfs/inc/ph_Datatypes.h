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
 * Global data types.
 * $Author: NXP $
 * $Revision: $ (01.01.00)
 * $Date: $
 *
 */

#ifndef PH_DATATYPES_H
#define PH_DATATYPES_H

/** \defgroup phDatatypes Global data types
 * \ingroup types
 * \brief Contains definitions for portable data types used within this firmware.
 *
 * The data types defined here have to be used instead of standard C data types (e.g. int, char)
 * to allow easier portability of the firmware.
 * @{
 */

#include <ph_Config.h>
#ifndef PHFL_CONFIG_TARGET_PLATFORM
#error "Target Platfrom must be defined"
#endif
#ifndef PHFL_CONFIG_TARGET_PLATFORM_ARM_PN76XX
#error "Arm PN76XX must be defined"
#endif

#if (PHFL_CONFIG_TARGET_PLATFORM == PHFL_CONFIG_TARGET_PLATFORM_ARM)
#include <stdint.h>
#else

#ifndef __uint8_t_defined
#define __uint8_t_defined
/**
 * \brief 8 bit unsigned integer
 */
typedef unsigned char uint8_t;
#endif

#ifndef __uint16_t_defined
#define __uint16_t_defined
/**
 * \brief 16 bit unsigned integer
 */
typedef unsigned short uint16_t;
#endif

#ifndef __uint32_t_defined
#define __uint32_t_defined
/**
 * \brief 32 bit unsigned integer
 */
typedef unsigned long uint32_t;
#endif

#ifndef __uint64_t_defined
#define __uint64_t_defined
/**
 * \brief 64 bit unsigned integer
 */
typedef unsigned long long uint64_t;
#endif

#ifndef __int8_t_defined
#define __int8_t_defined
/**
 * \brief 8 bit signed integer
 */
typedef signed char int8_t;
#endif

#ifndef __int16_t_defined
#define __int16_t_defined
/**
 * \brief 16 bit signed integer
 */
typedef signed short int16_t;
#endif

#ifndef __int32_t_defined
#define __int32_t_defined
/**
 * \brief 32 bit signed integer
 */
typedef signed int int32_t;
#endif
#endif

#if !defined(__cplusplus)
#ifndef __BOOL_DEFINED
#define __BOOL_DEFINED 1
/**
 * \brief Boolean type
 */
#ifndef false
#define false 0
#endif
#ifndef true
#define true (!false)
#endif
#ifndef bool
typedef uint8_t bool;
#endif
#endif
#endif

#ifndef TRUE
#define TRUE true
#endif

#ifndef FALSE
#define FALSE false
#endif

#ifndef NULL
#define NULL ((void *)0) /**< Value used for NULL pointers */
#endif

#define BYTE_SIZE   0x08U
#define NIBBLE_MASK 0x0FU

#ifdef PHFL_ENABLE_STACK_CHECK
#define PH_CALL_DIRECT_FUNCTION(fct) (fct)
#else
#define PH_CALL_DIRECT_FUNCTION(fct)
#endif

#if (PHFL_CONFIG_TARGET_PLATFORM == PHFL_CONFIG_TARGET_PLATFORM_ARM) || defined(__DOXYGEN)
#define STRINGIFY(a) #a

#ifdef PHFL_CONFIG_TARGET_PLATFORM_ARM_PN76XX
#define PH_PACK_STRUCT_BEGIN
#define PH_PACK_STRUCT_END __attribute__((__packed__))

#define PH_ZI_DATA_SECTION(SECTIONNAME)                    \
    _Pragma(STRINGIFY(clang section data = #SECTIONNAME)); \
    _Pragma(STRINGIFY(clang section bss = #SECTIONNAME));

#define PH_PLACE_ZI_DATA_TO_SECTION(SECTIONNAME) __attribute__((section(STRINGIFY(.bss.SECTIONNAME))))

#define PH_RO_DATA_SECTION(SECTIONNAME) _Pragma(STRINGIFY(clang section rodata = #SECTIONNAME));

#define PH_CODE_SECTION(SECTIONNAME) _Pragma(STRINGIFY(clang section text = #SECTIONNAME));

#define PH_ALIGN(x) __attribute__((aligned(x)))
#define PH_USED     __attribute__((used))

#else
#define PH_PACK_STRUCT_BEGIN __packed
#define PH_PACK_STRUCT_END

#define PH_ZI_DATA_SECTION(SECTIONNAME)                    \
    _Pragma(STRINGIFY(arm section rwdata = #SECTIONNAME)); \
    _Pragma(STRINGIFY(arm section zidata = #SECTIONNAME));

#define PH_RO_DATA_SECTION(SECTIONNAME) _Pragma(STRINGIFY(arm section rodata = #SECTIONNAME));

#define PH_CODE_SECTION(SECTIONNAME) _Pragma(STRINGIFY(arm section code = #SECTIONNAME));

#define PH_PLACE_ZI_DATA_TO_SECTION(SECTIONNAME) __attribute__((section(SECTIONNAME), zero_init))

#define PH_ALIGN __align
#define PH_USED  __attribute__((used))
#endif /* #ifdef PHFL_CONFIG_TARGET_PLATFORM_ARM_PN76XX */

/**
 * \brief Macro used to place given variable as ZI-data to specified section.
 * \note The section need to be defined in the scatter file.
 * Example:
 * \code
static uint32_t aBmaBuffer[PH_BOOT_BMA_BUFFER_SIZE] PH_PLACE_ZI_DATA_TO_SECTION("BMA");
\endcode
 */

/**
 * \brief Macro used to place constant data to specified section.
 * \note The section need to be defined in the scatter file.
 * Example:
 * \code
static const uint32_t dwFoo PH_PLACE_RO_DATA_TO_SECTION("FOO");
\endcode
 */
#define PH_PLACE_RO_DATA_TO_SECTION(SECTIONNAME)  __attribute__((section(SECTIONNAME)))
#define PH_PLACE_FUNCTION_TO_SECTION(SECTIONNAME) __attribute__((section(SECTIONNAME)))

#else
#ifdef __QAC__
#define PH_ZI_DATA_SECTION(SECTIONNAME) static void(SECTIONNAME)()
#define PH_RO_DATA_SECTION(SECTIONNAME) static void(SECTIONNAME)()
#define PH_CODE_SECTION(SECTIONNAME)    static void(SECTIONNAME)()
#else
#define PH_ZI_DATA_SECTION(SECTIONNAME)
#define PH_RO_DATA_SECTION(SECTIONNAME)
#define PH_CODE_SECTION(SECTIONNAME)
#endif
#define PH_PLACE_ZI_DATA_TO_SECTION(SECTIONNAME)
#define PH_PLACE_RO_DATA_TO_SECTION(SECTIONNAME)
#define PH_PLACE_FUNCTION_TO_SECTION(SECTIONNAME)
#define PH_ALIGN(a)
#define PH_USED
#define PH_PACK_STRUCT_BEGIN
#define PH_PACK_STRUCT_END __attribute__((__packed__))
#endif

#endif /* PH_DATATYPES_H */
