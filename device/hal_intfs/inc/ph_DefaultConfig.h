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
 * Default global configuration. Do NOT modify this file. ph_Config.h shall be modified instead.
 * $Author: NXP $
 * $Revision: $ (01.01.00)
 * $Date: $
 *
 */

#ifndef PH_DEFAULTCONFIG_H
#define PH_DEFAULTCONFIG_H

#ifndef PHFL_CONFIG_SYSCLK
#define PHFL_CONFIG_SYSCLK 45000000UL
#endif

#define PHFL_CONFIG_TARGET_PLATFORM_ARM 1
#define PHFL_CONFIG_TARGET_PLATFORM_X86 2

#ifndef PHFL_CONFIG_TARGET_PLATFORM
#if defined(__GNUC__) || defined(__ARMCC_VERSION) || defined(__ICCARM__)
#define PHFL_CONFIG_TARGET_PLATFORM PHFL_CONFIG_TARGET_PLATFORM_ARM
#if defined(__GNUC__) || (__ARMCC_VERSION == 6090000) || defined(__ICCARM__)
#define PHFL_CONFIG_TARGET_PLATFORM_ARM_PN76XX
#endif
#else
#define PHFL_CONFIG_TARGET_PLATFORM PHFL_CONFIG_TARGET_PLATFORM_X86
#endif
#endif

#define PHFL_CONFIG_MODE_MODULETESTOS 1
#define PHFL_CONFIG_MODE_NORMAL       2
#define PHFL_CONFIG_MODE_DOWNLOAD     3
#define PHFL_CONFIG_MODE_TESTOS       4

#ifndef PHFL_CONFIG_MODE
#define PHFL_CONFIG_MODE PHFL_CONFIG_MODE_NORMAL
#endif

#ifndef PHFL_CONFIG_DEBUG_PRINT
#define PHFL_CONFIG_DEBUG_PRINT 0
#endif

#ifndef PHFL_CONFIG_ENABLE_ASSERTIONS
#define PHFL_CONFIG_ENABLE_ASSERTIONS 0
#endif

#ifndef PHFL_CONFIG_USE_HDLL
#define PHFL_CONFIG_USE_HDLL 0
#endif

#endif /* PH_DEFAULTCONFIG_H */
