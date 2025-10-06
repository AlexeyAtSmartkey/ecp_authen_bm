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
 * Project specific configuration.
 * $Author: NXP $
 * $Revision: $
 * $Date: $
 *
 */

#ifndef PH_CONFIG_H
#define PH_CONFIG_H

/* Place configuration switches, which overrides values from phDefaultConfig.h, here. */
#if defined(PHFL_BUILD_TYPE_DEBUG)
#define PHFL_CONFIG_DEBUG_PRINT 1
//#define PHFL_LOG_HOST 1
#endif
#ifndef PHFL_CONFIG_ENABLE_ASSERTIONS
#define PHFL_CONFIG_ENABLE_ASSERTIONS 1
#endif
#ifndef PHFL_CONFIG_ENABLE_ASSERTIONS_DEBUG
#ifndef __QAC__
#define PHFL_CONFIG_ENABLE_ASSERTIONS_DEBUG 0
#else
#define PHFL_CONFIG_ENABLE_ASSERTIONS_DEBUG 1
#endif
#endif

/* To configure the selected variant, do make configure-variant */
#ifdef TB_TOP_INCLUDE
/* TB */
#include "tb_variant.h"
#else
/* FW */
//#include "variant_selected.h"

#endif /* TB_TOP_INCLUDE */

/* finally, include default configuration. */
#include "ph_DefaultConfig.h"

#endif /* PH_CONFIG_H */
