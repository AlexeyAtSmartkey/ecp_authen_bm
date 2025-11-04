/*----------------------------------------------------------------------------*/
/* Copyright 2014-2024  NXP                                                   */
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
 *
 * This file contains the implementation of T=0 protocol.
 *
 * $Date$
 * $Author$
 * $Revision$
 *
 */

#ifndef PHPALCT_T0_H
#define PHPALCT_T0_H

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */

/* ******************************************************************************************************************
 * Global Defines
 * ****************************************************************************************************************** */
/**
 * Macro for Class Byte in T=0 protocol header.
 */
#define PHPAL_CT_CLASS      0x00
/**
 * Macro for INS Byte in T=0 protocol header.
 */
#define PHPAL_CT_INS        0x01
/**
 * Macro for P1 Byte in T=0 protocol header.
 */
#define PHPAL_CT_P1         0x02
/**
 * Macro for P2 Byte in T=0 protocol header.
 */
#define PHPAL_CT_P2         0x03
/**
 * Macro for P3 Byte in T=0 protocol header.
 */
#define PHPAL_CT_P3         0x04
/**
 * Macro for maximum length INF.
 */
#define PHPAL_CT_MAX_LENGTH 256

/* ******************************************************************************************************************
 * Type Definitions
 * ****************************************************************************************************************** */

/* *******************************************************************************************************************
 * Extern Variables
 * ****************************************************************************************************************** */

/* *******************************************************************************************************************
 * Function Prototypes
 * ****************************************************************************************************************** */
phStatus16_t phpalCt_T0_Init( phpalCt_DATAParams_t * phpalCt_DATAParams );

/**
 * @brief This function transmits the Apdu in T=0 protocol and returns the response to the application.
 * @note  Pal transceive api calls this Api internally after selecting T=0 protocol.
 *
 * @param pbTransmitBuff(in) - Pointer to the transmit buffer
 * @param dwTransmitSize(in) - Size of the bytes to be transmitted
 * @param pbReceiveBuff(out) - Pointer to the receive buffer
 * @param dwReceiveSize(out) - Pointer to the receive buffer size
 * @return
 */
phStatus16_t phpalCt_T0_Transcieve( phpalCt_DATAParams_t * phpalCt_DATAParams,
								  uint8_t* pbTransmitBuff,
								  uint32_t dwTransmitSize,
								  uint8_t* pbReceiveBuff,
								  uint16_t* pwReceiveSize );

//#endif /* NXPBUILD__PHPAL_CT */

#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
#endif /* PHPALCT_T0_H */
