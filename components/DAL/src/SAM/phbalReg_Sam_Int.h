/*----------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                         */
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
* SAM (Secure Access Module) internal implementation for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHBALREG_SAM_INT_H
#define PHBALREG_SAM_INT_H

#include <ph_Status.h>
#ifdef NXPBUILD__PHBAL_REG_SAM

#define PHBAL_SAM_INVALID                       0xFFU

#ifdef _WIN32

#define PHBAL_SAM_COMM_TYPE_TDA                 0x80U
#define PHBAL_SAM_COMM_TYPE_I2C                 0x60U

#define PHBAL_SAM_CMD_READER_OPERATION          0xA0U
#define PHBAL_SAM_CONFIG_RD_OPS_SET_PCSC_MODE   0x0DU   /**< PCSC mode: Standard (0x00) or Direct (0x01). Only applicable for Pegoda 2 reader. */

#define PHBAL_SAM_CMD_ACTIVATE                  0x01U
#define PHBAL_SAM_CMD_COLD_RESET                0x02U
#define PHBAL_SAM_CMD_DEACTIVATE                0x06U
#define PHBAL_SAM_CMD_TRANSMIT_DATA             0x08U
#define PHBAL_SAM_CMD_SEND_PPS                  0x09U

#define PHBAL_SAM_CMD_CONFIGURATION             0xB0U
#define PHBAL_SAM_CONFIGURATION_SET             0x03U
#define PHBAL_SAM_CONFIGURATION_GET             0x04U

#define PHBAL_SAM_CMD_I2C_TRANSMIT_DATA         0x02U

#define PHBAL_SAM_FRAME_HEADER_LEN                 6U   /**< Length of a command header. */
#define PHBAL_SAM_FRAME_CMD_POS                    0U   /**< Position of the command code (ushort). */
#define PHBAL_SAM_FRAME_STATUS_POS                 2U   /**< Position of the status (ushort). */
#define PHBAL_SAM_FRAME_LEN_POS                    4U   /**< Position of the length (ushort). */
#define PHBAL_SAM_FRAME_PAYLOAD_POS                6U   /**< Position of the payload. */

phStatus_t phbalReg_Sam_Int_Exchange(phbalReg_Sam_DataParams_t * pDataParams, uint8_t bCommType, uint8_t bCmd, uint8_t * pData,
    uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phbalReg_Sam_Int_CheckResponse(uint16_t wCmd, uint8_t * pRxBuffer, uint16_t wRxBuffLen, uint8_t ** ppData,
    uint16_t * pDataLen);

phStatus_t phbalReg_Sam_Int_ParseAtr(uint8_t * pAtr, uint16_t wAtrLen, uint8_t * pTa1, uint8_t * pSpecificMode);

#endif /* _WIN32 */
#endif /* NXPBUILD__PHBAL_REG_SAM */

#endif /* PHBALREG_SAM_INT_H */
