/*----------------------------------------------------------------------------*/
/* Copyright 2009-2014, 2024 NXP                                              */
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
* Sam NonX MIFARE(R) Ultralight Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/

#ifndef PHALMFUL_SAM_NON_X_INT_H
#define PHALMFUL_SAM_NON_X_INT_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFUL_SAM_NONX

phStatus_t phhalHw_Sam_Cmd_SAM_KillAuthentication(void * pDataParams, uint8_t bOption);

phStatus_t phalMful_Sam_NonX_Int_UlcAuthenticate_Part1(void * pDataParams, uint8_t bOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pCardResponse, uint8_t bCardRespLen, uint8_t ** ppSamResponse,
    uint16_t * pSamRespLen);

phStatus_t phalMful_Sam_NonX_Int_UlcAuthenticate_Part2(void * pDataParams, uint8_t * pCardResponse, uint8_t bCardRespLen);

phStatus_t phalMful_Sam_NonX_Int_PwdAuth_Part1(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pDivInput,
    uint8_t bDivInputLen, uint8_t ** ppPwd, uint16_t * pPwdLen);

phStatus_t phalMful_Sam_NonX_Int_PwdAuth_Part2(void * pDataParams, uint8_t * pPack);

#endif /* NXPBUILD__PHAL_MFUL_SAM_NONX */

#endif /* PHALMFUL_SAM_NON_X_INT_H */
