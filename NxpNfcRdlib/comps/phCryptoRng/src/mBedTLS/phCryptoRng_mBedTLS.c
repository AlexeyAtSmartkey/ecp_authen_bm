/*----------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                         */
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
* mBedTLS specific Random Number Component of the Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 6617 $ (v07.10.00)
* $Date: 2022-05-03 22:06:54 +0530 (Tue, 03 May 2022) $
*
* History:
*  Generated 04. May 2022
*
*/

#include <stdlib.h>
#include <ph_Status.h>
#include <phCryptoRng.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_CRYPTORNG_MBEDTLS

#include "phCryptoRng_mBedTLS.h"

phStatus_t phCryptoRng_mBedTLS_Init(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t wSizeOfDataParams)
{
    if(sizeof(phCryptoRng_mBedTLS_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTORNG);
    }
    PH_ASSERT_NULL(pDataParams);

    /* Init. private data */
    pDataParams->wId = PH_COMP_CRYPTORNG | PH_CRYPTORNG_MBEDTLS_ID;
    pDataParams->dwErrorCode = 0;

#ifdef MBEDTLS_CTR_DRBG_C
    /* Initialize the context. */
    if(pDataParams->pCtx_Drbg == NULL)
    {
        pDataParams->pCtx_Drbg = (mbedtls_ctr_drbg_context *) malloc(sizeof(mbedtls_ctr_drbg_context));
        mbedtls_ctr_drbg_init(pDataParams->pCtx_Drbg);
    }

    if(pDataParams->pCtx_Entropy == NULL)
    {
        pDataParams->pCtx_Entropy = (mbedtls_entropy_context *) malloc(sizeof(mbedtls_entropy_context));
        mbedtls_entropy_init(pDataParams->pCtx_Entropy);
    }
#else
#ifdef NXPBUILD__PHHAL_HW_PN76XX
    PN76_Sys_Hal_RNG_Init();
#endif /* NXPBUILD__PHHAL_HW_PN76XX */
#endif /* MBEDTLS_CTR_DRBG_C */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_mBedTLS_DeInit(phCryptoRng_mBedTLS_DataParams_t * pDataParams)
{
#ifdef MBEDTLS_CTR_DRBG_C
    if(pDataParams->pCtx_Drbg != NULL)
    {
        mbedtls_ctr_drbg_free(pDataParams->pCtx_Drbg);
        pDataParams->pCtx_Drbg = NULL;
    }

    if(pDataParams->pCtx_Entropy != NULL)
    {
        mbedtls_entropy_free(pDataParams->pCtx_Entropy);
        pDataParams->pCtx_Entropy = NULL;
    }
#else
    PH_UNUSED_VARIABLE(pDataParams);
#endif /* MBEDTLS_CTR_DRBG_C */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_mBedTLS_Seed(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint8_t * pSeed, uint8_t bSeedLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

#ifdef MBEDTLS_CTR_DRBG_C
    TRY
    {
        PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_seed(pDataParams->pCtx_Drbg, mbedtls_entropy_func, pDataParams->pCtx_Entropy,
            pSeed, bSeedLen));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT
#else
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(pSeed);
    PH_UNUSED_VARIABLE(bSeedLen);
#endif /* MBEDTLS_CTR_DRBG_C */

    return wStatus;
}

phStatus_t phCryptoRng_mBedTLS_Rnd(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t  wNoOfRndBytes, uint8_t * pRnd)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

#ifdef MBEDTLS_CTR_DRBG_C
    TRY
    {
        PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_random(pDataParams->pCtx_Drbg, pRnd, wNoOfRndBytes));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT
#else
#ifdef NXPBUILD__PHHAL_HW_PN76XX
    PH_CHECK_SUCCESS_FCT(wStatus, PN76_Sys_Hal_RNG_GenerateSecureRng(pRnd, wNoOfRndBytes));
#endif /* NXPBUILD__PHHAL_HW_PN76XX */
    PH_UNUSED_VARIABLE(pDataParams);
#endif /* MBEDTLS_CTR_DRBG_C */

    return wStatus;
}

phStatus_t phCryptoRng_mBedTLS_GetLastStatus(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode)
{
    *pStatusCode = pDataParams->dwErrorCode;

#ifdef MBEDTLS_ERROR_C
#ifndef NXPBUILD__PHHAL_HW_PN76XX
    mbedtls_strerror(pDataParams->dwErrorCode, (char *) pStatusMsg, wStatusMsgLen);
#endif /* NXPBUILD__PHHAL_HW_PN76XX */
#endif /* MBEDTLS_ERROR_C */

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_CRYPTORNG_MBEDTLS */
