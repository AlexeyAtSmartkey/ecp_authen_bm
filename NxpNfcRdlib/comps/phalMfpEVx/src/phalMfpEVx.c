/*----------------------------------------------------------------------------*/
/* Copyright 2013 - 2019, 2022 NXP                                            */
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
* Generic MIFARE Plus EVx contactless IC (Ev1, and future versions) contactless IC Application Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 5464 $ (v07.10.00)
* $Date: 2019-01-10 19:08:57 +0530 (Thu, 10 Jan 2019) $
*
* History:
*  Kumar GVS: Generated 15. Apr 2013
*
*/

#include <phalMfpEVx.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHAL_MFPEVX_SW
#include "Sw/phalMfpEVx_Sw.h"
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
#include "Sam_NonX/phalMfpEVx_Sam_NonX.h"
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


#ifdef NXPBUILD__PHAL_MFPEVX

/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for personalization.                                                                                */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_WritePerso(void * pDataParams, uint8_t bLayer4Comm, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pValue)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_WritePerso");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLayer4Comm);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bNumBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Verify the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLayer4Comm), &bLayer4Comm);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bNumBlocks), &bNumBlocks);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, (bNumBlocks * 16U));
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_WritePerso((phalMfpEVx_Sw_DataParams_t *) pDataParams, bLayer4Comm, wBlockNr, bNumBlocks, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_WritePerso(pDataParams, bLayer4Comm, wBlockNr, bNumBlocks, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_CommitPerso(void * pDataParams, uint8_t bOption, uint8_t bLayer4Comm)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_CommitPerso");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLayer4Comm);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Verify the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLayer4Comm), &bLayer4Comm);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_CommitPerso((phalMfpEVx_Sw_DataParams_t *) pDataParams, bOption, bLayer4Comm);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_CommitPerso(pDataParams, bOption, bLayer4Comm);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}





/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for authentication.                                                                                 */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_AuthenticateMfc(void * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNumber, uint16_t wKeyVersion,
    uint8_t * pUid, uint8_t bUidLength)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_AuthenticateMfc");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bBlockNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyType);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bBlockNo), &bBlockNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeyType), &bKeyType);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pUid), pUid, bUidLength);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_AuthenticateMfc((phalMfpEVx_Sw_DataParams_t *) pDataParams, bBlockNo, bKeyType, wKeyNumber, wKeyVersion, pUid, bUidLength);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_AuthenticateMfc(pDataParams, bBlockNo, bKeyType, wKeyNumber, wKeyVersion, pUid, bUidLength);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_AuthenticateSL0(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t * pDivInput, uint8_t bLenPcdCap2, uint8_t * pPcdCap2In, uint8_t * pPcdCap2Out,
    uint8_t * pPdCap2)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_AuthenticateSL0");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLayer4Comm);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFirstAuth);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2In);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2Out);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPdCap2);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInput) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);
    if(0U != bLenPcdCap2) PH_ASSERT_NULL_PARAM(pPcdCap2In, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPcdCap2Out, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPdCap2, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLayer4Comm), &bLayer4Comm);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFirstAuth), &bFirstAuth);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bLenDivInput);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2In), pPcdCap2In, bLenPcdCap2);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_AuthenticateSL0((phalMfpEVx_Sw_DataParams_t *) pDataParams, bLayer4Comm, bFirstAuth, wBlockNr, wKeyNumber,
                wKeyVersion, bLenDivInput, pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_AuthenticateSL0(pDataParams, bLayer4Comm, bFirstAuth, wBlockNr, wKeyNumber, wKeyVersion,
                bLenDivInput, pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2Out), pPcdCap2Out, 6);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPdCap2), pPdCap2, 6);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_AuthenticateSL1(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t * pDivInput, uint8_t bLenPcdCap2, uint8_t * pPcdCap2In, uint8_t * pPcdCap2Out,
    uint8_t * pPdCap2)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_AuthenticateSL1");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLayer4Comm);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFirstAuth);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2In);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2Out);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPdCap2);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInput) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);
    if(0U != bLenPcdCap2) PH_ASSERT_NULL_PARAM(pPcdCap2In, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPcdCap2Out, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPdCap2, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLayer4Comm), &bLayer4Comm);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFirstAuth), &bFirstAuth);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bLenDivInput);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2In), pPcdCap2In, bLenPcdCap2);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_AuthenticateSL1((phalMfpEVx_Sw_DataParams_t *) pDataParams, bLayer4Comm, bFirstAuth, wBlockNr, wKeyNumber,
                wKeyVersion, bLenDivInput, pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_AuthenticateSL1(pDataParams, bLayer4Comm, bFirstAuth, wBlockNr, wKeyNumber, wKeyVersion,
                bLenDivInput, pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2Out), pPcdCap2Out, 6);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPdCap2), pPdCap2, 6);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_AuthenticateSL3(void * pDataParams, uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNumber, uint16_t wKeyVersion,
    uint8_t bLenDivInput, uint8_t * pDivInput, uint8_t bLenPcdCap2, uint8_t * pPcdCap2In, uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_AuthenticateSL3");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFirstAuth);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2In);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCap2Out);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPdCap2);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInput) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);
    if(0U != bLenPcdCap2) PH_ASSERT_NULL_PARAM(pPcdCap2In, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPcdCap2Out, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pPdCap2, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFirstAuth), &bFirstAuth);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bLenDivInput);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2In), pPcdCap2In, bLenPcdCap2);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_AuthenticateSL3((phalMfpEVx_Sw_DataParams_t *) pDataParams, bFirstAuth, wBlockNr, wKeyNumber, wKeyVersion,
                bLenDivInput, pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_AuthenticateSL3(pDataParams, bFirstAuth, wBlockNr, wKeyNumber, wKeyVersion, bLenDivInput,
                pDivInput, bLenPcdCap2, pPcdCap2In, pPcdCap2Out, pPdCap2);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCap2Out), pPcdCap2Out, 6);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPdCap2), pPdCap2, 6);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_SSAuthenticate(void * pDataParams, uint8_t bOption, uint16_t wSSKeyBNr, uint16_t wSSKeyNr, uint16_t wSSKeyVer,
    uint8_t bLenDivInputSSKey, uint8_t * pDivInputSSKey, uint8_t bSecCount, uint16_t * pSectorNos, uint16_t * pKeyNos, uint16_t * pKeyVers,
    uint8_t bLenDivInputSectorKeyBs, uint8_t * pDivInputSectorKeyBs)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEV1_SSAuthenticate");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSSKeyBNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSSKeyNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSSKeyVer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLenDivInputSSKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInputSSKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSecCount);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSectorNos);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeyNos);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeyVers);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLenDivInputSectorKeyBs);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInputSectorKeyBs);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInputSSKey) PH_ASSERT_NULL_PARAM(pDivInputSSKey, PH_COMP_AL_MFPEVX);
    if(0U != bSecCount) PH_ASSERT_NULL_PARAM(pSectorNos, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pKeyNos, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pKeyVers, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInputSectorKeyBs) PH_ASSERT_NULL_PARAM(pDivInputSectorKeyBs, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSSKeyBNr), &wSSKeyBNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSSKeyNr), &wSSKeyNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSSKeyVer), &wSSKeyVer);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSecCount), &bSecCount);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLenDivInputSSKey), &bLenDivInputSSKey);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLenDivInputSectorKeyBs), &bLenDivInputSectorKeyBs);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInputSSKey), pDivInputSSKey, bLenDivInputSSKey);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSectorNos), pSectorNos, bSecCount);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKeyNos), pKeyNos, bSecCount);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKeyVers), pKeyVers, bSecCount);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInputSectorKeyBs), pDivInputSectorKeyBs, bLenDivInputSectorKeyBs);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_SSAuthenticate((phalMfpEVx_Sw_DataParams_t *) pDataParams, wSSKeyBNr, wSSKeyNr, wSSKeyVer, bLenDivInputSSKey, pDivInputSSKey,
                bSecCount, pSectorNos, pKeyNos, pKeyVers, bLenDivInputSectorKeyBs, pDivInputSectorKeyBs);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_SSAuthenticate(pDataParams, bOption, wSSKeyBNr, wSSKeyNr, wSSKeyVer, bLenDivInputSSKey, pDivInputSSKey, bSecCount,
                pSectorNos, pKeyNos, pKeyVers, bLenDivInputSectorKeyBs, pDivInputSectorKeyBs);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_AuthenticatePDC(void * pDataParams, uint16_t wBlockNr, uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput,
    uint8_t * pDivInput, uint8_t bUpgradeInfo)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_AuthenticatePDC");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUpgradeInfo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Verify the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bLenDivInput) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bLenDivInput);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bUpgradeInfo), &bUpgradeInfo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_AuthenticatePDC((phalMfpEVx_Sw_DataParams_t *) pDataParams, wBlockNr, wKeyNumber, wKeyVersion, bLenDivInput, pDivInput, bUpgradeInfo);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_AuthenticatePDC(pDataParams, wBlockNr, wKeyNumber, wKeyVersion, bLenDivInput, pDivInput, bUpgradeInfo);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    /* Resetting the state. */
    PH_CHECK_SUCCESS(phalMfpEVx_ResetSecMsgState(pDataParams));

    return status;
}





/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for data operations.                                                                                */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Write(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pBlocks, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Write");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bEncrypted);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bWriteMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bNumBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Verify the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bEncrypted), &bEncrypted);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bWriteMaced), &bWriteMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bNumBlocks), &bNumBlocks);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pBlocks), pBlocks, 16 * bNumBlocks);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Write((phalMfpEVx_Sw_DataParams_t *) pDataParams, bEncrypted, bWriteMaced, wBlockNr, bNumBlocks, pBlocks, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Write(pDataParams, bEncrypted, bWriteMaced, wBlockNr, bNumBlocks, pBlocks, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_Read(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd, uint16_t wBlockNr,
    uint8_t bNumBlocks, uint8_t * pBlocks)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Read");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bEncrypted);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bReadMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMacOnCmd);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bNumBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bEncrypted), &bEncrypted);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bReadMaced), &bReadMaced);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMacOnCmd), &bMacOnCmd);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bNumBlocks), &bNumBlocks);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Read((phalMfpEVx_Sw_DataParams_t *) pDataParams, bEncrypted, bReadMaced, bMacOnCmd, wBlockNr, bNumBlocks, pBlocks);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Read(pDataParams, bEncrypted, bReadMaced, bMacOnCmd, wBlockNr, bNumBlocks, pBlocks);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pBlocks), pBlocks, 16 * bNumBlocks);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}





/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for value operations.                                                                               */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_WriteValue(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced, uint16_t wBlockNr, uint8_t * pValue,
    uint8_t bAddrData, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_WriteValue");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bEncrypted);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bWriteMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAddrData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bEncrypted), &bEncrypted);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bWriteMaced), &bWriteMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bAddrData), &bAddrData);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_WriteValue((phalMfpEVx_Sw_DataParams_t *) pDataParams, bEncrypted, bWriteMaced, wBlockNr, pValue, bAddrData, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_WriteValue(pDataParams, bEncrypted, bWriteMaced, wBlockNr, pValue, bAddrData, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_ReadValue(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd, uint16_t wBlockNr,
    uint8_t * pValue, uint8_t * pAddrData)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ReadValue");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bEncrypted);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bReadMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMacOnCmd);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAddrData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pAddrData, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bEncrypted), &bEncrypted);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bReadMaced), &bReadMaced);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMacOnCmd), &bMacOnCmd);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch (PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ReadValue((phalMfpEVx_Sw_DataParams_t *) pDataParams, bEncrypted, bReadMaced, bMacOnCmd, wBlockNr, pValue, pAddrData);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ReadValue(pDataParams, bEncrypted, bReadMaced, bMacOnCmd, wBlockNr, pValue, pAddrData);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
        PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAddrData), pAddrData);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_Increment(void * pDataParams, uint8_t bIncrementMaced, uint16_t wBlockNr, uint8_t * pValue)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Increment");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIncrementMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIncrementMaced), &bIncrementMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Increment((phalMfpEVx_Sw_DataParams_t *) pDataParams, bIncrementMaced, wBlockNr, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Increment(pDataParams, bIncrementMaced, wBlockNr, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_Decrement(void * pDataParams, uint8_t bDecrementMaced, uint16_t wBlockNr, uint8_t * pValue)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Decrement");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDecrementMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDecrementMaced), &bDecrementMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Decrement((phalMfpEVx_Sw_DataParams_t *) pDataParams, bDecrementMaced, wBlockNr, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Decrement(pDataParams, bDecrementMaced, wBlockNr, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_IncrementTransfer(void * pDataParams, uint8_t bIncrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_IncrementTransfer");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIncrementTransferMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSourceBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDestinationBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIncrementTransferMaced), &bIncrementTransferMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSourceBlockNr), &wSourceBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDestinationBlockNr), &wDestinationBlockNr);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_IncrementTransfer((phalMfpEVx_Sw_DataParams_t *) pDataParams, bIncrementTransferMaced, wSourceBlockNr, wDestinationBlockNr, pValue, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_IncrementTransfer(pDataParams, bIncrementTransferMaced, wSourceBlockNr, wDestinationBlockNr,
                pValue, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_DecrementTransfer(void * pDataParams, uint8_t bDecrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_DecrementTransfer");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDecrementTransferMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSourceBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDestinationBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDecrementTransferMaced), &bDecrementTransferMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSourceBlockNr), &wSourceBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDestinationBlockNr), &wDestinationBlockNr);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_DecrementTransfer((phalMfpEVx_Sw_DataParams_t *) pDataParams, bDecrementTransferMaced, wSourceBlockNr, wDestinationBlockNr, pValue, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_DecrementTransfer(pDataParams, bDecrementTransferMaced, wSourceBlockNr, wDestinationBlockNr,
                pValue, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_Transfer(void * pDataParams, uint8_t bTransferMaced, uint16_t wBlockNr, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Transfer");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bTransferMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bTransferMaced), &bTransferMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Transfer((phalMfpEVx_Sw_DataParams_t *) pDataParams, bTransferMaced, wBlockNr, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Transfer(pDataParams, bTransferMaced, wBlockNr, pTMC, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_Restore(void * pDataParams, uint8_t bRestoreMaced, uint16_t wBlockNr)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_Restore");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRestoreMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bRestoreMaced), &bRestoreMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_Restore((phalMfpEVx_Sw_DataParams_t *) pDataParams, bRestoreMaced, wBlockNr);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_Restore(pDataParams, bRestoreMaced, wBlockNr);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */





/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for special operations.                                                                             */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_GetVersion(void * pDataParams, uint8_t * pVerInfo)
{
    phStatus_t PH_MEMLOC_REM status;
    uint8_t     PH_MEMLOC_REM bVerLen = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_GetVersion");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pVerInfo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Verify the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pVerInfo, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_GetVersion((phalMfpEVx_Sw_DataParams_t *) pDataParams, pVerInfo, &bVerLen);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_GetVersion(pDataParams, pVerInfo, &bVerLen);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pVerInfo), pVerInfo, bVerLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_ReadSign(void * pDataParams, uint8_t bLayer4Comm, uint8_t bAddr, uint8_t ** pSignature)
{
    phStatus_t PH_MEMLOC_REM status = 0;
    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ReadSign");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAddr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSignature);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pSignature, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bAddr), &bAddr);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return  PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ReadSign((phalMfpEVx_Sw_DataParams_t *) pDataParams, bLayer4Comm, bAddr, pSignature);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ReadSign(pDataParams, bLayer4Comm, bAddr, pSignature);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSignature), *pSignature, 56);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_ResetAuth(void * pDataParams)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ResetAuth");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ResetAuth((phalMfpEVx_Sw_DataParams_t *) pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ResetAuth(pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_PersonalizeUid(void * pDataParams, uint8_t bUidType)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_PersonalizeUid");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidType);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bUidType), &bUidType);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_PersonalizeUid((phalMfpEVx_Sw_DataParams_t *) pDataParams, bUidType);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_PersonalizeUid(pDataParams, bUidType);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_SetConfigSL1(void * pDataParams, uint8_t bOption)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "PhalMfpEv1_SetConfigSL1");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_SetConfigSL1((phalMfpEVx_Sw_DataParams_t *) pDataParams, bOption);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_SetConfigSL1(pDataParams, bOption);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return status;
}

phStatus_t phalMfpEVx_ReadSL1TMBlock(void * pDataParams, uint16_t wBlockNr, uint8_t * pBlocks)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ReadSL1Tmac");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pBlocks);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ReadSL1TMBlock((phalMfpEVx_Sw_DataParams_t *) pDataParams, wBlockNr, pBlocks);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ReadSL1TMBlock(pDataParams, wBlockNr, pBlocks);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pBlocks), pBlocks, 16);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_VCSupportLastISOL3(void * pDataParams, uint8_t * pIid, uint8_t * pPcdCapL3, uint8_t * pInfo)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEV1_VCSupportLastISOL3");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pIid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPcdCapL3);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInfo);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pIid), pIid, 16);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPcdCapL3), pPcdCapL3, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_VCSupportLastISOL3((phalMfpEVx_Sw_DataParams_t *) pDataParams, pIid, pPcdCapL3, pInfo);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_VCSupportLastISOL3(pDataParams, pIid, pPcdCapL3, pInfo);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    if(pInfo != NULL)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pInfo), pInfo, 1);
    }
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_ChangeKey(void * pDataParams, uint8_t bChangeKeyMaced, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t * pDivInput)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ChangeKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bChangeKeyMaced);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBlockNr);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNumber);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(bLenDivInput) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bChangeKeyMaced), &bChangeKeyMaced);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBlockNr), &wBlockNr);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNumber), &wKeyNumber);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVersion), &wKeyVersion);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bLenDivInput);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ChangeKey((phalMfpEVx_Sw_DataParams_t *) pDataParams, bChangeKeyMaced, wBlockNr, wKeyNumber, wKeyVersion, bLenDivInput, pDivInput);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ChangeKey(pDataParams, bChangeKeyMaced, wBlockNr, wKeyNumber, wKeyVersion, bLenDivInput, pDivInput);
            break;
#endif /*NXPBUILD__PHAL_MFPEVX_SAM_NONX*/


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_CommitReaderID(void * pDataParams, uint16_t wBlockNr, uint8_t * pTMRI, uint8_t * pEncTMRI)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_CommitReaderID");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMRI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncTMRI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
#ifdef NXPBUILD__PHAL_MFPEVX_SW
    if(PH_GET_COMPID(pDataParams) == PHAL_MFPEVX_SW_ID)
        PH_ASSERT_NULL_PARAM(pTMRI, PH_COMP_AL_MFPEVX);
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PHAL_MFPEVX_SW
    if(PH_GET_COMPID(pDataParams) == PHAL_MFPEVX_SW_ID)
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMRI), pTMRI, 16);
#endif /* NXPBUILD__PHAL_MFPEVX_SW */
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_CommitReaderID((phalMfpEVx_Sw_DataParams_t *) pDataParams, wBlockNr, pTMRI, pEncTMRI);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_CommitReaderID(pDataParams, wBlockNr, pEncTMRI);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pEncTMRI), pEncTMRI, 16);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */





/***************************************************************************************************************************************/
/* Mifare Plus EV1 Generic command for utility operations.                                                                             */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_ResetSecMsgState(void * pDataParams)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_ResetSecMsgState");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_ResetSecMsgState((phalMfpEVx_Sw_DataParams_t *) pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_ResetSecMsgState(pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_SetConfig(void * pDataParams, uint16_t wOption, uint16_t wValue)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_SetConfig");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wValue), &wValue);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_SetConfig((phalMfpEVx_Sw_DataParams_t *) pDataParams, wOption, wValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_SetConfig(pDataParams, wOption, wValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_GetConfig(void * pDataParams, uint16_t wOption, uint16_t * pValue)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_GetConfig");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_GetConfig((phalMfpEVx_Sw_DataParams_t *) pDataParams, wOption, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_GetConfig(pDataParams, wOption, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_SetVCAParams(void * pDataParams, void * pAlVCADataParams)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_SetVCAParams");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pAlVCADataParams, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_SetVCAParams((phalMfpEVx_Sw_DataParams_t *) pDataParams, pAlVCADataParams);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_CalculateTMV(void * pDataParams, uint16_t wOption, uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pTMI,
    uint16_t wTMILen, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_CalculateTMV");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoTMACKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerTMACKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyVer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wTMILen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bDivInputLen) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pTMC, PH_COMP_AL_MFPEVX);
    if(0U != bUidLen) PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFPEVX);
    if(0U != wTMILen) PH_ASSERT_NULL_PARAM(pTMI, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNoTMACKey), &wKeyNoTMACKey);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVerTMACKey), &wKeyVerTMACKey);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wRamKeyNo), &wRamKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wRamKeyVer), &wRamKeyVer);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDivInputLen), &bDivInputLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bUidLen), &bUidLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wTMILen), &wTMILen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bDivInputLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pUid), pUid, bUidLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMI), pTMI, wTMILen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_CalculateTMV((phalMfpEVx_Sw_DataParams_t *) pDataParams, wOption, wKeyNoTMACKey, wKeyVerTMACKey, pDivInput,
                bDivInputLen, pTMC, pUid, bUidLen, pTMI, wTMILen, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_CalculateTMV(pDataParams, wKeyNoTMACKey, wKeyVerTMACKey, wRamKeyNo, wRamKeyVer, pTMC, pUid, bUidLen,
                pTMI, wTMILen, pTMV);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMV), pTMV, 8);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

phStatus_t phalMfpEVx_DecryptReaderID(void * pDataParams, uint16_t wOption, uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pTMC, uint8_t * pUid,
    uint8_t bUidLen, uint8_t * pEncTMRI, uint8_t * pTMRIPrev)
{
    phStatus_t PH_MEMLOC_REM status;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfpEVx_DecryptReaderID");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoTMACKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerTMACKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyVer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncTMRI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMRIPrev);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
    if(0U != bDivInputLen) PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pTMC, PH_COMP_AL_MFPEVX);
    if(0U != bUidLen) PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_PARAM(pEncTMRI, PH_COMP_AL_MFPEVX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNoTMACKey), &wKeyNoTMACKey);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyVerTMACKey), &wKeyVerTMACKey);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wRamKeyNo), &wRamKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wRamKeyVer), &wRamKeyVer);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDivInputLen), &bDivInputLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bUidLen), &bUidLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput, bDivInputLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMC), pTMC, 4);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pUid), pUid, bUidLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pEncTMRI), pEncTMRI, 16);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFPEVX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFPEVX_SW
        case PHAL_MFPEVX_SW_ID:
            status = phalMfpEVx_Sw_DecryptReaderID((phalMfpEVx_Sw_DataParams_t *) pDataParams, wOption, wKeyNoTMACKey, wKeyVerTMACKey, pDivInput,
                bDivInputLen, pTMC, pUid, bUidLen, pEncTMRI, pTMRIPrev);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
        case PHAL_MFPEVX_SAMAV3_NONX_ID:
            status = phalMfpEVx_Sam_NonX_DecryptReaderID(pDataParams, wKeyNoTMACKey, wKeyVerTMACKey, wRamKeyNo, wRamKeyVer, pTMC, pUid,
                bUidLen, pEncTMRI, pTMRIPrev);
            break;
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */


        default:
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMRIPrev), pTMRIPrev, 16);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}

#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

#endif /* NXPBUILD__PHAL_MFPEVX */
