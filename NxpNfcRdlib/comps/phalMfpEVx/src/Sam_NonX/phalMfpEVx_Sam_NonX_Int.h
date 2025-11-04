/*----------------------------------------------------------------------------*/
/* Copyright 2015, 2024 NXP                                                   */
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
* Mifare Plus EVx application's Sam NonX layer's internal component of Reader Library framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALMFPEVX_SAM_NONX_INT_H
#define PHALMFPEVX_SAM_NONX_INT_H

#include <ph_Status.h>

/* Mifare Plus EVx command codes. */
#define PHAL_MFPEVX_CMD_AUTH_FIRST                      0x70U   /**< MFPEVX command code for Authenticate First. */
#define PHAL_MFPEVX_CMD_AUTH_NON_FIRST                  0x76U   /**< MFPEVX command code for Authenticate Non First. */
#define PHAL_MFPEVX_CMD_AUTH_CONTINUE                   0x72U   /**< MFPEVX command code for Authenticate Continue. */

/* Mifare Plus EVx Security Levels to be used while performing authentication. This data will be utilized
 * for updating the P1 information byte of Sam Av3 Hal interface. */
#define PHAL_MFPEVX_SECURITY_LEVEL_0_KDF                0x00U   /**< MFPEVX Security Level 0 KDF value to be passed for P1 information byte. */
#define PHAL_MFPEVX_SECURITY_LEVEL_1_KDF                0x00U   /**< MFPEVX Security Level 1 KDF value to be passed for P1 information byte. */
#define PHAL_MFPEVX_SECURITY_LEVEL_3_KDF                0x0CU   /**< MFPEVX Security Level 3 KDF value to be passed for P1 information byte. */

/* Mifare Plus EVx buffer sizes. */
#define PHAL_MFPEVX_CAPABILITY_SIZE                     6U      /**< MFPEVX PCD or PD capability's buffer size. */
#define PHAL_MFPEVX_AUTH_CMD_SIZE                       39U     /**< MFPEVX Authenticate First command buffer size. */
#define PHAL_MFPEVX_RESP_PD_CHAL_SIZE                   16U     /**< MFPEVX Authenticate First response buffer size. */
#define PHAL_MFPEVX_PD_CHAL_SIZE                        16U     /**< MFPEVX PD Challenge size. */
#define PHAL_MFPEVX_RESP_PCD_CHAL_SIZE                  32U     /**< MFPEVX PCD Challenge response buffer size. */
#define PHAL_MFPEVX_COMBINED_WRITE_CMD_SIZE             5U      /**< MFPEVX Combined Write command buffer size. */
#define PHAL_MFPEVX_COMBINED_READ_CMD_SIZE              4U      /**< MFPEVX Combined Read command buffer size. */
#define PHAL_MFPEVX_CHANGE_KEY_CMD_SIZE                 36U     /**< MFPEVX ChangeKey command buffer size. */
#define PHAL_MFPEVX_COMMIT_READER_ID_CMD_SIZE           27U     /**< MFPEVX CommitReaderID command buffer size. */

#define PHAL_MFPEVX_IGNORE_PICC_STATUS_CHECK            0x0080U /**< This flag specifies the generic internal wrapping interface not to validate the PICC error codes. */
#define PHAL_MFPEVX_SAM_NONX_SESSION_TMAC_ENC           0x01U   /**< Option to perform generate the TMAC session encryption keys. */
#define PHAL_MFPEVX_SAM_NONX_SESSION_TMAC_MAC           0x02U   /**< Option to perform generate the TMAC session MAC keys. */

/* Sam maximum single frame size. */
#define PHAL_MFPEVX_SAM_DATA_FRAME_LENGTH               224U    /* Maximum data that can be exchanged in case of secure messaging computation by SAM. */
#define PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE    224U    /**< Maximum number of bytes that can be framed in one single SAM frame.
                                                                 *   => HOST PROTECTION PLAIN = [Cmd + BNr + Ext + RC] + Data
                                                                 *   => HOST PROTECTION MAC   = [Cmd + BNr + Ext + RC] + Data + HOST MAC
                                                                 *   => HOST PROTECTION FULL  = HOST_ENC ( [Cmd + BNr + Ext + RC] + Data ) + HOST_MAC
                                                                 */

/* Resolves the component to be used. */
#define PHAL_MFPEVX_RESOLVE_DATAPARAMS(DataParams)  ((phalMfpEVx_SamAV3_NonX_DataParams_t *) DataParams)

/* Resolves the Hal component to be used for communicating with Sam hardware in X mode. */
#define PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(DataParams)                                                                                              \
            (((*(uint16_t *)(DataParams)) & 0xFF) == PHAL_MFPEVX_SAMAV3_NONX_ID) ? ((phalMfpEVx_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams :   \
            NULL

phStatus_t phalMfpEVx_Sam_NonX_Int_ResetSecMsgState(void * pDataParams);

phStatus_t phalMfpEVx_Sam_NonX_Int_CardExchange(void * pDataParams, uint16_t wOption, uint8_t bIsoLayer, uint8_t bLc,
    uint8_t * pPayload, uint16_t wPayloadLen, uint8_t ** ppResponse, uint16_t * pRespLen, uint8_t * pPiccErrCode);

phStatus_t phalMfpEVx_Sam_NonX_Int_WriteExtMfc(void * pDataParams, uint8_t bCmdCode, uint8_t bBlockNo, uint8_t * pData,
    uint16_t wDataLen, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_Int_ReadExtMfc(void * pDataParams, uint8_t bBlockNo, uint8_t * pBlockData);

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMfc(void * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t * pUid, uint8_t bUidLen);

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMFP(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint8_t bKdf,
    uint16_t wBlockNr, uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen,
    uint8_t * pPcdCap2In, uint8_t * pPcdCap2Out, uint8_t * pPdCap2);

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMFP_Ext(void * pDataParams, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2);

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthSectorSwitchMFP(void * pDataParams, uint8_t bOption, uint16_t wSSKeyBNr,
    uint16_t wSSKeyNr, uint16_t wSSKeyVer, uint8_t bLenDivInputSSKey, uint8_t * pDivInputSSKey, uint8_t bSecCount,
    uint16_t *pSectorNos, uint16_t *pKeyNo, uint16_t *pKeyVer, uint8_t bLenDivInputSectorKeyBs,
    uint8_t * pDivInputSectorKeyBs);

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticatePDC(void * pDataParams, uint16_t wBlockNr, uint16_t wKeyNum, uint16_t wKeyVer,
    uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bUpgradeInfo);

phStatus_t phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(void * pDataParams, uint8_t bCmdCode, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pData, uint8_t bDataLen, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_Int_CombinedReadMFP(void * pDataParams, uint8_t bCmdCode, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pBlocks);

phStatus_t phalMfpEVx_Sam_NonX_Int_ChangeKeyMFP(void * pDataParams, uint8_t bCommand, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput);

phStatus_t phalMfpEVx_Sam_NonX_Int_CommitReaderID(void * pDataParams, uint16_t wBlockNr, uint8_t * pEncTMRI);

phStatus_t phalMfpEVx_Sam_NonX_Int_ComputeTMACSessionVectors(void * pDataParams, uint8_t bOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen);
#endif /* PHALMFPEVX_SAM_NONX_INT_H */
