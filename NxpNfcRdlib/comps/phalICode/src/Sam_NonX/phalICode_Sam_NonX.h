/*----------------------------------------------------------------------------*/
/* Copyright 2017-2020, 2022-2024 NXP                                         */
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
 * Sam NonX ICode Application Component of Reader Library Framework.
 * $Author: NXP $
 * $Revision: $ (v07.10.00)
 * $Date: $
 *
 */

#ifndef PHALICODE_SAM_NONX_H
#define PHALICODE_SAM_NONX_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_ICODE_SAM_NONX
/* Performs a Inventory command. This command performs the ISO15693 anti-collision sequence and detects one ISO15693 complaint
 * card.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bFlags          : Request flags byte.
 *                          0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                          0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                          0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                          0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                          0x10:   PHAL_ICODE_FLAG_SELECTED
 *                          0x10:   PHAL_ICODE_FLAG_AFI
 *                          0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                          0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                          0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi            : Application Family Identifier.
 *      pMask           : UID mask, holding known UID bits.
 *      bMaskBitLen     : Number of UID bits within pMask.
 *
 * Output Parameters:
 *      pDsfid          : 1 byte Data Storage Format Identifier.
 *      pUid            : 8 bytes of Unique identifier of the card.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_Inventory(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags, uint8_t bAfi,
    uint8_t * pMask, uint8_t bMaskBitLen, uint8_t * pDsfid, uint8_t * pUid);

/*
 * Perform a StayQuiet command. When receiving the Stay quiet command, the VICC shall enter the quiet state and shall
 * NOT send back a response. There is NO response to the Stay quiet command.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_StayQuiet(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * Performs a Single block read command. When receiving the Read Single Block command, the VICC shall read the requested block and send
 * back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                              0x00:   PHAL_ICODE_OPTION_OFF
 *                              0x01:   PHAL_ICODE_OPTION_ON
 *                              0x00:   PHAL_ICODE_OPTION_DEFAULT
 *
 *                              If Option is OFF, block Security Status information is not available. Only block data is available.
 *                              Format will be 4 byte data.
 *                              If Option is ON, both block Security Status information and Block Data is available. Format of the
 *                              response will be Status, 4 byte data
 *      bBlockNo        : Block number from where the data to be read.
 *
 * Output Parameters:
 *      ppData          : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadSingleBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bBlockNo, uint8_t ** ppData, uint16_t * pDataLen);

/*
 * Performs a Single block write command. When receiving the Write single block command, the VICC shall write the requested block with the
 * data contained in the request and report the success of the operation in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON)
 * is set in the request, the VICC shall wait for the reception of an EOF from the VCD and upon such reception shall return its response.
 * If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its response when it has completed the write operation starting
 * after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon
 * detection of the rising edge of the EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bBlockNo        : Block number to which the data should be written.
 *      pData           : Information to be written to the specified block number.
 *      bDataLen        : Number of bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WriteSingleBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bBlockNo, uint8_t * pData, uint8_t bDataLen);

/*
 * Performs a Lock block command. When receiving the Lock block command, the VICC shall lock permanently the requested block. If the
 * Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the VCD
 * and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 * (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bBlockNo        : Block number which should be locked.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bBlockNo);

/*
 * Performs a Multiple block read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s) and send
 * back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall
 * return only the block value.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo        : Block number from where the data to be read.
 *      bNumBlocks      : Total number of block to read.
 *
 * Output Parameters:
 *      pData           : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadMultipleBlocks(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bBlockNo, uint8_t bNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Perform a Select command.
 * When receiving the Select command:
 *      If the UID is equal to its own UID, the VICC shall enter the selected state and shall send a response.
 *      If it is different, the VICC shall return to the Ready state and shall not send a response.The Select command
 *      shall always be executed in Addressed mode. (The Select_flag is set to 0. The Address_flag is set to 1.)
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_Select(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * Perform a ResetToReady command. When receiving a Reset to ready command, the VICC shall return to the Ready state.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ResetToReady(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * Performs a WriteAFI command. When receiving the Write AFI request, the VICC shall write the  AFI value into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the write operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bAfi            : Value of Application Family Identifier.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WriteAFI(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bAfi);

/*
 * Performs a LockAFI command. When receiving the Lock AFI request, the VICC shall lock the AFI value permanently into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockAFI(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * Performs WriteDSFID command. When receiving the Write DSFID request, the VICC shall write the DSFID value into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the write operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bDsfid          : Value of DSFID (data storage format identifier).
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WriteDSFID(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bDsfid);

/*
 * Performs LockDSFID command. When receiving the Lock DSFID request, the VICC shall lock the DSFID value permanently into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the
 * VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us)
 * with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockDSFID(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * Performs GetSystemInformation command. This command allows for retrieving the system information value from the VICC.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppSystemInfo    : The system information of the VICC.
 *      pSystemInfoLen  : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetSystemInformation(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t ** ppSystemInfo,
    uint16_t * pSystemInfoLen);

/*
 * Performs GetMultipleBlockSecurityStatus. When receiving the Get multiple block security status command, the VICC
 * shall send back the block security status.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bBlockNo        : Block number for which the status should be returned.
 *      bNoOfBlocks     : Number of blocks to be used for returning the status.
 *
 * Output Parameters:
 *      pStatus         : The status of the block number mentioned in bBlockNo until bNoOfBlocks.
 *      pStatusLen      : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetMultipleBlockSecurityStatus(phalICode_SamAV3_NonX_DataParams_t * pDataParams,
    uint8_t bBlockNo, uint8_t bNoOfBlocks, uint8_t * pStatus, uint16_t * pStatusLen);

/*
 * Performs a Multiple block fast read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s) and
 * send back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall
 * return only the block value.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo        : Block number from where the data to be read.
 *      bNumBlocks      : Total number of block to read.
 *
 * Output Parameters:
 *      pData           : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_FastReadMultipleBlocks(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bBlockNo, uint8_t bNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/**
 * \brief Performs a Extended Single block read command. When receiving the Extended Read Single Block command, the VICC shall read the
 * requested block and send back its value in the response. If a VICC supports Extended read single block command, it shall also support
 * Read single block command for the first 256 blocks of memory. If the Option_flag (bOption = #PHAL_ICODE_OPTION_ON) is set in the request,
 * the VICC shall return the block security status, followed by the block value. If it is not set (bOption = #PHAL_ICODE_OPTION_OFF), the
 * VICC shall return only the block value.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                              0x00:   PHAL_ICODE_OPTION_OFF
 *                              0x01:   PHAL_ICODE_OPTION_ON
 *                              0x00:   PHAL_ICODE_OPTION_DEFAULT
 *
 *                              If Option is OFF, block Security Status information is not available. Only block data is available.
 *                              Format will be 4 byte data.
 *                              If Option is ON, both block Security Status information and Block Data is available. Format of the
 *                              response will be Status, 4 byte data
 *      wBlockNo        : Block number from where the data to be read.
 *
 * Output Parameters:
 *      ppData          : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedReadSingleBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint16_t wBlockNo, uint8_t ** ppData, uint16_t * pDataLen);

/**
 * \brief Performs a Extended Single block Write command. When receiving the Extended write single block command, the VICC shall write the
 * requested block with the data contained in the request and report the success of the operation in the response. If a VICC supports
 * Extended write single block command, it shall also support Write single block command for the first 256 blocks of memory.
 *
 * If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its response when it has completed the write operation starting
 * after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon
 * detection of the rising edge of the EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      wBlockNo        : Block number to which the data should be written.
 *      pData           : Information to be written to the specified block number.
 *      bDataLen        : Number of bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedWriteSingleBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint16_t wBlockNo, uint8_t * pData, uint8_t bDataLen);

/*
 * Performs a Extended Lock block command. When receiving the Lock block command, the VICC shall lock permanently the requested
 * block. If a VICC supports Extended lock block command, it shall also support Lock block command for the first 256 blocks of memory.
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the
 * VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 * (302 us) with a total tolerance of 32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bBlockNo        : Block number which should be locked.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedLockBlock(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint16_t wBlockNo);

/*
 * Performs a Extended Multiple block read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s)
 * and send back its value in the response. If a VICC supports Extended read multiple blocks command, it shall also support Read multiple blocks
 * command for the first 256 blocks of memory.
 *
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block security status, followed by the block
 * value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      wBlockNo        : Block number from where the data to be read.
 *      wNumBlocks      : Total number of block to read.
 *
 * Output Parameters:
 *      pData           : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedReadMultipleBlocks(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint16_t wBlockNo, uint16_t wNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Authneticates with the card using AES keys provided. This interface performs TAM1 authentication
 * with the card.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams : Pointer to this layer's parameter structure.
 *      bOption     : Options to be enabled or disabled. As per ISO15693 protocol
 *                      0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                      0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bKeyNo      : AES key address in software key store or SAM hardware keystore.
 *      bKeyVer     : AES key version to be used.
 *      bKeyNoCard  : Block number of the AES key available in the card.
 *      pDivInput   : Diversification Input used to diversify the key. The diversification input is
 *                    available in SAM mode only.
 *      bDivLen     : Length of diversification input used to diversify the key.
 *                    If 0, no diversification is performed.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_AuthenticateTAM1(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivLen);

/*
 * Authneticates with the card using AES keys provided. This interface performs TAM2 authentication
 * with the card.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams : Pointer to this layer's parameter structure.
 *      bOption     : Options to be enabled or disabled.
 *                      0x00: Disable option.
 *                      0x01: Enable option.
 *      bKeyNo      : AES key address in hardware key store.
 *      bKeyVer     : AES key version to be used.
 *      bKeyNoCard  : Block number of the AES key available in the card.
 *      pDivInput   : Diversification Input used to diversify the key.
 *      bDivLen     : Length of diversification input used to diversify the key.
 *                    If 0, no diversification is performed.
 *      bBlockSize  : To select the size of custom data block to be used.
 *                    The value should either be 0x00 for 16 bit block size or 0x01 for 64 bit
 *                    block size. As per ISO 29167
 *      bBlockCount : To select the custom data block to be used from the offset specified.
 *                    The BlockCount range is from 1 - 16.
 *      bProfile    : To select one of the memory profiles supported by the tag.
 *                    The Profile range is from 0 - 15. As per ISO 29167
 *      bProtMode   : To specify the mode of operation to be used for encryption/decryption.
 *                    The ProtMode ranges form 0 - 3. As per ISO 29167
 *      bOffset     : To set the offset for the specified profile.
 *                    The Offset ranges form 0 - 4095. As per ISO 29167
 *
 * Output Parameters:
 *      ppCustomData    : The custom data returned by the card.
 *      pCustomDataLen  : The length of custom data returned.
 *
 * Return:
 *      0x2200  : successful operation.
 *      0x22xx  : Error codes as per 15693 spec. or custom error codes of this layer.
 */
phStatus_t phalICode_Sam_NonX_AuthenticateTAM2(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivLen, uint8_t bBlockSize,
    uint8_t bBlockCount, uint8_t bProfile, uint8_t bProtMode, uint16_t wOffset, uint8_t * pCustomData,
    uint16_t * pCustomDataLen);

/*
 * Authneticates with the card using AES keys provided. This interface performs MAM authentication
 * with the card. Both MAM1 and MAM2 message are framed and exchanged to the card.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams : Pointer to this layer's parameter structure.
 *      bOption     : Options to be enabled or disabled. As per ISO15693 protocol
 *                      0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                      0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bKeyNo      : AES key address in software key store or SAM hardware keystore.
 *      bKeyVer     : AES key version to be used.
 *      bKeyNoCard  : Block number of the AES key available in the card.
 *      bPurposeMAM2: The PurposeMAM2 data to be used. This is a 4 bit value. As per ISO15693 protocol
 *      pDivInput   : Diversification Input used to diversify the key. The diversification input is
 *                    available in SAM mode only.
 *      bDivLen     : Length of diversification input used to diversify the key.
 *                    If 0, no diversification is performed.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_AuthenticateMAM(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyNoCard, uint8_t bPurposeMAM2, uint8_t * pDivInput, uint8_t bDivLen);



/*
 * Performs tag authentication with the card. This is another method of authenticating with the card.
 * Here the TAM1 challenge message is sent to the card. The card does not respond for this command.
 * To verify if this command was success the command phalIcodeDna_ReadBuffer should be called.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams : Pointer to this layer's parameter structure.
 *      bKeyNoCard  : Block number of the AES key available in the card.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_Challenge(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bKeyNoCard);

/*
 * Reads the crypto calculation result of previous Challenge command. If the Challenge Command was success,
 * Then the encrypted response will be returned. The response will be same as TAM1 response format. If verification
 * is enabled (i.e. bVerify = 0x01), The encrypted response will be decrypted and the random number generated by the
 * Challenge command will be compared against the received one. If fails AUTH_ERROR will be returned.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams : Pointer to this layer's parameter structure.
 *      bVerify     : To verify the received data with the random number generated by Challenge command.
 *                      0x00: Disable verification
 *                      0x01: Enable verification
 *      bKeyNo      : AES key address in software key store.
 *      bKeyVer     : AES key version to be used.
 *
 * Output Parameters:
 *      ppResponse  : If verification is enabled the decrypted response data will be available. Also
 *                    the response will be verified with the random number generated by
 *                    \ref phalICode_Challenge command.
 *                    If verification is disabled the encrypted response data will be available.
 *      pRespLen    : Length of available bytes in ppResponse buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadBuffer(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bVerify, uint8_t bKeyNo,
    uint8_t bKeyVer, uint8_t ** ppResponse, uint16_t * pRespLen);

/*
 * Performs ExtendedGetSystemInformation command. This command allows for retrieving the system information value
 * from the VICC and shall be supported by the VICC if extended memory or security functionalities are supported
 * by the VICC.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bInfoParams         : Extend Get System Information parameter request fields.
 *                              0x10: PHAL_ICODE_INFO_PARAMS_REQUEST_DEFAULT
 *                              0x01: PHAL_ICODE_INFO_PARAMS_REQUEST_DSFID
 *                              0x02: PHAL_ICODE_INFO_PARAMS_REQUEST_AFI
 *                              0x04: PHAL_ICODE_INFO_PARAMS_REQUEST_VICC_MEM_SIZE
 *                              0x08: PHAL_ICODE_INFO_PARAMS_REQUEST_IC_REFERENCE
 *                              0x10: PHAL_ICODE_INFO_PARAMS_REQUEST_MOI
 *                              0x20: PHAL_ICODE_INFO_PARAMS_REQUEST_COMMAND_LIST
 *                              0x50: PHAL_ICODE_INFO_PARAMS_REQUEST_CSI_INFORMATION
 *                              0x80: PHAL_ICODE_INFO_PARAMS_REQUEST_EXT_GET_SYS_INFO
 *
 * Output Parameters:
 *      ppSystemInfo        : The system information of the VICC.
 *      pSystemInfoLen      : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedGetSystemInformation(phalICode_SamAV3_NonX_DataParams_t * pDataParams,
    uint8_t bInfoParams, uint8_t ** ppSystemInfo, uint16_t * pSystemInfoLen);

/*
 * Performs ExtendedGetMultipleBlockSecurityStatus. When receiving the Extended Get multiple block security status
 * command, the VICC shall send back the block security status. The blocks are numbered from 0000 to FFFF (0 - 65535).
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      wBlockNo        : Block number for which the status should be returned.
 *      wNoOfBlocks     : Number of blocks to be used for returning the status.
 *
 * Output Parameters:
 *      pStatus         : The status of the block number mentioned in wBlockNo until wNoOfBlocks.
 *      pStatusLen      : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedGetMultipleBlockSecurityStatus(phalICode_SamAV3_NonX_DataParams_t * pDataParams,
    uint16_t wBlockNo, uint16_t wNoOfBlocks, uint8_t * pStatus, uint16_t * pStatusLen);

/*
 * Performs a Extended Multiple block fast read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s)
 * and send back its value in the response. If a VICC supports Extended read multiple blocks command, it shall also support Read multiple blocks
 * command for the first 256 blocks of memory.
 *
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block security status, followed by the block
 * value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      wBlockNo        : Block number from where the data to be read.
 *      wNumBlocks      : Total number of block to read.
 *
 * Output Parameters:
 *      pData           : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ExtendedFastReadMultipleBlocks(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint16_t wBlockNo, uint16_t wNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Perform ISO15693 InventoryRead command. When receiving the INVENTORY READ request, the ICODE IC performs the same as the
 * anti-collision sequence, with the difference that instead of the UID and the DSFID, the requested response is defined by
 * additional options.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bFlags          : Request flags byte.
 *                          0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                          0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                          0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                          0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                          0x10:   PHAL_ICODE_FLAG_SELECTED
 *                          0x10:   PHAL_ICODE_FLAG_AFI
 *                          0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                          0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                          0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi            : Application Family Identifier.
 *      pMask           : UID mask, holding known UID bits.
 *      bMaskBitLen     : Number of UID bits within pMask.
 *      bBlockNo        : Block number of first block to read.
 *      bNoOfBlocks     : Number of blocks to read.
 *
 * Output Parameters:
 *      pUid            : Received Uid.
 *      pUidLen         : Number of received UID bytes.
 *      pData           : Received data.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_InventoryRead(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags, uint8_t bAfi,
    uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bBlockNo, uint8_t bNoOfBlocks, uint8_t * pUid, uint8_t * pUidLen,
    uint8_t * pData, uint16_t * pDataLen);

/*
 * Perform ISO15693 InventoryReadExtended command.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bFlags              : Request flags byte.
 *                              0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                              0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                              0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                              0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                              0x10:   PHAL_ICODE_FLAG_SELECTED
 *                              0x10:   PHAL_ICODE_FLAG_AFI
 *                              0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                              0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                              0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi                : Application Family Identifier.
 *      pMask               : UID mask, holding known UID bits.
 *      bMaskBitLen         : Number of UID bits within pMask.
 *      bExtendedOptions    : Request flags byte.
 *                              0x00:   PHAL_ICODE_INVENTORY_READ_EXT_DEFAULT
 *                              0x01:   PHAL_ICODE_INVENTORY_READ_EXT_EAS_MODE
 *                              0x02:   PHAL_ICODE_INVENTORY_READ_EXT_UID_MODE
 *                              0x04:   PHAL_ICODE_INVENTORY_READ_EXT_CID_COMPARE
 *                              0x08:   PHAL_ICODE_INVENTORY_READ_EXT_CID_RESPONSE
 *                              0x10:   PHAL_ICODE_INVENTORY_READ_EXT_SKIP_DATA
 *                              0x20:   PHAL_ICODE_INVENTORY_READ_EXT_QUIET
 *                              0x40:   PHAL_ICODE_INVENTORY_READ_EXT_PERSIST_QUIET
 *                              0x60:   PHAL_ICODE_INVENTORY_READ_EXT_PERSIST_QUIET_RESPONSE
 *      bAfi                : Application Family Identifier.
 *      pCID                : Two byte CID -> if marked in extended options.
 *      bBlockNo            : Block Number from where start reading.
 *      bNoOfBlocks         : Number of blocks to read.
 *
 * Output Parameters:
 *      pCDIDOut            : Received CID.
 *      pUid                : Received Uid.
 *      pUidLen             : Number of received UID bytes.
 *      pData               : Received data.
 *      pDataLen            : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_InventoryReadExtended(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags,
    uint8_t bAfi, uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bExtendedOptions, uint8_t * pCID, uint8_t bBlockNo,
    uint8_t bNoOfBlocks, uint8_t * pCDIDOut, uint8_t * pUid, uint8_t * pUidLen, uint8_t * pData, uint16_t * pDataLen);

/*
 * Perform ISO15693 FastInventoryRead command. When receiving the FAST INVENTORY READ command the ICODE IC behaves the
 * same as the INVENTORY READ command with the following exceptions: \n
 *
 * The data rate in the direction ICODE DNA IC to the interrogator is twice that defined in ISO/IEC 15693-3 depending on
 * the Datarate_flag 53 kbit (high data rate) or 13 kbit (low data rate).
 *
 * The data rate from the interrogator to the ICODE DNA IC and the time between the rising edge of the EOF from the
 * interrogator to the ICODE DNA IC remain unchanged (stay the same as defined in ISO/IEC 15693-3).
 *
 * In the ICODE DNA IC to the interrogator direction, only the single sub-carrier mode is supported.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bFlags              : Request flags byte.
 *                              0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                              0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                              0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                              0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                              0x10:   PHAL_ICODE_FLAG_SELECTED
 *                              0x10:   PHAL_ICODE_FLAG_AFI
 *                              0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                              0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                              0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi                : Application Family Identifier.
 *      pMask               : UID mask, holding known UID bits.
 *      bMaskBitLen         : Number of UID bits within pMask.
 *      bBlockNo            : Block number of first block to read.
 *      bNoOfBlocks         : Number of blocks to read.
 *
 * Output Parameters:
 *      pUid                : Received Uid.
 *      pUidLen             : Number of received UID bytes.
 *      pData               : Received data.
 *      pDataLen            : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_FastInventoryRead(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags, uint8_t bAfi,
    uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bBlockNo, uint8_t bNoOfBlocks, uint8_t * pUid, uint8_t * pUidLen,
    uint8_t * pData, uint16_t * pDataLen);

/*
 * Perform ISO15693 FastInventoryRead command. When receiving the FAST INVENTORY READ command the ICODE IC behaves the
 * same as the INVENTORY READ command with the following exceptions: \n
 *
 * The data rate in the direction ICODE DNA IC to the interrogator is twice that defined in ISO/IEC 15693-3 depending on
 * the Datarate_flag 53 kbit (high data rate) or 13 kbit (low data rate).
 *
 * The data rate from the interrogator to the ICODE DNA IC and the time between the rising edge of the EOF from the
 * interrogator to the ICODE DNA IC remain unchanged (stay the same as defined in ISO/IEC 15693-3).
 *
 * In the ICODE DNA IC to the interrogator direction, only the single sub-carrier mode is supported.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bFlags              : Request flags byte.
 *                              0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                              0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                              0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                              0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                              0x10:   PHAL_ICODE_FLAG_SELECTED
 *                              0x10:   PHAL_ICODE_FLAG_AFI
 *                              0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                              0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                              0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi                : Application Family Identifier.
 *      pMask               : UID mask, holding known UID bits.
 *      bMaskBitLen         : Number of UID bits within pMask.
 *      bBlockNo            : Block number of first block to read.
 *      bNoOfBlocks         : Number of blocks to read.
 *
 * Output Parameters:
 *      pUid                : Received Uid.
 *      pUidLen             : Number of received UID bytes.
 *      pData               : Received data.
 *      pDataLen            : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_FastInventoryReadExtended(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags,
    uint8_t bAfi, uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bExtendedOptions, uint8_t * pCID, uint8_t bBlockNo,
    uint8_t bNoOfBlocks, uint8_t * pCDIDOut, uint8_t * pUid, uint8_t * pUidLen, uint8_t * pData, uint16_t * pDataLen);

/*
 * This command enables the EAS mode if the EAS mode is not locked. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_SetEAS(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * This command disables the EAS mode if the EAS mode is not locked. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ResetEAS(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * This command locks the current state of the EAS mode and the EAS ID. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockEAS(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * This command returns the EAS sequence if the EAS mode is enabled.
 *
 * bOption disabled: bEasIdMaskLength and pEasIdValue are not transmitted, EAS Sequence is returned;
 * bOption enabled and bEasIdMaskLength = 0: EAS ID is returned;
 * bOption enabled and bEasIdMaskLength > 0: EAS Sequence is returned by ICs with matching pEasIdValue;
 *
 * If the EAS mode is disabled, the label remains silent.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Option flag;
 *                              PHAL_ICODE_OPTION_OFF
 *                                  EAS ID mask length and EAS ID value shall not be transmitted.
 *                                  If the EAS mode is enabled, the EAS response is returned from the ICODE IC.
 *                                  This configuration is compliant with the EAS command of the ICODE IC
 *                              PHAL_ICODE_OPTION_ON.
 *                                  Within the command the EAS ID mask length has to be transmitted to identify how
 *                                  many bits of the following EAS ID value are valid (multiple of 8-bits). Only those
 *                                  ICODE ICs will respond with the EAS sequence which have stored the corresponding
 *                                  data in the EAS ID configuration (selective EAS) and if the EAS Mode is set.
 *                                  If the EAS ID mask length is set to 0, the ICODE IC will answer with its EAS ID
 *      pEasIdValue         : EAS ID; 0, 8 or 16 bits; optional.
 *      bEasIdMaskLen       : 8 bits; optional.
 *
 * Input Parameters:
 *      ppEas               : EAS ID (16 bits) or EAS Sequence (256 bits).
 *      pEasLen             : Length of bytes available in ppEas buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_EASAlarm(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t * pEasIdValue, uint8_t bEasIdMaskLen, uint8_t ** ppEas, uint16_t * pEasLen);

/*
 * This command enables the password protection for EAS. The EAS password has to be transmitted before with
 * \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_PasswordProtectEAS(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * This command enables the password protection for AFI. The AFI password has to be transmitted before with
 * \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_PasswordProtectAFI(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * With this command, a new EAS identifier is stored in the corresponding configuration memory. If the EAS mode
 * is password protected the EAS password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pEasIdValue         : EAS ID; 16 bits.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WriteEAS_ID(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t * pEasIdValue);

/*
 * On this command, the label will respond with it's EPC data.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppEpc               : EPC data; 96 bits.
 *      pEpcLen             : Length of bytes available in ppEpc buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadEPC(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t ** ppEpc, uint16_t * pEpcLen);

/*
 * Performs GetNXPSystemInformation command. This command allows for retrieving the NXP system information value from the VICC.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppSystemInfo    : The NXP system information of the VICC.
 *      pSystemInfoLen  : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetNXPSystemInformation(phalICode_SamAV3_NonX_DataParams_t * pDataParams,
    uint8_t ** ppSystemInfo, uint16_t * pSystemInfoLen);

/*
 * Perform InventoryPageRead command. When receiving the Inventory Page Read request, the ICODE IC performs the same
 * as in the anti-collision sequence, with the difference that instead of the UID and the DSFID the requested memory content
 * is re-transmitted from the ICODE IC.
 *
 * If the Option flag is set to 0 N pages of data including page protection status (password protection condition) are
 * re-transmitted. If the option flag is set to 1 N pages (4 blocks = 16 byte) of data including page protection status
 * (password protection condition) and the part of the UID which is not part of the mask are re-transmitted.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bFlags          : Request flags byte.
 *                          0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                          0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                          0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                          0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                          0x10:   PHAL_ICODE_FLAG_SELECTED
 *                          0x10:   PHAL_ICODE_FLAG_AFI
 *                          0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                          0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                          0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi            : Application Family Identifier.
 *      pMask           : UID mask, holding known UID bits.
 *      bMaskBitLen     : Number of UID bits within pMask.
 *      bPageNo         : Block number of first page to read.
 *      bNoOfPages      : Number of pages to read.
 *
 * Output Parameters:
 *      ppUid           : Received Uid.
 *      pUidLen         : Number of received UID bytes.
 *      ppData          : Received data.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_InventoryPageRead(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags, uint8_t bAfi,
    uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bPageNo, uint8_t bNoOfPages, uint8_t ** ppUid, uint8_t * pUidLen,
    uint8_t ** ppData, uint16_t * pDataLen);

/*
 * Perform FastInventoryPageRead command.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bFlags              : Request flags byte.
 *                              0x01:   PHAL_ICODE_FLAG_TWO_SUB_CARRIERS
 *                              0x02:   PHAL_ICODE_FLAG_DATA_RATE
 *                              0x04:   PHAL_ICODE_FLAG_INVENTORY
 *                              0x08:   PHAL_ICODE_FLAG_PROTOCOL_EXTENSION
 *                              0x10:   PHAL_ICODE_FLAG_SELECTED
 *                              0x10:   PHAL_ICODE_FLAG_AFI
 *                              0x20:   PHAL_ICODE_FLAG_ADDRESSED
 *                              0x20:   PHAL_ICODE_FLAG_NBSLOTS
 *                              0x40:   PHAL_ICODE_FLAG_OPTION
 *      bAfi                : Application Family Identifier.
 *      pMask               : UID mask, holding known UID bits.
 *      bMaskBitLen         : Number of UID bits within pMask.
 *      bPageNo             : Block number of first page to read.
 *      bNoOfPages          : Number of pages to read.
 *
 * Output Parameters:
 *      ppUid               : Received Uid.
 *      pUidLen             : Number of received UID bytes.
 *      ppData              : Received data.
 *      pDataLen            : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_FastInventoryPageRead(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bFlags,
    uint8_t bAfi, uint8_t * pMask, uint8_t bMaskBitLen, uint8_t bPageNo, uint8_t bNoOfPages, uint8_t ** ppUid,
    uint8_t * pUidLen, uint8_t ** ppData, uint16_t * pDataLen);

/*
 * Performs a GetRandomNumber command. On this command, the label will respond with a random number.
 * The received random number shall be used to diversify the password for the \ref phalICode_SetPassword command.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppRnd               : Random number; 16 bits.
 *      ppRnd               : Number of bytes in ppRnd buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetRandomNumber(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t ** ppRnd,
    uint16_t * pRndLen);

/*
 * Perforns SetPassword command. With this command the different passwords can be transmitted to the label.
 *
 * This command has to be executed just once for the related passwords if the label is powered.
 *
 * \verbatim
 * [XOR password calculation example]
 * pXorPwd[0] = pPassword[0] ^ pRnd[0];
 * pXorPwd[1] = pPassword[1] ^ pRnd[1];
 * pXorPwd[2] = pPassword[2] ^ pRnd[0];
 * pXorPwd[3] = pPassword[3] ^ pRnd[1];
 * \endverbatim
 *
 * \b Remark: This command can only be executed in addressed or selected mode except of Privay Password.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier      : Password Identifier.
 *                              PHAL_ICODE_SET_PASSWORD_READ
 *                              PHAL_ICODE_SET_PASSWORD_WRITE
 *                              PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                              PHAL_ICODE_SET_PASSWORD_DESTROY
 *                              PHAL_ICODE_SET_PASSWORD_EAS
 *      pXorPwd             : XOR Password; 32 bits.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_SetPassword(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bPwdIdentifier, uint8_t * pXorPwd);
/*
 * Performs WritePassword command. With this command, a new password is written into the related memory. Note that the
 * old password has to be transmitted before with \ref phalICode_SetPassword. The new password takes effect immediately which
 * means that the new password has to be transmitted with \ref phalICode_SetPassword to get access to protected blocks/pages.
 * \b Remark: This command can only be executed in addressed or selected mode.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier      : Password Identifier.
 *                              PHAL_ICODE_SET_PASSWORD_READ
 *                              PHAL_ICODE_SET_PASSWORD_WRITE
 *                              PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                              PHAL_ICODE_SET_PASSWORD_DESTROY
 *                              PHAL_ICODE_SET_PASSWORD_EAS
 *      pPwd                : Plain Password; 32 bits
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WritePassword(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bPwdIdentifier, uint8_t * pPwd);
/*
 * Performs LockPassword command. This command locks the addressed password. Note that the addressed password
 * has to be transmitted before with \ref phalICode_SetPassword. A locked password can not be changed any longer.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier      : Password Identifier.
 *                              PHAL_ICODE_SET_PASSWORD_READ
 *                              PHAL_ICODE_SET_PASSWORD_WRITE
 *                              PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                              PHAL_ICODE_SET_PASSWORD_DESTROY
 *                              PHAL_ICODE_SET_PASSWORD_EAS
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockPassword(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bPwdIdentifier);
/*
 * Performs Page protection command. This command changes the protection status of a page. Note that the related
 * passwords have to be transmitted before with \ref phalICode_SetPassword if the page is not public.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPPAdd_PageNo       : Page number to be protected in case of products that do not have pages
 *                            characterized as high and Low.
 *                            Block number to be protected in case of products that have pages
 *                            characterized as high and Low.
 *      bProtectionStatus   : Protection status options for the products that do not have pages
 *                            characterized as high and Low.
 *                              0x00: PHAL_ICODE_PROTECT_PAGE_PUBLIC
 *                              0x01: PHAL_ICODE_PROTECT_PAGE_READ_WRITE_READ_PASSWORD
 *                              0x10: PHAL_ICODE_PROTECT_PAGE_WRITE_PASSWORD
 *                              0x11: PHAL_ICODE_PROTECT_PAGE_READ_WRITE_PASSWORD_SEPERATE
 *
 *                            Extended Protection status options for the products that have pages
 *                            characterized as high and Low.
 *                              0x01: PHAL_ICODE_PROTECT_PAGE_READ_LOW
 *                              0x02: PHAL_ICODE_PROTECT_PAGE_WRITE_LOW
 *                              0x10: PHAL_ICODE_PROTECT_PAGE_READ_HIGH
 *                              0x20: PHAL_ICODE_PROTECT_PAGE_WRITE_HIGH
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ProtectPage(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bPPAdd_PageNo, uint8_t bProtectionStatus);
/*
 * Perform LockPageProtectionCondition command. This command permanently locks the protection status of a page.
 * Note that the related passwords have to be transmitted before with \ref phalICode_SetPassword if the page is
 * not public.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPageNo             : Page number to be protected.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_LockPageProtectionCondition(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bPageNo);
/*
 * Perform GetMultipleBlockProtectionStatus command. This instructs the label to return the block protection
 * status of the requested blocks.
 *
 * Remark: If bBlockNo + bNumBlocks exceeds the total available number of user blocks, the number of received
 * status bytes is less than the requested number. This means that the last returned status byte corresponds to the
 * highest available user block.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bBlockNo            : First Block number.
 *      bNoOfBlocks         : Number of blocks.
 *
 * Output Parameters:
 *      pProtectionStates   : Protection states of requested blocks.
 *      pNumReceivedStates  : Number of received block protection states.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetMultipleBlockProtectionStatus(phalICode_SamAV3_NonX_DataParams_t * pDataParams,
    uint8_t bBlockNo, uint8_t bNoOfBlocks, uint8_t * pProtectionStates, uint16_t * pNumReceivedStates);

/*
 * Performs Destroy command. This command permanently destroys the label.
 *
 * The Destroy password has to be transmitted before with \ref phalICode_SetPassword.
 * Remark: This command is irreversible and the label will never respond to any command again.
 * Remark: This command can only be executed in addressed or selected mode.
 *
 * Note: This command is not valid for ICode Dna product as the Destroy feature is part of Mutual
 * Authentication command (refer \ref phalICode_AuthenticateMAM).
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pXorPwd             : XOR Password; 32 bits. Pass the password for the ICODE products that supports and NULL
 *                            for the products that do not support.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_Destroy(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t * pXorPwd);

/*
 * Performs EnablePrivacy command. This command instructs the label to enter privacy mode.
 *
 * In privacy mode, the label will only respond to \ref phalSli_GetRandomNumber and \ref phalICode_SetPassword commands.
 * To get out of the privacy mode, the Privacy password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Note: This command is not valid for ICode Dna product as the Destroy feature is part of Mutual
 * Authentication command (refer \ref phalICode_AuthenticateMAM).
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pXorPwd             : XOR Password; 32 bits. Pass the password for the ICODE products that supports and NULL
 *                            for the products that do not support.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_EnablePrivacy(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t * pXorPwd);

/*
 * Perform 64-BitPasswordProtection command. This instructs the label that both of the Read and Write passwords
 * are required for protected access.
 *
 * Note that both the Read and Write passwords have to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_64BitPasswordProtection(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption);

/*
 * When receiving the STAY QUIET PERSISTENT command, the label IC enters the persistent quiet state and
 * will not send back a response.
 *
 * Remark: The STAY QUIET PERSISTENT command provides the same behavior as the mandatory STAY QUIET command
 * with the only difference at a reset (power off). The label IC will turn to the ready state, if the power off
 * time is exceeding the persistent time.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_StayQuietPersistent(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/*
 * Performs ReadSignature command. On this command, the label will respond with the signature value.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppSign              : The originality signature returned by the VICC.
 *      ppSign              : Length of originality signature buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadSignature(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t ** ppSign,
    uint16_t * pSignLen);

/*
 * Reads a multiple 4 byte(s) data from the mentioned configuration block address. Here the starting address of the
 * configuration block should be given in the parameter bBlockAddr and the number of blocks to read from the starting
 * block should be given in the parameter bNoOfBlocks.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bBlockAddr          : Configuration block address.
 *      bNoOfBlocks         : The n block(s) to read the configuration data.
 *
 * Output Parameters:
 *      ppData              : Multiple of 4 (4u * No Of Blocks) byte(s) of data read from the mentioned
 *                            configuration block address.
 *      pDataLen            : Number of received configuration data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadConfig(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bBlockAddr,
    uint8_t bNoOfBlocks, uint8_t ** ppData, uint16_t * pDataLen);
/*
 * Writes a 4 byte data to the mentioned configuration block address.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bBlockAddr          : Configuration block address.
 *      pData               : A 4 byte data to be written to the mentioned configuration block address.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_WriteConfig(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption,
    uint8_t bBlockAddr, uint8_t * pData);

/*
 * Enables the random ID generation in the tag. This interfaces is used to instruct the tag to generate
 * a random number in privacy mode.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_PickRandomID(phalICode_SamAV3_NonX_DataParams_t * pDataParams);

/**
 * \brief Provides the tag tamper status.
 *
 * Flag can be set using \ref phalICode_SetConfig "SetConfig" utility interface
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If any of the DataParams are null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *          - If the buffers are null.
 *          - For the option values that are not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalICode_Sam_NonX_ReadTT(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppResponse,
    uint16_t * pRspLen);

/*
 * Performs Parameter Request command. When receiving VICC PARAMETER REQUEST, PLUTUS returns all supported bit rates
 * and timing information.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      pBitRate            : One byte buffer containing the supported bitrates.
 *                              0x00: PHAL_ICODE_PARAMETERS_BITRATE_26KBPS_BOTH_DIRECTIONS
 *                              0x01: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VCD_VICC
 *                              0x02: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VCD_VICC
 *                              0x04: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VCD_VICC
 *                              0x10: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VICC_VCD
 *                              0x20: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VICC_VCD
 *                              0x40: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VICC_VCD
 *      pTiming             : One byte buffer containing the supported bitrates.
 *                              0x00: PHAL_ICODE_PARAMETERS_TIMING_320_9_US
 *                              0x01: PHAL_ICODE_PARAMETERS_TIMING_160_5_US
 *                              0x02: PHAL_ICODE_PARAMETERS_TIMING_80_2_US
 *                              0x04: PHAL_ICODE_PARAMETERS_TIMING_SAME_BOTH_DIRECTIONS
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ParameterRequest(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pBitRate,
    uint8_t * pTiming);

/*
 * Performs Parameter Select command. PARAMETER SELECT command is used to activate one bit rate combination and the T1
 * timing indicated in PARAMETER REQUEST response. Only one option in each direction shall be chosen. After the response to PARAMETER
 * SELECT command, new parameters are valid.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      bBitRate            : One byte buffer containing the supported bitrates.
 *                              0x00: PHAL_ICODE_PARAMETERS_BITRATE_26KBPS_BOTH_DIRECTIONS
 *                              0x01: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VCD_VICC
 *                              0x02: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VCD_VICC
 *                              0x04: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VCD_VICC
 *                              0x10: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VICC_VCD
 *                              0x20: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VICC_VCD
 *                              0x40: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VICC_VCD
 *      bTiming             : One byte buffer containing the supported bitrates.
 *                              0x00: PHAL_ICODE_PARAMETERS_TIMING_320_9_US
 *                              0x01: PHAL_ICODE_PARAMETERS_TIMING_160_5_US
 *                              0x02: PHAL_ICODE_PARAMETERS_TIMING_80_2_US
 *                              0x04: PHAL_ICODE_PARAMETERS_TIMING_SAME_BOTH_DIRECTIONS
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ParameterSelect(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bBitRate,
    uint8_t bTiming);

/*
 * Performs a SRAM Read command.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo        : Block number from where the data to be read.
 *      bNumBlocks      : Total number of block to read.
 *
 * Output Parameters:
 *      pData           : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen        : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_ReadSRAM(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bBlockNo,
    uint8_t bNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Performs a SRAM Write command. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bOption         : Option flag.
 *                          0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                         starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                         (302 us) with a total tolerance of 32/fc and latest after 20 ms upon detection
 *                                                         of the rising edge of the EOF of the VCD request.)
 *                          0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      bBlockNo        : Block number from where the data should be written.
 *      bNumBlocks      : Total number of block to be written.
 *      pData           : Information to be written to VICC.
 *      wDataLen        : Number of data bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */

phStatus_t phalICode_Sam_NonX_WriteSRAM(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint8_t bBlockNo,
    uint8_t bNumBlocks, uint8_t * pData, uint16_t wDataLen);

/*
 * Performs a I2CM Read command. This command is used to read from any I2C slave connected to Plutus I2C Host.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bAddr_Config    : I2C Slave address from which the data should be read and the information
 *                        to set the Stop bit.
 *                          Bits 0 - 6: Is for slave address. Its 7 bit address.
 *                          Bit 7     : Configuration Bit
 *                                      0b: Generate stop condition
 *                                      1b: Don't generate stop condition
 *      bDataLen        : Total Number of data bytes to be read. If 1 byte has to be read then the
 *                        length will be 1.
 *
 * Output Parameters:
 *      pData           : Information to be read from the VICC.

 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_I2CMRead (phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bI2CParam, uint16_t wDataLen,
    uint8_t * pData);
/*
 * Performs a I2CM Write command. This command is used to write to any I2C slave connected to Plutus I2C Host.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      bAddr_Config    : I2C Slave address to which the data should be written and the information
 *                        to set the Stop bit.
 *                          Bits 0 - 6: Is for slave address. Its 7 bit address.
 *                          Bit 7     : Configuration Bit
 *                                      0b: Generate stop condition
 *                                      1b: Don't generate stop condition
 *      pData           : Information to be written to the VICC.
 *      bDataLen        : Total Number of data bytes to be written. If 1 byte has to be written then the
 *                        length will be 1.

 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_I2CMWrite (phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bI2CParam, uint8_t * pData,
    uint16_t wDataLen);
/*
 * Gets the UID of the tag.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      ppUid           : 8 byte UID of the tag.
 *      pUidLen         : Length of the UID buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetSerialNo(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t ** ppUid,
    uint16_t * pUidLen);

/*
 * Sets the UID of the tag.
 *
 * Input Parameters:
 *      pDataParams     : Pointer to this layer's parameter structure.
 *      pUid            : 8 byte UID of the tag.
 *      bUidLen         : Length of the UID buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_SetSerialNo(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pUid, uint8_t bUidLen);

/*
 * Get the configuration settings.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      wConfig             : Configuration to read.
 *                              0x00: PHAL_ICODE_CONFIG_FLAGS
 *                              0x01: PHAL_ICODE_CONFIG_ADD_INFO
 *                              0x02: PHAL_ICODE_CONFIG_TIMEOUT_US
 *                              0x03: PHAL_ICODE_CONFIG_TIMEOUT_MS
 *                              0x04: PHAL_ICODE_CONFIG_ENABLE_BUFFERING
 *
 * Output Parameters:
 *      pValue              : The value for the mentioned configuration information in wConfig parameter.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetConfig(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

/*
 * Set the configuration settings.
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *      wConfig             : Configuration to write.
 *                              0x00: PHAL_ICODE_CONFIG_FLAGS
 *                              0x04: PHAL_ICODE_CONFIG_ENABLE_BUFFERING
 *      wValue              : The value for the mentioned configuration information in wConfig parameter.
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_SetConfig(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

/*
 * Get the type of Tag
 *
 * Input Parameters:
 *      pDataParams         : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      pTagType            : The type of ICode tag.
 *                              0xFFFF: PHAL_ICODE_TAG_TYPE_UNKNOWN
 *                              0x0001: PHAL_ICODE_TAG_TYPE_ICODE_SLI
 *                              0x0002: PHAL_ICODE_TAG_TYPE_ICODE_SLI_S
 *                              0x0003: PHAL_ICODE_TAG_TYPE_ICODE_SLI_L
 *                              0x5001: PHAL_ICODE_TAG_TYPE_ICODE_SLIX
 *                              0x5002: PHAL_ICODE_TAG_TYPE_ICODE_SLIX_S
 *                              0x5003: PHAL_ICODE_TAG_TYPE_ICODE_SLIX_L
 *                              0x0801: PHAL_ICODE_TAG_TYPE_ICODE_SLI_X2
 *                              0x1801: PHAL_ICODE_TAG_TYPE_ICODE_DNA
 *                              0x5801: PHAL_ICODE_TAG_TYPE_ICODE_PLUTUS
 *
 * Return:
 *          PH_ERR_SUCCESS for successful operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Sam_NonX_GetTagType(phalICode_SamAV3_NonX_DataParams_t * pDataParams, uint16_t * pTagType);

#endif /* NXPBUILD__PHAL_ICODE_SAM_NONX */
#endif /* PHALICODE_SAM_NONX_H */
