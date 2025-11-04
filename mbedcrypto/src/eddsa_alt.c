/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
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
 * This file contains the interfaces for applications to use the cryptolib via mbedtls
 * $Author: NXP $
 * $Revision: $
 * $Date: 2020-11-4 $
 *
 * History:
 *
 */

/** Revision History:
 * # _____________________________________________________________________________
 * #
 * # 00.01.00         : Initial implementation
 * #                  : - <details about changes in this version>
 * # _____________________________________________________________________________
 */

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "ph_Datatypes.h"
#include "string.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/

#include "eddsa_alt.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Global Static variables
 ****************************************************************************/


/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Private functions declaration
 ****************************************************************************/


/*****************************************************************************
 * Global functions implementation
 ****************************************************************************/

int phmbedcrypto_EdDSA_KeyGen(uint8_t  privkeyindex, uint8_t *pEncPublicKeyTwEd ,uint8_t *pPrivateKey, uint8_t *pPrivateKeyHash,
            uint8_t *pSubPrivateKey, phmbedcrypto_eddsa_keygen_option_t phmbedcrypto_eddsa_keygen_option,
            phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option)
{
   phmbedcrypto_eddsa_keygen_params_t Eddsa_keygen;
   Eddsa_keygen.privkeyindex = privkeyindex;
   Eddsa_keygen.pEncPublicKeyTwEd = pEncPublicKeyTwEd;
   Eddsa_keygen.pPrivateKey = pPrivateKey;
   Eddsa_keygen.pPrivateKeyHash = pPrivateKeyHash;
   Eddsa_keygen.pSubPrivateKey = pSubPrivateKey;
   Eddsa_keygen.phmbedcrypto_eddsa_keygen_option = phmbedcrypto_eddsa_keygen_option;
   Eddsa_keygen.phmbedcrypto_eddsa_hash_option = phmbedcrypto_eddsa_hash_option;

   return phmbedcrypto_EdDSA_KeyGen_stz(&Eddsa_keygen);
}

int phmbedcrypto_EdDSA_Sign(uint8_t *pDigest, uint32_t digestlength, uint8_t *pEncPublicKeyTwEd, uint8_t *pPrivateKey,
            uint8_t *pSigR, uint8_t *pSigS, MPInt_t *pcontextstring,
            phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option, phmbedcrypto_eddsa_sign_option_t phmbedcrypto_eddsa_sign_option, uint8_t privkeyindex)
{
   phmbedcrypto_eddsa_sign_params_t Eddsa_sign;

   if(pPrivateKey == NULL)
   {
      Eddsa_sign.privkeyindex = privkeyindex;
   }

   Eddsa_sign.pDigest = pDigest;
   Eddsa_sign.digestlength = digestlength;
   Eddsa_sign.pEncPublicKeyTwEd = pEncPublicKeyTwEd;
   Eddsa_sign.pPrivateKey = pPrivateKey;
   Eddsa_sign.pSigR = pSigR;
   Eddsa_sign.pSigS = pSigS;
   Eddsa_sign.pcontextstring = pcontextstring;
   Eddsa_sign.phmbedcrypto_eddsa_hash_option = phmbedcrypto_eddsa_hash_option;
   Eddsa_sign.phmbedcrypto_eddsa_sign_option = phmbedcrypto_eddsa_sign_option;

   return phmbedcrypto_EdDSA_Sign_stz(&Eddsa_sign);
}

int phmbedcrypto_EdDSA_Verify(uint8_t *pDigest, uint32_t digestlength , MPInt_t *pcontextString, uint8_t *pPublickey, uint8_t *pSigR, uint8_t *pSigS)
{
   phmbedcrypto_eddsa_verify_params_t phmbedcrypto_eddsa_verify_params;

   phmbedcrypto_eddsa_verify_params.pDigest = pDigest;
   phmbedcrypto_eddsa_verify_params.digestlength = digestlength;
   phmbedcrypto_eddsa_verify_params.pcontextstring = pcontextString;
   phmbedcrypto_eddsa_verify_params.pPublickey = pPublickey;
   phmbedcrypto_eddsa_verify_params.pSigR = pSigR;
   phmbedcrypto_eddsa_verify_params.pSigS = pSigS;

   return phmbedcrypto_EdDSA_Verify_stz(&phmbedcrypto_eddsa_verify_params);
}

int phmbedcrypto_EdDSA_MontDhKeyGen(uint8_t *pPublicKey, uint8_t *pPrivateKey)
{
   phmbedcrypto_eddsa_MontDhKeyGen_Param_t Eddsa_MontDhKeyGen;

   Eddsa_MontDhKeyGen.pPublicKey = pPublicKey;
   Eddsa_MontDhKeyGen.pPrivateKey = pPrivateKey;

   return phmbedcrypto_EdDSA_MontDhKeyGen_stz(&Eddsa_MontDhKeyGen);

}
int phmbedcrypto_EdDSA_MontDhKeyExchange(uint8_t *pPublicKey, uint8_t *pPrivateKey, uint8_t *pCommonSecret, uint8_t privkeyindex)
{
   phmbedcrypto_eddsa_MontDhKeyExchange_Param_t Eddsa_MontDhKeyExchange;

   if(pPrivateKey == NULL)
   {
      Eddsa_MontDhKeyExchange.privkeyindex = privkeyindex;
   }

   Eddsa_MontDhKeyExchange.pPublicKey = pPublicKey;
   Eddsa_MontDhKeyExchange.pPrivateKey = pPrivateKey;
   Eddsa_MontDhKeyExchange.pCommonSecret = pCommonSecret;

   return phmbedcrypto_EdDSA_MontDhKeyExchange_stz(&Eddsa_MontDhKeyExchange);
}

