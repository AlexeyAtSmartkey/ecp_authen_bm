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
 * $Date: 2021-02-24 $
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
#include "PN76_Eccalt.h"
#include "PN76_Eddsaalt.h"
#include "ecc_alt.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Global Static variables
 ****************************************************************************/
uint8_t aprivkey[48];
uint8_t apubkey[48*2];
uint8_t sigr[48];
uint8_t sigs[48];
uint8_t sharedsecret[48*2];

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/*****************************************************************************
 * Private functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Global functions implementation
 ****************************************************************************/
/*
 * Generate key pair, wrapper for conventional base point
 */
int mbedtls_ecp_gen_keypair( mbedtls_ecp_group *grp, mbedtls_mpi *d,
                             mbedtls_ecp_point *Q,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    int ret;
    uint8_t buflen;

    if ((grp == NULL) ||  (d == NULL) || (Q == NULL) || (f_rng != NULL) || (p_rng != NULL))
    {
       return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((grp->id == MBEDTLS_ECP_DP_BP256R1) || (grp->id == MBEDTLS_ECP_DP_SECP256R1))
    {
       buflen = 32;
    }
    else if ((grp->id == MBEDTLS_ECP_DP_BP384R1) || (grp->id == MBEDTLS_ECP_DP_SECP384R1))
    {
       buflen = 48;
    }
    else
    {
       return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ret = mbedtls_ecp_gen_keypair_stz(grp, aprivkey, apubkey);
    if (ret == 0)
    {
       /*Convert */
       ret = mbedtls_mpi_read_binary(d,aprivkey,buflen);
       if (ret == 0)
       {
          ret = mbedtls_mpi_read_binary(&Q->X,apubkey,buflen);
          if (ret == 0)
          {
             ret = mbedtls_mpi_read_binary(&Q->Y,((uint8_t*)apubkey+buflen),buflen);
             if (ret == 0)
             {
                ret = mbedtls_mpi_lset(&Q->Z,1);
             }
          }
       }
    }

    return ret;
}

int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
      int ret = -1;
      mbedtls_ecdsa_sign_stz_params_t mbedtls_ecdsa_sign_stz_params;
      uint8_t buflen;
      uint8_t *pPrivateKey;

      if ((grp == NULL) || (r == NULL) || (s == NULL) || (buf == NULL) || (f_rng != NULL) || (p_rng != NULL))
      {
         return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      }

      if ((grp->id == MBEDTLS_ECP_DP_BP256R1) || (grp->id == MBEDTLS_ECP_DP_SECP256R1))
      {
         buflen = 32;
      }
      else if ((grp->id == MBEDTLS_ECP_DP_BP384R1) || (grp->id == MBEDTLS_ECP_DP_SECP384R1))
      {
         buflen = 48;
      }
      else
      {
         return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
      }

      if(d != NULL)
      {
         ret = mbedtls_mpi_write_binary(d,aprivkey,buflen);
         pPrivateKey = &aprivkey[0];
      }
      else
      {
    	  ret = 0;
    	  pPrivateKey = NULL;
      }
      if (ret == 0)
      {
         mbedtls_ecdsa_sign_stz_params.grp = grp;
         mbedtls_ecdsa_sign_stz_params.sig_r = sigr;
         mbedtls_ecdsa_sign_stz_params.sig_s = sigs;
         mbedtls_ecdsa_sign_stz_params.privkey = pPrivateKey;
         mbedtls_ecdsa_sign_stz_params.buf = buf;
         mbedtls_ecdsa_sign_stz_params.blen = blen;
         ret = mbedtls_ecdsa_sign_stz(&mbedtls_ecdsa_sign_stz_params);
         if (ret == 0)
         {
            ret = mbedtls_mpi_read_binary(r,sigr,buflen);
            if (ret == 0)
            {
               ret = mbedtls_mpi_read_binary(s,sigs,buflen);
            }
         }
      }

      return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
    int ret;
    uint8_t buflen;

    if ((grp == NULL) || (r == NULL) || (s == NULL) || (Q == NULL) || (buf == NULL))
    {
       return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((grp->id == MBEDTLS_ECP_DP_BP256R1) || (grp->id == MBEDTLS_ECP_DP_SECP256R1))
    {
       buflen = 32;
    }
    else if ((grp->id == MBEDTLS_ECP_DP_BP384R1) || (grp->id == MBEDTLS_ECP_DP_SECP384R1))
    {
       buflen = 48;
    }
    else
    {
       return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_ecdsa_verify_stz_params_t mbedtls_ecdsa_verify_stz_params;

    ret = mbedtls_mpi_write_binary(&Q->X,apubkey,buflen);
    if (ret == 0)
    {
       ret = mbedtls_mpi_write_binary(&Q->Y,&apubkey[buflen],buflen);
       if (ret == 0)
       {
          ret = mbedtls_mpi_write_binary(r,sigr,buflen);
          if (ret == 0)
          {
             ret = mbedtls_mpi_write_binary(s,sigs,buflen);
             if (ret == 0)
             {
               mbedtls_ecdsa_verify_stz_params.grp = grp;
               mbedtls_ecdsa_verify_stz_params.sig_r = sigr;
               mbedtls_ecdsa_verify_stz_params.sig_s = sigs;
               mbedtls_ecdsa_verify_stz_params.pubkey = apubkey;
               mbedtls_ecdsa_verify_stz_params.buf = buf;
               mbedtls_ecdsa_verify_stz_params.blen = blen;
               ret = mbedtls_ecdsa_verify_stz(&mbedtls_ecdsa_verify_stz_params);
             }
          }
       }
    }
    return ret;
}

int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                 const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng )
{
   int ret = -1;
   mbedtls_ecdh_stz_params_t mbedtls_ecdh_stz_params;
   uint8_t buflen;
   uint8_t *pPrivateKey;

   /* please note that d i.e. private key is not being checked for NULL
    * since it can be NULL if the key index is provided */
   if ((grp == NULL) || (z == NULL) || (Q == NULL) || (f_rng != NULL) || (p_rng != NULL))
   {
      return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
   }

   if ((grp->id == MBEDTLS_ECP_DP_BP256R1) || (grp->id == MBEDTLS_ECP_DP_SECP256R1))
   {
      buflen = 32;
   }
   else if ((grp->id == MBEDTLS_ECP_DP_BP384R1) || (grp->id == MBEDTLS_ECP_DP_SECP384R1))
   {
      buflen = 48;
   }
   else
   {
      return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
   }
   if(d != NULL)
   {
      ret = mbedtls_mpi_write_binary(d,aprivkey,buflen);
      pPrivateKey = &aprivkey[0];
   }
   else
   {
	   ret = 0;
	   pPrivateKey = NULL;
   }
   if (ret == 0)
   {
      ret = mbedtls_mpi_write_binary(&Q->X,apubkey,buflen);
      if (ret == 0)
      {
         ret = mbedtls_mpi_write_binary(&Q->Y,&apubkey[buflen],buflen);
         if (ret == 0)
         {
            mbedtls_ecdh_stz_params.grp = grp;
            mbedtls_ecdh_stz_params.pubKey = apubkey;
            mbedtls_ecdh_stz_params.privKey = pPrivateKey;
            mbedtls_ecdh_stz_params.sharedSecret = sharedsecret;
            ret = mbedtls_ecdh_compute_shared_stz(&mbedtls_ecdh_stz_params);
            if (ret == 0)
            {
               ret = mbedtls_mpi_read_binary(z,sharedsecret,buflen);
            }
         }
      }
   }

   return ret;
}

int phmbedcrypto_Get_AsymmPubKey(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q)
{
   int ret = -1;
   uint8_t buflen;
   uint8_t *pPrivateKey;

   if ((grp == NULL) || (Q == NULL))
   {
      return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
   }

   if ((grp->id == MBEDTLS_ECP_DP_BP256R1) || (grp->id == MBEDTLS_ECP_DP_SECP256R1))
   {
      buflen = 32;
   }
   else if ((grp->id == MBEDTLS_ECP_DP_BP384R1) || (grp->id == MBEDTLS_ECP_DP_SECP384R1))
   {
      buflen = 48;
   }
   else
   {
      return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
   }

   if(d != NULL)
   {
      ret = mbedtls_mpi_write_binary(d,aprivkey,buflen);
      pPrivateKey = &aprivkey[0];
   }
   else
   {
	   ret = 0;
	   pPrivateKey = NULL;
   }
   if (ret == 0)
   {
      ret = mbedtls_get_asymmpubkey_stz(grp, pPrivateKey, apubkey);
      if (ret == 0)
      {
         ret = mbedtls_mpi_read_binary(&Q->X,apubkey,buflen);
         if (ret == 0)
         {
            ret = mbedtls_mpi_read_binary(&Q->Y,((uint8_t*)apubkey+buflen),buflen);
            if (ret == 0)
            {
               ret = mbedtls_mpi_lset(&Q->Z,1);
            }
         }
      }
   }

   return ret;
}

/*****************************************************************************
 * Private functions
 ****************************************************************************/
