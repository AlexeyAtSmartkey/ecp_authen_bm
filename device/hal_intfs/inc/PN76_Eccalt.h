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
/* Copyright 2021-2023 NXP                                                    */
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


/** @file
 * This file contains the interfaces for applications to use the cryptolib via mbedtls
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */


#ifndef PN76_ECCALT_H_
#define PN76_ECCALT_H_

/** @addtogroup PN76SYSASYMMETRICECC
 *
 * @brief System Service ECC API's
 *
 * This module briefs about the implementation of various ECC Algorithms.
 *
 
 * \section PN76SYSASYMMETRICECC_NOTE Note regarding the use of the ECC private keys stored in hardware keystore
	If ECC private keys stored in hardware keystore to be used for signing, only
	\ref SKM_KEY_TYPE_APP_ASYMM  must be used. This key must be provisioned before using it by \ref PN76SYSHALSKM APIs.
	
 *
 * @{
 *
 */
/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
#include "bignum.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/
/*
 * ECP error codes
 */
#define MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_ECP_HW_ACCEL_FAILED                   -0x4B80  /**< The ECP hardware accelerator failed. */
#define MBEDTLS_ERR_ECP_VERIFY_FAILED                     -0x4E00  /**< The signature is not valid. */
/*
 * ASYMM PUB KEY error codes
 */
#define MBEDTLS_ERR_ASYMM_PUB_KEY_BAD_INPUT_DATA          -0x6F80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_ASYMM_PUB_KEY_HW_ACCEL_FAILED         -0x6B80  /**< The ASYMM_PUB_KEY hardware accelerator failed. */
/*
 * EDDSA error codes
 */
#define MBEDTLS_ERR_EDDSA_BAD_INPUT_DATA                  -0x7F80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_EDDSA_HW_ACCEL_FAILED                 -0x7B80  /**< The EDDSA hardware accelerator failed. */
#define MBEDTLS_ERR_EDDSA_KEYGEN_FAILED                   -0x7EC0  /**< Received PH_ERR_CLTWEDMONTGFP_KEYGEN_NOT_OK error. */
#define MBEDTLS_ERR_EDDSA_SIGN_FAILED                     -0x7EE0  /**< Received PH_ERR_CLTWEDMONTGFP_SIGN_NOT_OK error. */
#define MBEDTLS_ERR_EDDSA_VERIFY_FAILED                   -0x7E00  /**< Received PH_ERR_CLTWEDMONTGFP_EDDSAVERIFY_NOT_OK error. */
#define MBEDTLS_ERR_EDDSA_MONTDH_KEYGEN_FAILED            -0x7ED0  /**< Received PH_ERR_CLTWEDMONTGFP_KEYGEN_NOT_OK error. */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*!
 * @brief           The ECP point structure, in Jacobian coordinates.
 *
 * \note            All functions expect and return points satisfying
 *                  the following condition: <code>Z == 0</code> or
 *                  <code>Z == 1</code>. Other values of \p Z are
 *                  used only by internal functions.
 *                  The point is zero, or "at infinity", if <code>Z == 0</code>.
 *                  Otherwise, \p X and \p Y are its standard (affine)
 *                  coordinates.
 */
typedef struct mbedtls_ecp_point
{
    mbedtls_mpi X;          /*!< The X coordinate of the ECP point. */
    mbedtls_mpi Y;          /*!< The Y coordinate of the ECP point. */
    mbedtls_mpi Z;          /*!< The Z coordinate of the ECP point. */
}
mbedtls_ecp_point;


/*!
 * Domain-parameter identifiers: curve, subgroup, and generator.
 *
 * \note Only curves over prime fields are supported.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only standardized domain parameters from trusted
 * sources should be used. See mbedtls_ecp_group_load().
 */
/* Note: when adding a new curve:
 * - Add it at the end of this enum, otherwise you'll break the ABI by
 *   changing the numerical value for existing curves.
 * - Increment MBEDTLS_ECP_DP_MAX below if needed.
 * - Add the corresponding MBEDTLS_ECP_DP_xxx_ENABLED macro definition to
 *   config.h.
 * - List the curve as a dependency of MBEDTLS_ECP_C and
 *   MBEDTLS_ECDSA_C if supported in check_config.h.
 * - Add the curve to the appropriate curve type macro
 *   MBEDTLS_ECP_yyy_ENABLED above.
 * - Add the necessary definitions to ecp_curves.c.
 * - Add the curve to the ecp_supported_curves array in ecp.c.
 * - Add the curve to applicable profiles in x509_crt.c if applicable.
 */
typedef enum
{
    MBEDTLS_ECP_DP_NONE = 0,       /*!< Curve not defined. */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    MBEDTLS_CUSTOM_DP,             /*!< Domain parameters for a custom curve. */
    MBEDTLS_EDDSA_256,             /*!< Domain parameters for 256-bit EDDSA curve. */
    MBEDTLS_EDDSA_MONTDH25519_256,      /*!< Domain paramters for 256-bit EDDSA MONTDH 25519 */
} mbedtls_ecp_group_id;


/*!
 * @brief           The ECP group structure.
 *
 */
typedef struct mbedtls_ecp_group
{
    mbedtls_ecp_group_id id;    /*!< An internal group identifier. */
    uint8_t          privkeyindex;/*!< The key index will be used to fetch internal private key from key store
                                       when the private key is not provided.
									   
									   \note If private key stored in hardware key store is required for any asymmetric key operations, only the key index of \ref SKM_KEY_TYPE_APP_ASYMM must be used.
									   \note Asymmetric private key must be proivisioned using the \ref PN76SYSHALSKM
								   */
    uint16_t         wconfig; /*!<RFU */

    /* Added the domain parameters here, this is according to the mbedTLS way, however the data types of the domain
     * parameters vary from the mbedTLS, this nees to be taken care once the whole mbedTLS get merged into */
    uint8_t* P;              /*!< The prime modulus of the base field. */
    uint16_t pLength;        /*!< Prime modulus length */
    uint8_t* A;              /*!< For Short Weierstrass: \p A in the equation. For
                                     Montgomery curves: <code>(A + 2) / 4</code>. */
    uint8_t* B;              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    uint8_t* G;        /*!< The generator of the subgroup used. */
    uint8_t* N;              /*!< The order of \p G. */
    uint16_t nLength;        /*!< The order N length */
    uint8_t *pPrecomputedPointsGeneration;          /**< \brief Pointer to memory area, where coordinates of pre-computed base points for ECDSA Key and Signature Generation stored */
    uint8_t *pPrecomputedPointsVerification;        /**< \brief Pointer to memory area, where coordinates of pre-computed points for ECDSA Signature Verification stored */

}
mbedtls_ecp_group;

/*!
 * @brief           The ecdsa signature generation structure.
 *
 */
typedef struct mbedtls_ecdsa_sign_stz_params
{
   mbedtls_ecp_group *grp; /*!< An internal identifier. */
   uint8_t *sig_r;         /*!< Pointer holding signature r component */
   uint8_t *sig_s;         /*!< Pointer holding signature s component */
   uint8_t *privkey;       /*!< Pointer holding private key, if this is NULL then a private key index needs to be
                                provided to fetch the private key from the hardware keystore */
   const uint8_t *buf; /*!< Pointer holding the message buffer */
   size_t blen;              /*!< Length of the message */
}mbedtls_ecdsa_sign_stz_params_t;

/*!
 * @brief           The ecdsa signature verification structure.
 *
 */
typedef struct mbedtls_ecdsa_verify_stz_params
{
   mbedtls_ecp_group *grp;   /*!< An internal identifier. */
   const uint8_t *buf; /*!< Pointer holding the message Digest buffer */
   size_t blen;              /*!< Length of the message */
   uint8_t *pubkey;          /*!< Pointer holding the public key */
   uint8_t *sig_r;           /*!< Pointer holding signature r component */
   uint8_t *sig_s;           /*!< Pointer holding signature s component */
}mbedtls_ecdsa_verify_stz_params_t;

/*!
 * @brief           The ECDH share secret generation structure.
 *
 */
typedef struct mbedtls_ecdh_stz_params
{
   mbedtls_ecp_group *grp;   /*!< Has curve parameter index and private key index */
   uint8_t *sharedSecret;    /*!< Output parameter contains the shared secret pointer */
   uint8_t *pubKey;          /*!< Public key of the other party */
   uint8_t *privKey;         /*!< Our Private key, or NULL in case a private key stored in hardware key store to be used */
}mbedtls_ecdh_stz_params_t;

/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*!
 * @brief           This function generates an ECP keypair.
 *
 *
 * \param grp       The ECP group to generate a key pair for and must be
 *                  initialized
 * \param privkey   Destination raw binary data(secret part)
 * \param pubkey    Destination raw binary data(public part)
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int32_t mbedtls_ecp_gen_keypair_stz(mbedtls_ecp_group *grp, uint8_t *privkey, uint8_t *pubkey);

/*!
 * @brief           This function computes the ECDSA signature of a
 *                  previously-hashed message.
 *
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated
 *                  as defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \param mbedtls_ecdsa_sign_stz_params  The structure holding the input and output params
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 * \note           If private key stored in hardware key store to be used, then value in \ref mbedtls_ecdsa_sign_stz_params_t.privKey must be NULL.
				   \n The value in \ref mbedtls_ecdsa_sign_stz_params_t.grp.privkeyindex must contain the key index of private key (only APP_ASYMM_KEY) stored in hardware key store.
                   \n The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSASYMMETRICECC_NOTE
 */
int32_t mbedtls_ecdsa_sign_stz(mbedtls_ecdsa_sign_stz_params_t *mbedtls_ecdsa_sign_stz_params);

/*!
 * @brief           This function verifies the ECDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \param mbedtls_ecdsa_verify_stz_params  The structure holding the input and output params
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_VERIFY_FAILED  if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int32_t mbedtls_ecdsa_verify_stz(mbedtls_ecdsa_verify_stz_params_t *mbedtls_ecdsa_verify_stz_params);

/*!
 * @brief           This function gets the public key corresponding to the private key provided.
 *
 *
 * \param grp       The ECP group to generate a Public key for
 *                  must be initialized
 * \param privkey   Source raw binary data(secret part)
 *                  NULL to get private key from key store
 * \param pubkey    Destination raw binary data(public part)
 *
 * \return          \c 0 on success.
 * \return          1 on failure
 *
 
 * \note           If private key stored in hardware key store to be used, then value in parameter \b privkey must be NULL.
				   \n The value in \ref mbedtls_ecp_group.privkeyindex must contain the key index of private key (only APP_ASYMM_KEY) stored in hardware key store.
                   \n The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSASYMMETRICECC_NOTE
 
 */
int32_t mbedtls_get_asymmpubkey_stz(mbedtls_ecp_group *grp, uint8_t *privkey, uint8_t *pubkey);

/*!
 * @brief           This function computes the ECDH shared secret
 *
 * \note            The point multiplication primitive function is used to calculate
 *                  the shared secret.
 *                  shared secret = Point Multiplication of (Private Key * Public key of other)
 *
 * \param mbedtls_ecdh_stz_params  The structure holding the input and output params
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the parameters are wrong
 *
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 
 * \note           If private key stored in hardware key store to be used, then value in \ref mbedtls_ecdh_stz_params_t.privKey must be NULL.
				   \n The value in \ref mbedtls_ecdh_stz_params_t.grp.privkeyindex must contain the key index of private key (only APP_ASYMM_KEY) stored in hardware key store.
                   \n The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSASYMMETRICECC_NOTE
 
 */
int32_t mbedtls_ecdh_compute_shared_stz(mbedtls_ecdh_stz_params_t * mbedtls_ecdh_stz_params);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* PN76_ECCALT_H_ */
