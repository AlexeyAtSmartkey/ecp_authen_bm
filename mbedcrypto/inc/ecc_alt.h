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


/** @file
 * Alternate implementation of mbedtls functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef _ECC_ALT_H_
#define _ECC_ALT_H_

/** @addtogroup mbedcrypto_asymm_wrap
 *
 * @brief Implementation of mbedtls functions using HW Crypto blocks of PN76 NFC Controller
 *
 * This module briefs all the prototypes of mbedtls functions that uses HW Crypto blocks of PN76 NFC Controller.
 *
 *
 * @{
 *
 */


/*****************************************************************************
 * System Includes
 ****************************************************************************/


/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/
/* Parameters are in Big-endian */

/** \brief edwards25519, Prime of the underlying field
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> phCl_MPInt_t p
 * p = 0x 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFED
 */
#define EDDSA_PRIME_P  \
  0x7F, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, \
  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xED
/*! Elliptic curve order P in byte length */
#define EDDSA_PRIME_P_BYTELEN    (32U)

/** \brief edwards25519, Order of the base point
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> phCl_MPInt_t n
 * n = 0x 10000000 00000000 00000000 00000000 14DEF9DE A2F79CD6 5812631A 5CF5D3ED
 */
#define EDDSA_ORDER_N  \
  0x10, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, \
  0x14, 0xDE, 0xF9, 0xDE,  0xA2, 0xF7, 0x9C, 0xD6,  0x58, 0x12, 0x63, 0x1A,  0x5C, 0xF5, 0xD3, 0xED
/*! Elliptic curve order N in byte length */
#define EDDSA_ORDER_N_BYTELEN    (32U)

/** \brief edwards25519, Parameters a and d of twisted Edwards curve
 * - each buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pa / uint8_t* pd
 * a = p - 1
 *   = 0x 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFEC
 * d = 0x 52036CEE 2B6FFE73 8CC74079 7779E898 00700A4D 4141D8AB 75EB4DCA 135978A3
 */
#define EDDSA_TWED_CURVEPARAM_A  \
  0x7F, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, \
  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xEC
/** \brief edwards25519, Parameters a and d of twisted Edwards curve
 * - each buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pa / uint8_t* pd
 * a = p - 1
 *   = 0x 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFEC
 * d = 0x 52036CEE 2B6FFE73 8CC74079 7779E898 00700A4D 4141D8AB 75EB4DCA 135978A3
 */
#define EDDSA_TWED_CURVEPARAM_D  \
  0x52, 0x03, 0x6C, 0xEE,  0x2B, 0x6F, 0xFE, 0x73,  0x8C, 0xC7, 0x40, 0x79,  0x77, 0x79, 0xE8, 0x98, \
  0x00, 0x70, 0x0A, 0x4D,  0x41, 0x41, 0xD8, 0xAB,  0x75, 0xEB, 0x4D, 0xCA,  0x13, 0x59, 0x78, 0xA3


/** \brief Parameters A and B of birationally equivalent Montgomery curve
 *     A = 2*(a+d)/(a-d) mod p
 *     B = 4/(a-d) mod p
 * - each buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pA / uint8_t* pB
 * A = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00076D06
 * B = 0x 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFF892E5
 */
#define EDDSA_MONT_CURVEPARAM_A  \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x6D, 0x06
/** \brief Parameters A and B of birationally equivalent Montgomery curve
 *     A = 2*(a+d)/(a-d) mod p
 *     B = 4/(a-d) mod p
 * - each buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pA / uint8_t* pB
 * A = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00076D06
 * B = 0x 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFF892E5
 */
#define EDDSA_MONT_CURVEPARAM_B  \
  0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x92, 0xE5

/** \brief Point G=(x,y) on birationally equivalent Montgomery curve (defined by A and B)
 *         which corresponds to the base point G_E=(u,v) on the twisted Edwards curve (defined by a and d)
 *         via the transformation
 *         x = (1+v)/(1-v) mod p
 *         y = (1+v)/(u*(1-v)) mod p
 * - the coordinates u and v are
 *   u = 0x 216936D3 CD6E53FE C0A4E231 FDD6DC5C 692CC760 9525A7B2 C9562D60 8F25D51A
 *   v = 0x 66666666 66666666 66666666 66666666 66666666 66666666 66666666 66666658
 * - the buffer contains x||y and has twice the byte length of the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pBasePointMont
 * x = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000009
 * y = 0x 660AD33A B9BDD38B AAD2FF27 9162FB80 361D762B 70A6F157 A0BADD5A BA838736
 */
#define EDDSA_MONT_BASEPOINT_X  \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09
/** \brief Point G=(x,y) on birationally equivalent Montgomery curve (defined by A and B)
 *         which corresponds to the base point G_E=(u,v) on the twisted Edwards curve (defined by a and d)
 *         via the transformation
 *         x = (1+v)/(1-v) mod p
 *         y = (1+v)/(u*(1-v)) mod p
 * - the coordinates u and v are
 *   u = 0x 216936D3 CD6E53FE C0A4E231 FDD6DC5C 692CC760 9525A7B2 C9562D60 8F25D51A
 *   v = 0x 66666666 66666666 66666666 66666666 66666666 66666666 66666666 66666658
 * - the buffer contains x||y and has twice the byte length of the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pBasePointMont
 * x = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000009
 * y = 0x 660AD33A B9BDD38B AAD2FF27 9162FB80 361D762B 70A6F157 A0BADD5A BA838736
 */
#define EDDSA_MONT_BASEPOINT_Y  \
  0x66, 0x0A, 0xD3, 0x3A, 0xB9, 0xBD, 0xD3, 0x8B, 0xAA, 0xD2, 0xFF, 0x27, 0x91, 0x62, 0xFB, 0x80, \
  0x36, 0x1D, 0x76, 0x2B, 0x70, 0xA6, 0xF1, 0x57, 0xA0, 0xBA, 0xDD, 0x5A, 0xBA, 0x83, 0x87, 0x36

/** \brief A square root of -1 modulo p,
 * - buffer has the same byte length as the prime p
 * - applicable for Ed25519 (p = 5 mod 8)
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pPrecSqrtMinusOne
 * i = 0x 2B832480 4FC1DF0B 2B4D0099 3DFBD7A7 2F431806 AD2FE478 C4EE1B27 4A0EA0B0
 */
#define EDDSA_SQRTMINUSONE  \
  0x2B, 0x83, 0x24, 0x80, 0x4F, 0xC1, 0xDF, 0x0B, 0x2B, 0x4D, 0x00, 0x99, 0x3D, 0xFB, 0xD7, 0xA7, \
  0x2F, 0x43, 0x18, 0x06, 0xAD, 0x2F, 0xE4, 0x78, 0xC4, 0xEE, 0x1B, 0x27, 0x4A, 0x0E, 0xA0, 0xB0


/** \brief Ladder constant (A+2) / 4 mod p
 * - buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t* pLadderConst
 * L = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0001DB42
 */
#define EDDSA_LADDERCONST  \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDB, 0x42

/** \brief edwards25519, Cofactor h = 2^c of the twisted Edwards curve
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint8_t c
 * c = 0x03
 */
#define EDDSA_COFACTOR_EXPONENT    (0x03U)


/** \brief edwards25519, Length t = 0xFE
 * - the secret EdDSA scalar s (also called sub-private key) has exactly t+1 bits (msb is set to 1)
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint16_t t
 */
#define EDDSA_BITLEN_T    (0xFEU)


/** \brief edwards25519, Length b = 0x0100
 * - EdDSA public and secret keys have exactly b bits, and EdDSA signatures have exactly 2b bits
 * - specified by: phClTwEdMontGfp_EdDsaDomainParam_t -> uint16_t b
 */
#define EDDSA_BITLEN_B    (0x0100U)
/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/


/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief           This function generates an ECP keypair.
 *
 * \note            This function uses bare components rather than an
 *                  mbedtls_ecp_keypair structure to ease use with other
 *                  structures, such as mbedtls_ecdh_context or
 *                  mbedtls_ecdsa_context.
 *
 * \param grp       The ECP group to generate a key pair for.
 *                  This must be initialized
 * \param d         The destination MPI (secret part).
 *                  This must be initialized.
 * \param Q         The destination point (public part).
 *                  This must be initialized.
 * \param f_rng     Handled internally. To be NULL
 * \param p_rng     Handled internally. To be NULL
 *                  be \c NULL if \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX error code
 *                  on failure.
 */
int mbedtls_ecp_gen_keypair( mbedtls_ecp_group *grp, mbedtls_mpi *d,
                             mbedtls_ecp_point *Q,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng );

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
 *
 * \param grp       The context for the elliptic curve to use.
 *                  This must be initialized
 * \param r         The MPI context in which to store the first part
 *                  the signature. This must be initialized.
 * \param s         The MPI context in which to store the second part
 *                  the signature. This must be initialized.
 * \param d         The private signing key. This must be initialized.
 * \param buf       The content to be signed. This is usually the hash of
 *                  the original data to be signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param f_rng     Handled internally. To be NULL
 * \param p_rng     Handled internally. To be NULL
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

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
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized
 * \param buf       The hashed content that was signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param Q         The public key to use for verification. This must be
 *                  initialized and setup.
 * \param r         The first integer of the signature.
 *                  This must be initialized.
 * \param s         The second integer of the signature.
 *                  This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                          const mbedtls_mpi *s);

/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by mbedtls_ecdh_gen_public().
 *
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see mbedtls_ecp_mul().
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param z         The destination MPI (shared secret).
 *                  This must be initialized.
 * \param Q         The public key from another party.
 *                  This must be initialized.
 * \param d         Our secret exponent (private key).
 *                  This must be initialized.
 * \param f_rng     The RNG function. This may be \c NULL if randomization
 *                  of intermediate results during the ECP computations is
 *                  not needed (discouraged). See the documentation of
 *                  mbedtls_ecp_mul() for more.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't need a
 *                  context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                 const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng );

/*!
 * @brief           This function gets the public key corresponding to the private key provided.
 *
 *
 * \param grp       The ECP group to generate a Pub key for.
 *                  This must be initialized
 * \param d         The Source MPI (Private part).
 *                  NULL to get private key from key store
 * \param Q         The destination point (public part).
 *                  This must be initialized.
 *
 * \return          \c 0 on success.
 * \return          1 on failure
 *
 */
int phmbedcrypto_Get_AsymmPubKey(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q);

#ifdef __cplusplus
}
#endif
/** @} */
#endif /* _ECC_ALT_NS_H_ */
