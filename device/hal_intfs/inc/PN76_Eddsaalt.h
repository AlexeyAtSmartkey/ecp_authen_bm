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
 * Alternate implementation of the EdDsa algorithm interfaces for applications
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_EDDSAALT_H_
#define PN76_EDDSAALT_H_
/** @addtogroup PN76SYASSYMMETRICEDDSA
 *
 * @brief System Service EDDSA API's
 *
 * This module briefs about the implementation of various EDDSA Algorithms.
 *
 
 * \section PN76SYASSYMMETRICEDDSA_NOTE Note regarding the use of the ECC private keys stored in hardware keystore
	If ECC private keys stored in hardware keystore to be used for signing, only
	\ref SKM_KEY_TYPE_APP_ASYMM  must be used. This key must be provisioned before using it by \ref PN76SYSHALSKM APIs.
	
 
 * @{
 *
 */


/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
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

/** \brief curve25519, Parameters A and B of Montgomery curve
 * - each buffer has the same byte length as the prime p
 * - specified by: phClTwEdMontGfp_MontDhDomainParam_t -> uint8_t* pA / uint8_t* pB
 * A = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00076D06
 * B = 0x 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
 */
#define MONTDH_CURVEPARAM_A  \
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x07, 0x6D, 0x06
#define MONTDH_CURVEPARAM_B  \
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, \
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x01

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
/** \brief Enumeration for choosing the complete key generation or getting only the public key */
typedef enum 
{
   PH_CLTWEDMONTGFP_OPTION_EDDSASIGN_KEYGEN, /*!< Generates both public and private keys */
   PH_CLTWEDMONTGFP_OPTION_EDDSASIGN_GETPUBKEY /*!< Generates only the public key */

}phmbedcrypto_eddsa_keygen_option_t;

/** \brief Enumeration for choosing the only scalar or random scalar while generating the signature */
typedef enum 
{
   PH_CLTWEDMONTGFP_OPTION_EDDSASIGN_SCALAR, /*!< Signature generation is only using scalar */
   PH_CLTWEDMONTGFP_OPTION_EDDSASIGN_RANDOM /*!< Signature generation is only using random scalar */

}phmbedcrypto_eddsa_sign_option_t;

/** \brief Enumeration for choosing the only scalar or random scalar while generating the signature */
typedef enum 
{
   PH_CLTWEDMONTGFP_OPTION_EDDSA_HASH, /*!< Option to use the normal hash */
   PH_CLTWEDMONTGFP_OPTION_EDDSA_HASH_SCP /*!< Option to use the hash with side channel protection. */

}phmbedcrypto_eddsa_hash_option_t;

/** \brief Structure for multi-precision integer used into asymmetric cryptography*/
typedef struct MPInt_t
{
  uint8_t *pMPInt; /*!< Pointer to the multi precision integer. */
  uint16_t wNumBytes; /*!< Length in bytes of multi precision integer. */
} MPInt_t;

/*!
 * @brief           The EdDSA domain parameter structure.
 *
 */
typedef struct EdDsaDomainParam_t
{
    uint8_t *pA; /*!< Curve parameter A of Montgomery curve which is birationally equivalent to twisted Edwards curve E (computed by calling phClTwEdMontGfp_FillEdDsaDomainParameters) */
    uint8_t *pB; /*!< Curve parameter B of Montgomery curve which is birationally equivalent to twisted Edwards curve E (computed by calling phClTwEdMontGfp_FillEdDsaDomainParameters)*/
    MPInt_t p;   /*!< Prime of the underlying field satisfying p != 1 mod 8 */
    uint8_t *pBasePointMont; /*!< Pointer to the point G on the Montgomery curve which corresponds to the base point on the birationally equivalent twisted Edwards curve E (computed by calling phClTwEdMontGfp_FillEdDsaDomainParameters) (byte length of buffer is twice the byte length of p) */
    MPInt_t n; /*!< Order of the base point n */
    uint8_t c; /*!< Integer >= 2 which specifies the cofactor h = 2^c of the twisted Edwards curve */
    uint16_t t; /*!< Integer t with c <= t < b. The secret EdDSA scalar s (also called sub-private key) has exactly t+1 bits (msb is set to 1) and its c less significant bits are 0. */
    uint8_t *pLadderConst; /*!< ladder constant (A+2) / 4 mod p (buffer has same byte length as p) (computed by calling phClTwEdMontGfp_FillEdDsaDomainParameters) */
    uint8_t *pa; /*!< Twisted Edwards curve parameter a which must be a square modulo p (buffer has same byte length as p) */
    uint8_t *pd; /*!< Twisted Edwards curve parameter d which must be a non-square modulo p (buffer has same byte length as p */
    uint8_t *pPrecSqrtMinusOne; /*!< Pointer to a square root of -1 modulo p, if p = 5 mod 8. If p != 5 mod 8, then this pointer is unspecified. */
    uint16_t                  b; /*!< Integer b with 2^{b-1} > p. EdDSA public and secret keys have exactly b bits, and EdDSA signatures have exactly 2b bits. */
} EdDsaDomainParam_t;

/*!
 * @brief           The EdDSA key generation structure.
 *
 */
typedef struct phmbedcrypto_eddsa_keygen_params
{
   uint8_t  privkeyindex;           /*!< The key index will be used to fetch internal private key from key store
                                      when the private key is not provided */
   uint8_t *pEncPublicKeyTwEd;      /**< \brief Pointer to encoded twisted Edwards curve public point (output) (b-bit encoded; buffer size minimal to store b bits)
                                       The encoded point is exported via a call to the export function specified by pCallExportBigEndianParamFromCL */
   uint8_t *pPrivateKey;            /**< \brief Pointer to the b-bit private key k (input/output) (buffer size minimal to store b bits)
                                       If private key k is imported, it is imported via a call to the import function specified by pCallSecureHashSecureImportFunction
                                       If private key k is generated, it is exported via a call to the export function specified by pCallExportParamSecureFromCL */
   uint8_t *pPrivateKeyHash;        /**< \brief Pointer to the b-bits (h_b,...,h_{2b-1}) of the hashed private key k (output) (buffer size minimal to store b bits)
                                       It is exported via a call to the export function specified by pCallExportParamSecureFromCL */
   uint8_t *pSubPrivateKey;         /**< \brief Pointer to the sub-private key s (output) */
   phmbedcrypto_eddsa_keygen_option_t phmbedcrypto_eddsa_keygen_option; /*!< Option for choosing the key generation output type */
   phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option; /*!< Option for choosing the hash type */
} phmbedcrypto_eddsa_keygen_params_t;

/*!
 * @brief           The EdDSA signature generation structure.
 *
 */
typedef struct phmbedcrypto_eddsa_sign_params
{
   uint8_t *pDigest; /*!< Digest of the message (input) */
   uint32_t digestlength; /*!< Length of the digest */
   uint8_t *pEncPublicKeyTwEd; /*!< Pointer to the encoded twisted Edwards curve public point (input) */
   uint8_t *pPrivateKey; /*!< Pointer to the encoded twisted Edwards curve private key (input) */
   uint8_t  privkeyindex;/*!< The key index will be used to fetch internal private key from key store
                                          when the private key is not provided */
   uint8_t *pSigR; /*!< Pointer to the first part of the signature (input) (Encoded twisted Edwards point) */
   uint8_t *pSigS; /*!< Pointer to the second part of the signature (input) (integer) */
   MPInt_t *pcontextstring;  /*!< Context string internally prepended to the message before hashing (input) */
   phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option; /*!< Option for choosing the hash type */
   phmbedcrypto_eddsa_sign_option_t phmbedcrypto_eddsa_sign_option; /*!< Option for choosing the signature output type */
} phmbedcrypto_eddsa_sign_params_t;

/*!
 * @brief           The EdDSA signature verification structure.
 *
 */
typedef struct phmbedcrypto_eddsa_verify_params
{
   uint8_t *pDigest; /*!< Digest of the message (input) */
   uint32_t digestlength; /*!< Length of the digest */
   uint8_t *pPublickey; /*!< Pointer to the encoded twisted Edwards curve public point (input) */
   uint8_t *pSigR; /*!< Pointer to the first part of the signature (input) (Encoded twisted Edwards point) */
   uint8_t *pSigS; /*!< Pointer to the second part of the signature (input) (integer) */
   MPInt_t *pcontextstring;  /*!< Context string internally prepended to the message before hashing (input) */
   EdDsaDomainParam_t *pEdDsaDomainParams; /*!< #EdDsaDomainParam_t */
} phmbedcrypto_eddsa_verify_params_t;

/**
 * Structure for domain parameters used within MontDH functions.
 */
typedef struct phmbedcrypto_eddsa_MontDhDomainParam_t
{
    uint8_t *pA;                  /**< Montgomery curve parameter A (buffer has same byte length as p) */
    uint8_t *pB;                  /**< Montgomery curve parameter B (buffer has same byte length as p) */
    MPInt_t              p;       /**< Prime of the underlying field satisfying p != 1 mod 8 */
    uint8_t *pBasePointXCoord;    /**< Pointer to the x-coordinate of the base point G (buffer has same byte length as p) */
    MPInt_t              n;       /**< Order of the base point n */
    uint8_t                   c;  /**< Integer >= 2 which specifies the cofactor h = 2^c of the Montgomery curve */
    uint16_t                  t;  /**< Integer t with c <= t. The used private keys k have exactly t+1 bits (msb is set to 1) and its c less significant bits are 0. */
} phmbedcrypto_eddsa_MontDhDomainParam_t;

/**
 * \brief Structure of parameters for the Diffie-Hellman key-gen (phClTwEdMontGfp_MontDhKeyGen)
 */
typedef struct phmbedcrypto_eddsa_MontDhKeyGen_Param
{
    uint8_t *pPublicKey;                                                   /**< \brief Pointer to the public key q (input) (element of GF(p))
                                                                                                        The public key is imported via a call to the import function specified by pCallImportBigEndianParamToCL */
    uint8_t *pPrivateKey;                                                  /**< \brief Pointer to the private key k (input): an integer which is exactly one bit shorter than the group order 2^c*n and divisible by 2^c
                                                                                                        The private key is imported via a call to the import function specified by pCallImportBigEndianParamSecureToCL */
    uint8_t *pCommonSecret;                                                                 /**< \brief Pointer to the common secret (output): an element of GF(p)
                                                                                                        The secret is exported via a call to the export function specified by pCallExportBigEndianParamSecureFromCL */
} phmbedcrypto_eddsa_MontDhKeyGen_Param_t;

/**
 * \brief Structure of parameters for the Diffie-Hellman key-exchange (phClTwEdMontGfp_MontDhKeyExchange)
 */
typedef struct phmbedcrypto_eddsa_MontDhKeyExchange_Param_t
{
    uint8_t  privkeyindex;/*!< The key index will be used to fetch internal private key from key store
                                          when the private key is not provided */
    uint8_t *pPublicKey;                                                   /**< \brief Pointer to the public key q (input) (element of GF(p))
                                                                                                        The public key is imported via a call to the import function specified by pCallImportBigEndianParamToCL */
    uint8_t *pPrivateKey;                                                  /**< \brief Pointer to the private key k (input): an integer which is exactly one bit shorter than the group order 2^c*n and divisible by 2^c
                                                                                                        The private key is imported via a call to the import function specified by pCallImportBigEndianParamSecureToCL */
    uint8_t *pCommonSecret;                                                                 /**< \brief Pointer to the common secret (output): an element of GF(p)
                                                                                                        The secret is exported via a call to the export function specified by pCallExportBigEndianParamSecureFromCL */
} phmbedcrypto_eddsa_MontDhKeyExchange_Param_t;

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief           This function generates the EdDsa key pair
 *
 *
 * \param           phmbedcrypto_eddsa_keygen_params Pointer to structure holding the input and output params
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 */

int32_t phmbedcrypto_EdDSA_KeyGen_stz(phmbedcrypto_eddsa_keygen_params_t *phmbedcrypto_eddsa_keygen_params);

/*!
 * @brief           This function generates the EdDsa signature
 *
 *
 * \param           phmbedcrypto_eddsa_keygen_params Pointer to structure holding the input and output params
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 * \note           If private key stored in hardware key store to be used, then value in \ref phmbedcrypto_eddsa_sign_params_t.pPrivateKey must be NULL.
				   \n The value in \ref phmbedcrypto_eddsa_sign_params_t.privkeyindex must contain the key index of private key (only APP_ASYMM_KEY) stored in hardware key store.
                   \n The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYASSYMMETRICEDDSA_NOTE
 
 */

int32_t phmbedcrypto_EdDSA_Sign_stz(phmbedcrypto_eddsa_sign_params_t *phmbedcrypto_eddsa_sign_params);

/*!
 * @brief           This function verifies the EdDSA signature
 *
 *
 * \param           phmbedcrypto_eddsa_verify_params Pointer to structure holding the input and output params
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 */

int32_t phmbedcrypto_EdDSA_Verify_stz(phmbedcrypto_eddsa_verify_params_t *phmbedcrypto_eddsa_verify_params);

/*!
 * @brief           This function computes the shared secret using the eddsa 25519 curve
 *
 *
 * \param           phmbedcrypto_eddsa_MontDhKeyGen_Param Pointer to structure holding the input and output params
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 */
int32_t phmbedcrypto_EdDSA_MontDhKeyGen_stz(phmbedcrypto_eddsa_MontDhKeyGen_Param_t *phmbedcrypto_eddsa_MontDhKeyGen_Param);

/*!
 * @brief           This function computes the shared secret using the eddsa 25519 curve
 *
 *
 * \param           phmbedcrypto_eddsa_MontDhKeyExchange_Param Pointer to structure holding the input and output params
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 * \note           If private key stored in hardware key store to be used, then value in \ref phmbedcrypto_eddsa_MontDhKeyExchange_Param_t.pPrivateKey must be NULL.
				   \n The value in \ref phmbedcrypto_eddsa_MontDhKeyExchange_Param_t.privkeyindex must contain the key index of private key (only APP_ASYMM_KEY) stored in hardware key store.
                   \n The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYASSYMMETRICEDDSA_NOTE
 */
int32_t phmbedcrypto_EdDSA_MontDhKeyExchange_stz(phmbedcrypto_eddsa_MontDhKeyExchange_Param_t *phmbedcrypto_eddsa_MontDhKeyExchange_Param);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_EDDSAALT_H_ */
