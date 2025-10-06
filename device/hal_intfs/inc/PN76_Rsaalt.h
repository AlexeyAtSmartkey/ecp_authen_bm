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
/* Copyright 2021-2022 NXP                                                    */
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
 * Alternate implementation of mbedtls RSA functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_RSAALT_H_
#define PN76_RSAALT_H_

/** @addtogroup PN76SYASSYMMETRICRSA
 *
 * @brief System Service RSA API's
 *
 * This module briefs about the implementation of various RSA Algorithms.
 *
 * This module implements PN76SYASSYMMETRICRSA interface in the ROM code
 *
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
/*
 * RSA Error codes
 */
#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_RSA_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define MBEDTLS_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the validity check of the library. */
#define MBEDTLS_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define MBEDTLS_ERR_RSA_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define MBEDTLS_ERR_RSA_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define MBEDTLS_ERR_RSA_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */
#define MBEDTLS_ERR_RSA_HW_ACCEL_FAILED                   -0x4580  /**< The RSA hardware accelerator failed. */

/*
 * RSA constants
 */

#define MBEDTLS_RSA_PKCS_V15    0 /**< Use PKCS#1 v1.5 encoding. */
#define MBEDTLS_RSA_PKCS_V21    1 /**< Use PKCS#1 v2.1 encoding. */

#define MBEDTLS_RSA_SIGN        1 /**< Identifier for RSA signature operations. */
#define MBEDTLS_RSA_CRYPT       2 /**< Identifier for RSA encryption and decryption operations. */

#define MBEDTLS_RSA_SALT_LEN_ANY    -1

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
typedef struct mbedtls_rsa_context_stz_params
{

    size_t len;                       /*!<  The size of \p N in Bytes. */

    uint8_t * N;                      /*!<  The public modulus. */
    uint8_t * E;                      /*!<  The public exponent. */

    uint8_t * D;                      /*!<  The private exponent. */
    uint8_t * P;                      /*!<  The first prime factor. */
    uint8_t * Q;                      /*!<  The second prime factor. */

    uint8_t * DP;                     /*!<  <code>D % (P - 1)</code>. */
    uint8_t * DQ;                     /*!<  <code>D % (Q - 1)</code>. */
    uint8_t * QP;                     /*!<  <code>1 / (Q % P)</code>. */

    uint16_t len_E;                   /*!<  The public exponent length */
    uint16_t len_P;                   /*!<  The first prime factor length */
    uint16_t len_Q;                   /*!<  The second prime factor length */
    uint16_t len_DP;                  /*!<  <code>D % (P - 1)</code> length */
    uint16_t len_DQ;                  /*!<  <code>D % (Q - 1)</code> length */
    uint16_t len_QP;                  /*!<  <code>1 / (Q % P)</code> length */

    int32_t padding;                      /*!< Selects padding mode:
                                           #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                           #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int32_t hash_id;                      /*!< Hash identifier of mbedtls_md_type_stz_t type,
                                             as specified in md.h for use in the MGF
                                             mask generating function used in the
                                           EME-OAEP and EMSA-PSS encodings. */
}
mbedtls_rsa_context_stz_params_t;

/**
 * \brief     Supported message digests.
 *
 * \warning   MD5 and SHA-1 are considered weak message digests and
 *            their use constitutes a security risk. We recommend considering
 *            stronger message digests instead.
 *
 */
typedef enum {
    MBEDTLS_MD_NONE_STZ=0,    /**< None. */
    MBEDTLS_MD_MD5_STZ,       /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1_STZ,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224_STZ,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256_STZ,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384_STZ,    /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512_STZ,    /**< The SHA-512 message digest. */
    MBEDTLS_MD_RIPEMD160_STZ, /**< The RIPEMD-160 message digest. */
} mbedtls_md_type_stz_t;

/*!
 * @brief           The OAEP encrypt/decrypt structure
 *
 */
typedef struct mbedtls_pkcs_encdec_stz_params
{
   const uint8_t *label; /*!< The buffer holding the custom label to use. */
   size_t label_len; /*!< The length of the label in Bytes. */
   size_t ilen; /*!< The length of the plaintext buffer. */
   size_t *olen; /*!< The address at which to store the length of plaintext. */
}mbedtls_pkcs_encdec_stz_params_t;

typedef struct mbedtls_rsa_sign_verify_stz_params
{
    mbedtls_md_type_stz_t md_alg;                     /*!<  md_alg   The message-digest algorithm used to hash the original data.
                                                            Use #MBEDTLS_MD_NONE for signing raw data.  */
    uint32_t hashlen;                                 /*!<  hashlen  The length of the message digest or raw data in Bytes.
                                                            If \p md_alg is not #MBEDTLS_MD_NONE, this must match the
                                                            output length of the corresponding hash algorithm.
                                                            When used #MBEDTLS_MD_NONE option the hashlen will be raw bytes
                                                            length and nothing to do with the hash algorithm length */
    const uint8_t *hash;                              /*!<  hash     The buffer holding the message digest or raw data.
                                                            This must be a readable buffer of at least \p hashlen Bytes.
                                                            When used #MBEDTLS_MD_NONE option the this should be readable buffer of same
                                                            length passed in the hashlen parameter*/
    union sig
    {
       uint8_t *signature;                            /*!<  signature  The buffer to hold the signature. This must be a writable
                                                            buffer of length \c ctx->len Bytes. For example, \c 256 Bytes */
       const uint8_t *signature_verify;               /*!<  signature_verify The buffer holding the signature. This must be a readable
                                                            buffer of length \c ctx->len Bytes. For example, \c 256 Bytes
                                                            for an 2048-bit RSA modulus.  */
    }sig_t;

    int32_t saltlen;                                  /*!< saltlen : Only required for PSS extended sign / verify operation */
}
mbedtls_rsa_sign_verify_stz_params_t;

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/

/**
 * \brief          This function performs an RSA key generation in CRT format
 *
 * \param ctx      The initialized RSA context to use.
 * \param nbits    The number of bits to generate the RSA Key. The maximum number of bits supported is 3072 bits
 *
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_gen_key_crt_stz(mbedtls_rsa_context_stz_params_t *ctx,
                                    uint32_t nbits);

/**
 * \brief          This function performs an RSA key generation in Plain format
 *                 Please note that all the context parameters in CRT format namely P, Q, DP, DQ, DP
 *                 are manadatorily to be passed in this function. The output will be both in CRT and plain key formats.
 *
 * \param ctx      The initialized RSA context to use.
 * \param nbits    The number of bits to generate the RSA Key. The maximum number of bits supported is 3072 bits
 *
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_gen_key_plain_stz(mbedtls_rsa_context_stz_params_t *ctx,
                                    uint32_t nbits);

/**
 * \brief          This function performs an RSA public key operation.
 *
 * \param ctx      The initialized RSA context to use.
 * \param input    The input buffer. This must be a readable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 * \param output   The output buffer. This must be a writable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 *
 * \note           This function does not handle message padding.
 *
 * \note           Make sure to set \p input[0] = 0 or ensure that
 *                 input is smaller than \p N.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_public_stz( mbedtls_rsa_context_stz_params_t *ctx,
                const uint8_t *input,
                uint8_t *output );

/**
 * \brief          This function performs an RSA private key operation.
 *
 * \param ctx      The initialized RSA context to use.
 * \param input    The input buffer. This must be a readable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 * \param output   The output buffer. This must be a writable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 *
 */
int32_t mbedtls_rsa_private_stz( mbedtls_rsa_context_stz_params_t *ctx,
                 const uint8_t *input,
                 uint8_t *output );

/**
 * \brief          This function adds the message padding, then performs an RSA
 *                 operation.
 *
 *                 It is the generic wrapper for performing a PKCS#1 encryption
 *                 operation.
 *
 * \param ctx      The initialized RSA context to use.
 * \param pkcs_encdec  Structure holding the label parameters #mbedtls_oaep_encdec_stz_params_t.
 * \param input    The input data to encrypt. This must be a readable
 *                 buffer of size \p ilen Bytes. It may be \c NULL if
 *                 `ilen == 0`.
 * \param output   The output buffer. This must be a writable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_pkcs1_encrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                        mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
                       const uint8_t *input,
                       uint8_t *output );

/**
 * \brief          This function performs a PKCS#1 v1.5 encryption operation
 *                 (RSAES-PKCS1-v1_5-ENCRYPT).
 *
 * \param ctx      The initialized RSA context to use.
 * \param ilen     The length of the plaintext in Bytes.
 * \param input    The input data to encrypt. This must be a readable
 *                 buffer of size \p ilen Bytes. It may be \c NULL if
 *                 `ilen == 0`.
 * \param output   The output buffer. This must be a writable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsaes_pkcs1_v15_encrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                 size_t ilen,
                                 const uint8_t *input,
                                 uint8_t *output );

/**
 * \brief            This function performs a PKCS#1 v2.1 OAEP encryption
 *                   operation (RSAES-OAEP-ENCRYPT). The hash used for OAEP
 *                   is SHA256
 *
 * \note             The output buffer must be as large as the size
 *                   of ctx->N. For example, 128 Bytes if RSA-1024 is used.
 *
 * \param ctx        The initialized RSA context to use.
 * \param pkcs_encdec  Structure holding the label parameters #mbedtls_oaep_encdec_stz_params_t.
 * \param input      The input data to encrypt. This must be a readable
 *                   buffer of size \p ilen Bytes. It may be \c NULL if
 *                   `ilen == 0`.
 * \param output     The output buffer. This must be a writable buffer
 *                   of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                   for an 2048-bit RSA modulus.
 *
 * \return           \c 0 on success.
 * \return           An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsaes_oaep_encrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                       mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
                                       const uint8_t *input,
                                       uint8_t *output );

/**
 * \brief          This function performs an RSA private operation, then removes the
 *                 message padding.
 *
 *                 It is the generic wrapper for performing a PKCS#1 decryption
 *                 operation.
 *
 * \warning         When using this API, DO NOT use the OAEP padding scheme,
 *                  instead directly use \ref mbedtls_rsa_rsaes_oaep_decrypt_stz_v2() API
 *                  for the OAEP decryption.
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \p ctx->len of \p ctx->N (for example,
 *                 128 Bytes if RSA-1024 is used) to be able to hold an
 *                 arbitrary decrypted message. If it is not large enough to
 *                 hold the decryption of the particular ciphertext provided,
 *                 the function returns \c MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ctx      The initialized RSA context to use.
 * \param pkcs_encdec     Structure holding the label parameters #mbedtls_pkcs_encdec_stz_params_t.
 * \param input    The ciphertext buffer. This must be a readable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 * \param output   The buffer used to hold the plaintext. This must
 *                 be a writable buffer of length \p output_max_len Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_pkcs1_decrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                              mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
                              const uint8_t *input,
                              uint8_t *output);

/**
 * \brief          This function performs a PKCS#1 v1.5 decryption
 *                 operation (RSAES-PKCS1-v1_5-DECRYPT).
 *
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \p ctx->len of \p ctx->N, for example,
 *                 128 Bytes if RSA-1024 is used, to be able to hold an
 *                 arbitrary decrypted message. If it is not large enough to
 *                 hold the decryption of the particular ciphertext provided,
 *                 the function returns #MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ctx      The initialized RSA context to use.
 * \param pkcs_encdec     Structure holding the label parameters #mbedtls_pkcs_encdec_stz_params_t.
 * \param input    The ciphertext buffer. This must be a readable buffer
 *                 of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 * \param output   The buffer used to hold the plaintext. This must
 *                 be a writable buffer of length \p output_max_len Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 *
 */
int32_t mbedtls_rsa_rsaes_pkcs1_v15_decrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                          mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
                                          const uint8_t *input,
                                          uint8_t *output );

/**
 *
 * \warning            This API is deprecated, instead use \ref mbedtls_rsa_rsaes_oaep_decrypt_stz_v2() API
 *                  for the OAEP decryption.
 *
 *
 * \brief            This function performs a PKCS#1 v2.1 OAEP decryption
 *                   operation (RSAES-OAEP-DECRYPT). Hash algorithm used
 *                   for OAEP is SHA256
 *
 * \note             The output buffer length \c output_max_len should be
 *                   as large as the size \p ctx->len of \p ctx->N, for
 *                   example, 128 Bytes if RSA-1024 is used, to be able to
 *                   hold an arbitrary decrypted message. If it is not
 *                   large enough to hold the decryption of the particular
 *                   ciphertext provided, the function returns
 *                   #MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ctx        The initialized RSA context to use.
 * \param pkcs_encdec     Structure holding the label parameters #mbedtls_pkcs_encdec_stz_params_t.
 * \param input      The ciphertext buffer. This must be a readable buffer
 *                   of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                   for an 2048-bit RSA modulus.
 * \param output     The buffer used to hold the plaintext. This must
 *                   be a writable buffer of length \p output_max_len Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsaes_oaep_decrypt_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                       mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
                                       const uint8_t *input,
                                       uint8_t *output);

/**
 * \brief                 This function performs a private RSA operation to sign
 *                        a message digest using PKCS#1.
 *
 *                        It is the generic wrapper for performing a PKCS#1
 *                        signature.
 *
 * \note                  The \p signature buffer must be as large as the size
 *                        of \p ctx->N. For example, 128 Bytes if RSA-1024 is used.
 *
 * \note                  For PKCS#1 v2.1 encoding, see comments on
 *                        mbedtls_rsa_rsassa_pss_sign() for details on
 *                        \p md_alg and \p hash_id.
 *
 * \param ctx             The initialized RSA context to use.
 * \param rsa_sign_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature, and md_alg.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_pkcs1_sign_stz( mbedtls_rsa_context_stz_params_t *ctx,
                           mbedtls_rsa_sign_verify_stz_params_t *rsa_sign_data );

/**
 * \brief          This function performs a PKCS#1 v1.5 signature
 *                 operation (RSASSA-PKCS1-v1_5-SIGN).
 *
 * \param ctx      The initialized RSA context to use.
 * \param rsa_sign_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature, and md_alg.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsassa_pkcs1_v15_sign_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                      mbedtls_rsa_sign_verify_stz_params_t *rsa_sign_data);

/**
 * \brief          This function performs a PKCS#1 v2.1 PSS signature
 *                 operation (RSASSA-PSS-SIGN).
 *
 * \note           This function always uses the salt length as zero and
 *                 hash is fixed to SHA256 ONLY
 *
 * \param ctx      The initialized RSA context to use.
 * \param rsa_sign_data   a stucture to be filled with required info
 *                        such as hash, hashlen, and signature.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsassa_pss_sign_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                mbedtls_rsa_sign_verify_stz_params_t *rsa_sign_data );

/**
 * \brief          This function performs a PKCS#1 v2.1 PSS signature
 *                 operation (RSASSA-PSS-SIGN).
 *
 * \note           This function enforces that the provided salt length complies
 *                 with FIPS 186-4 §5.5 (e) and RFC 8017 (PKCS#1 v2.2) §9.1.1
 *                 step 3. The constraint is that the hash length plus the salt
 *                 length plus 2 bytes must be at most the key length. If this
 *                 constraint is not met, this function returns
 *                 #MBEDTLS_ERR_RSA_BAD_INPUT_DATA.
 *
 * \param ctx      The initialized RSA context to use.
 * \param rsa_sign_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature, and saltlen.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsassa_pss_sign_ext_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                    mbedtls_rsa_sign_verify_stz_params_t *rsa_sign_data );

/**
 * \brief          This function performs a public RSA operation and checks
 *                 the message digest.
 *
 *                 This is the generic wrapper for performing a PKCS#1
 *                 verification.
 *
 * \note           For PKCS#1 v2.1 encoding, see comments on
 *                 mbedtls_rsa_rsassa_pss_verify() about \p md_alg and
 *                 \p hash_id.
 *
 * \param ctx      The initialized RSA public key context to use.
 * \param rsa_verify_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature_verify, and md_alg.
 *
 * \return         \c 0 if the verify operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 * \note           MBEDTLS_ERR_RSA_HW_ACCEL_FAILED  error returned in case of sgnature
 *                 verification failures
 */
int32_t mbedtls_rsa_pkcs1_verify_stz( mbedtls_rsa_context_stz_params_t *ctx,
                             mbedtls_rsa_sign_verify_stz_params_t *rsa_verify_data );

/**
 * \brief          This function performs a PKCS#1 v1.5 verification
 *                 operation (RSASSA-PKCS1-v1_5-VERIFY).
 *
 * \param ctx      The initialized RSA public key context to use.
 * \param rsa_verify_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature_verify, and md_alg.
 *
 * \return         \c 0 if the verify operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 * \note           MBEDTLS_ERR_RSA_HW_ACCEL_FAILED  error returned in case of sgnature
 *                 verification failures
 */
int32_t mbedtls_rsa_rsassa_pkcs1_v15_verify_stz( mbedtls_rsa_context_stz_params_t *ctx,
                                 mbedtls_rsa_sign_verify_stz_params_t *rsa_verify_data );

/**
 * \brief          This function performs a PKCS#1 v2.1 PSS verification
 *                 operation (RSASSA-PSS-VERIFY).
 *
 *
 * \param ctx      The initialized RSA public key context to use.
 * \param rsa_verify_data   a stucture to be filled with required info
 *                        such as hash, hashlen, and signature_verify.
 *
 * \return         \c 0 if the verify operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 * \note           MBEDTLS_ERR_RSA_HW_ACCEL_FAILED  error returned in case of sgnature
 *                 verification failures
 */
int32_t mbedtls_rsa_rsassa_pss_verify_stz( mbedtls_rsa_context_stz_params_t *ctx,
                           mbedtls_rsa_sign_verify_stz_params_t *rsa_verify_data );

/**
 * \brief          This function performs a PKCS#1 v2.1 PSS verification
 *                 operation (RSASSA-PSS-VERIFY).
 *
 * \note           The \p signature buffer must be as large as the size
 *                 of \p ctx->N. For example, 128 Bytes if RSA-1024 is used.
 *
 *
 * \param ctx      The initialized RSA public key context to use.
 * \param rsa_verify_data   a stucture to be filled with required info
 *                        such as hash, hashlen, signature_verify, and saltlen.
 *
 * \return         \c 0 if the verify operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 * \note           MBEDTLS_ERR_RSA_HW_ACCEL_FAILED  error returned in case of sgnature
 *                 verification failures
 *
 */
int32_t mbedtls_rsa_rsassa_pss_verify_ext_stz( mbedtls_rsa_context_stz_params_t *ctx,
                               mbedtls_rsa_sign_verify_stz_params_t *rsa_verify_data );


/**
 * \brief            This function performs a PKCS#1 v2.1 OAEP decryption
 *                   operation (RSAES-OAEP-DECRYPT). Hash algorithm used
 *                   for OAEP is SHA256
 *
 * \note             The output buffer length \c output_max_len should be
 *                   as large as the size \p ctx->len of \p ctx->N, for
 *                   example, 128 Bytes if RSA-1024 is used, to be able to
 *                   hold an arbitrary decrypted message. If it is not
 *                   large enough to hold the decryption of the particular
 *                   ciphertext provided, the function returns
 *                   #MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ctx        The initialized RSA context to use.
 * \param pkcs_encdec     Structure holding the label parameters #mbedtls_pkcs_encdec_stz_params_t.
 * \param input      The ciphertext buffer. This must be a readable buffer
 *                   of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                   for an 2048-bit RSA modulus.
 * \param output     The buffer used to hold the plaintext. This must
 *                   be a writable buffer of length \p output_max_len Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int32_t mbedtls_rsa_rsaes_oaep_decrypt_stz_v2( mbedtls_rsa_context_stz_params_t *ctx,
            mbedtls_pkcs_encdec_stz_params_t * pkcs_encdec,
            const uint8_t *input,
            uint8_t *output);
#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_RSAALT_H_ */
