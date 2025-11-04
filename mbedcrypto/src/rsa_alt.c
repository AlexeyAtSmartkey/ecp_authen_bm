/*----------------------------------------------------------------------------*/
/* Copyright 2022  NXP                                                        */
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
 * This file contains the RSA interfaces for applications to use the cryptolib via mbedtls
 * $Author:  $
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
#include "ph_Registers.h"
//#include "ph_RegistersApb.h"
#include "string.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

#include "rsa_alt.h"
#include "PN76_Rsaalt.h"

/*********************************************************************************************************************/
/*   Section Initialisation                                                                                          */
/*********************************************************************************************************************/
//PH_ZI_DATA_SECTION(gphHal_crypto);

/*****************************************************************************
 * Macros
 ****************************************************************************/
#define MAX_RSA_KEY_BYTE_LEN 384U /* Maximum supported key bit length is 3072 bits  */
/*****************************************************************************
 * Global Static variables
 ****************************************************************************/
uint8_t modulus[MAX_RSA_KEY_BYTE_LEN] __attribute__((aligned(4)));
uint8_t exponent[32] __attribute__((aligned(4)));
uint8_t privateExponent[MAX_RSA_KEY_BYTE_LEN] __attribute__((aligned(4)));
uint8_t aP[MAX_RSA_KEY_BYTE_LEN/2] __attribute__((aligned(4)));
uint8_t aQ[MAX_RSA_KEY_BYTE_LEN/2] __attribute__((aligned(4)));
uint8_t aDP[MAX_RSA_KEY_BYTE_LEN/2] __attribute__((aligned(4)));
uint8_t aDQ[MAX_RSA_KEY_BYTE_LEN/2] __attribute__((aligned(4)));
uint8_t aQP[MAX_RSA_KEY_BYTE_LEN/2] __attribute__((aligned(4)));
/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Private functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Global functions implementation
 ****************************************************************************/
void mbedtls_rsa_init( mbedtls_rsa_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_rsa_context ) );
}

void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_rsa_context ) );
}

int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
   int ret = -1;
   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   uint8_t Exponent[3] = {0x01, 0x00, 0x01};

   rsa_context.N = &modulus[0];
   rsa_context.len = nbits/8;
   rsa_context.D = &privateExponent[0];
   rsa_context.E = &Exponent[0];
   rsa_context.len_E = sizeof(Exponent);
   rsa_context.P = &aP[0];
   rsa_context.len_P = nbits/16;
   rsa_context.Q = &aQ[0];
   rsa_context.len_Q = nbits/16;
   rsa_context.DP = &aDP[0];
   rsa_context.len_DP = nbits/16;
   rsa_context.DQ = &aDQ[0];
   rsa_context.len_DQ = nbits/16;
   rsa_context.QP = &aQP[0];
   rsa_context.len_QP = nbits/16;

   do
   {
      if(ctx->bKeyType == 0)
      {
         if(0 != mbedtls_rsa_gen_key_plain_stz(&rsa_context, nbits))
            break;

         /* Convert the public modulus into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->N, modulus, nbits/8))
            break;

         /* Convert the Private Exponent into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->D, privateExponent, nbits/8))
            break;

         /* Convert the Exponent into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->E, Exponent, sizeof(Exponent)))
            break;

      }
      else
      {
         if(0 != mbedtls_rsa_gen_key_crt_stz(&rsa_context, nbits))
            break;

         /* Convert the public modulus into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->N, modulus, nbits/8))
            break;

         /* Convert the Exponent into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->E, Exponent, sizeof(Exponent)))
            break;

         /* Convert the first prime factor into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->P, aP, nbits/16))
            break;

         /* Convert the second prime factor into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->Q, aQ, nbits/16))
            break;

         /* Convert the <code>D % (P - 1)</code> into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->DP, aDP, nbits/16))
            break;

         /* Convert the <code>D % (Q - 1)</code> into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->DQ, aDQ, nbits/16))
            break;

         /* Convert the <code>1 / (Q % P)</code> into the MPI format */
         if(0 != mbedtls_mpi_read_binary(&ctx->QP, aQP, nbits/16))
            break;
      }

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];

      if(0 != mbedtls_rsa_public_stz(&rsa_context, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
            int (*f_rng)(void *, unsigned char *, size_t),
            void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];

      if(0 != mbedtls_rsa_private_stz(&rsa_context, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_pkcs_encdec_stz_params_t pkcs_encdec = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      rsa_context.padding = ctx->padding;
      pkcs_encdec.ilen = ilen;

      if(0 != mbedtls_rsa_pkcs1_encrypt_stz(&rsa_context, &pkcs_encdec, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];
      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;

      rsa_context.E = &exponent[0];

      if(0 != mbedtls_rsa_rsaes_pkcs1_v15_encrypt_stz(&rsa_context, ilen, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_pkcs_encdec_stz_params_t pkcs_encdec = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      pkcs_encdec.ilen = ilen;
      pkcs_encdec.label = label;
      pkcs_encdec.label_len = label_len;

      if(0 != mbedtls_rsa_rsaes_oaep_encrypt_stz(&rsa_context, &pkcs_encdec, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_pkcs_encdec_stz_params_t pkcs_encdec = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      rsa_context.padding = ctx->padding;
      pkcs_encdec.olen = olen;

      if(0 != mbedtls_rsa_pkcs1_decrypt_stz(&rsa_context, &pkcs_encdec, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_pkcs_encdec_stz_params_t pkcs_encdec = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      pkcs_encdec.olen = olen;

      if(0 != mbedtls_rsa_rsaes_pkcs1_v15_decrypt_stz(&rsa_context, &pkcs_encdec, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_pkcs_encdec_stz_params_t pkcs_encdec = {0};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      pkcs_encdec.olen = olen;
      pkcs_encdec.label = label;
      pkcs_encdec.label_len = label_len;

      if(0 != mbedtls_rsa_rsaes_oaep_decrypt_stz_v2(&rsa_context, &pkcs_encdec, input, output))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};
   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      rsa_context.padding = ctx->padding;
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) (mbedtls_md_type_stz_t) md_alg;

      if(0 != mbedtls_rsa_pkcs1_sign_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};
   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg; //TODO: if for pss does not need send, assign according to padding

      if(0 != mbedtls_rsa_rsassa_pkcs1_v15_sign_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};
   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg; // TODO: Not used why passing?

      if(0 != mbedtls_rsa_rsassa_pss_sign_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pss_sign_ext( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};
   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];

      /* Convert the private exponent into the raw binary format */
      if(0 != mbedtls_mpi_write_binary(&ctx->D, privateExponent, ctx->len))
         break;
      rsa_context.D = &privateExponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg; // TODO: Not used why passing?
      rsa_data.saltlen = saltlen;

      if(0 != mbedtls_rsa_rsassa_pss_sign_ext_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];
      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      rsa_context.padding = ctx->padding;
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature_verify = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg; //TODO: if for pss does not need send, assign according to padding

      if(0 != mbedtls_rsa_pkcs1_verify_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];
      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature_verify = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg;

      if(0 != mbedtls_rsa_rsassa_pkcs1_v15_verify_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];
      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature_verify = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg; // TODO : Not used why passing

      if(0 != mbedtls_rsa_rsassa_pss_verify_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}

int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
   int ret = -1;

   mbedtls_rsa_context_stz_params_t rsa_context = {0};
   mbedtls_rsa_sign_verify_stz_params_t rsa_data = {MBEDTLS_MD_NONE_STZ};

   do
   {
      /* Convert the public modulus into the raw binary format */
      rsa_context.len = ctx->len;
      if(0 != mbedtls_mpi_write_binary(&ctx->N, modulus, ctx->len))
         break;
      rsa_context.N = &modulus[0];
      /* Convert the public exponent into the raw binary format */
      rsa_context.len_E = mbedtls_mpi_size(&ctx->E);
      if(0 != mbedtls_mpi_write_binary(&ctx->E, exponent, rsa_context.len_E))
         break;
      rsa_context.E = &exponent[0];
      rsa_data.hash = hash;
      rsa_data.hashlen = hashlen;
      rsa_data.sig_t.signature_verify = sig;
      rsa_data.md_alg = (mbedtls_md_type_stz_t) md_alg;  // TODO : Not used why passing
      rsa_data.saltlen = expected_salt_len;

      if(0 != mbedtls_rsa_rsassa_pss_verify_ext_stz(&rsa_context, &rsa_data))
         break;

      ret = 0; /* if code reached till here all conditions were success */

   }while(0);

   return ret;
}


/*****************************************************************************
 * Private functions
 ****************************************************************************/
