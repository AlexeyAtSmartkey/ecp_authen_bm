#include "NdefEx.h"

static uint8_t bufferapp[1024];

PN76_Status_t APP_InitMbedCrypto(void)
{
    PN76_Status_t eKeyStoreStatus;
    PN76_Status_t InitStatus;
    uint8_t       bKeyStoreStatus = 0;

    /*Initialize the crypto modules */
    InitStatus = (PN76_Status_t)phmbedcrypto_Init();
    if (InitStatus != PN76_STATUS_SUCCESS)
    {
//        PRINTF("Crypto initialization failure\r\n");
        return InitStatus;
    }

    eKeyStoreStatus = PN76_Sys_KeyStore_Init(&bKeyStoreStatus);

    /* bKeyStoreStatus 6th bit means fatal error. */
    if ((eKeyStoreStatus != PN76_STATUS_SUCCESS) || ((bKeyStoreStatus & 0x40U) != 0U))
    {
//        PRINTF("Crypto initialization error\r\n");
        return eKeyStoreStatus; /* if Failed Do not go further */
    }

    mbedtls_memory_buffer_alloc_init(bufferapp, sizeof(bufferapp));
    return eKeyStoreStatus;
}

PN76_Status_t APP_DeInitMbedCrypto(void)
{
	mbedtls_memory_buffer_alloc_free();
    /*DeInitialize the crypto modules */
    phmbedcrypto_DeInit();

//	PN76_Sys_KeyStore_DeInit();
}

void InitSmartTapSession(SmartTapSessionData *sessionData, int privateKeyVersion)
{
	LongTermPrivateKey *testLongTermPrivateKeys = GetTestPrivateKeys();
	int privateKeyIndex = privateKeyVersion - 1;
	// It needs to implement load from secure storage
	memcpy(sessionData->collector_id, testLongTermPrivateKeys[privateKeyIndex].cid, 4);
	memcpy(sessionData->merchant_long_term_key_version, testLongTermPrivateKeys[privateKeyIndex].ver, 4);
	memcpy(sessionData->merchant_long_term_private_key, testLongTermPrivateKeys[privateKeyIndex].key, 32);
	//================================================
	GenerateSessionID(sessionData->session_id);
	GenerateTerminalNonce(sessionData->terminal_nonce);
    GenerateEphemeralTerminalKey(sessionData);
    sessionData->sequence_number = 0x01;
}

// Compression of public key to 33 bytes
int ECP_Compress(uint8_t *X, uint8_t *Y, uint8_t *compressed_key)
{
    compressed_key[0] = (Y[31] & 1) ? 0x03 : 0x02; 	// Detect parity of Y
    memcpy(compressed_key + 1, X, 32); 				// Copy 32 bytes from X to compressed_key+1
    return 0;
}

int GenerateEphemeralTerminalKey(SmartTapSessionData *sessionData) {
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	mbedtls_mpi d;
	int result = 1;
	uint8_t buflen = 256 / 8;

    MBEDTLS_MPI_INIT(&d, &Q.X, &Q.Y, &Q.Z)

	grp.id = MBEDTLS_ECP_DP_SECP256R1;

	result = mbedtls_ecp_gen_keypair(&grp, &d, &Q, NULL, NULL);
    CHECK_STATUS_AND_RETURN(result, PH_ERR_MASK, "Error: ECC Key Pair generation failed! (Status: 0x%X)\n")
	mbedtls_mpi_write_binary(&d, sessionData->terminal_private_key, buflen);
	mbedtls_mpi_write_binary(&Q.X, sessionData->terminal_public_key_x, buflen);
	mbedtls_mpi_write_binary(&Q.Y, sessionData->terminal_public_key_y, buflen);
	result = ECP_Compress(sessionData->terminal_public_key_x, sessionData->terminal_public_key_y, sessionData->terminal_compressed_public_key);

    MBEDTLS_MPI_FREE(&d, &Q.X, &Q.Y, &Q.Z)

	return result;
}

#define AES_BLOCK_SIZE 16
#define IV_SIZE 12
#define HMAC_SIZE 32
#define DERIVED_KEY_SIZE 48  // HKDF output size
#define AES_KEY_SIZE 16      // First 16 bytes of derived key
#define HMAC_KEY_SIZE 32     // Last 32 bytes of derived key


int ECC_SignData(SmartTapSessionData *sessionData, uint8_t *signature) {
	mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    phStatus_t status;
    uint8_t hash[32];
//    uint8_t merchant_public_key[64] = {0};  // X || Y coordinates

    MBEDTLS_MPI_INIT(&d, &r, &s, &Q.X, &Q.Y, &Q.Z)

    grp.id = MBEDTLS_ECP_DP_SECP256R1;

    // 1. SHA-256 calculate data hash
    status = mbedtls_sha256_ret(sessionData->terminal_nonce, SIGNED_SESSION_DATA_LEN, hash, 0);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: SHA-256 computation failed! (Status: 0x%X)\n")

    /* Load stored private key `d` */
    status = mbedtls_mpi_read_binary(&d, sessionData->merchant_long_term_private_key, sizeof(sessionData->merchant_long_term_private_key));
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: Load private key failed! (Status: 0x%X)\n")

    /* Generate public key from private */
    status = phmbedcrypto_Get_AsymmPubKey(&grp, &d, &Q);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: Public key generation failed! (Status: 0x%X)\n")

    // 3. Signing
    status = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash), NULL, NULL);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: ECC signing failed! (Status: 0x%X)\n")

    status = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &r, &s);
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: ECDSA verification failed! (Status: 0x%X)\n")

    uint8_t *sigr = signature;
    uint8_t *sigs = signature + (ECC_PUBLIC_KEY_SIZE / 2);
    status = mbedtls_mpi_write_binary(&r, sigr, (ECC_PUBLIC_KEY_SIZE / 2));
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: Extracting signature R failed! (Status: 0x%X)\n")
    status = mbedtls_mpi_write_binary(&s, sigs, (ECC_PUBLIC_KEY_SIZE / 2));
    CHECK_STATUS_AND_RETURN(status, PH_ERR_MASK, "Error: Extracting signature S failed! (Status: 0x%X)\n")

    MBEDTLS_MPI_FREE(&d, &r, &s, &Q.X, &Q.Y, &Q.Z)

    return PH_ERR_SUCCESS;
}

// DER encoding of raw sign (64 bytes, R||S).
// Write result into der_sig, and actual length into *der_sig_len.
// Handling the case when high bit R or S set to 1.
#define R_PART_LEN 32
#define S_PART_LEN 32
int DER_EncodeSignature(const uint8_t *raw_sig, uint8_t *der_sig)
{
    int offset = 0;
    der_sig[offset++]       = 0x30;							// DER SEQUENCE
    int total_length_offset = offset++; 					// placeholder for total length
    int r_extra             = (raw_sig[0] & 0x80) ? 1 : 0;  // If first two bytes R ≥ 0x80, add another 0x00
    int s_extra             = (raw_sig[32] & 0x80) ? 1 : 0;
    int r_len               = R_PART_LEN + r_extra;
    int s_len               = S_PART_LEN + s_extra;

    // Handle R-part
    der_sig[offset++] = 0x02;							// INTEGER tag for R
    der_sig[offset++] = (uint8_t)r_len;
    if(r_extra) { der_sig[offset++]   = 0x00; }				// add leading 0x00
    memcpy(der_sig + offset, raw_sig, R_PART_LEN);
    offset += R_PART_LEN;
    // Handle S-part
    der_sig[offset++] = 0x02;  								// INTEGER tag for S
    der_sig[offset++] = (uint8_t)s_len;
    if(s_extra){ der_sig[offset++] = 0x00; }				// add leading 0x00
    memcpy(der_sig + offset, raw_sig + R_PART_LEN, S_PART_LEN);
    offset += S_PART_LEN;
    der_sig[total_length_offset] = (uint8_t)(offset - 2); // Total Length (except first two bytes of header)
    return offset;
}

int SignSessionData(SmartTapSessionData *sessionData, uint8_t *buffer)
{
    uint8_t signature[64];                        // Buffer for ECC signature

    int res = ECC_SignData(sessionData, signature);
    if (res != PH_ERR_SUCCESS) {
        DEBUG_PRINTF("Error: ECC_SignData failed (0x%X).\n", res);
        return 0;
    }

    uint8_t l = DER_EncodeSignature(signature, buffer); // Convert to DER format
    memcpy(sessionData->der_signature, buffer, l);
    sessionData->der_signature_len = l;
    return l;
}

//========================================================
// ConstructNegotiateNDEF
//
// Builds an NDEF message containing:
//   1. "ngr" record (Negotiate Request) – contains 2-byte version.
//   2. "ses" record (Session) – contains 8-byte Session ID, 1-byte Sequence, 1-byte Status.
//   3. "cpr" record (Cryptography Parameters) – contains:
//         a) Terminal nonce (32 bytes)
//         b) Authentication byte (1 byte)
//         c) Compressed Merchant ephemeral public key (33 bytes)
//         d) Merchant long-term key version (4 bytes)
//   4. "sig" record (Signature record):
//         • Header (6 bytes) and payload (64-byte signature)
//   5. "cld" record (Collector ID record):
//         • Header (6 bytes) and payload (4 bytes)
// The outer record headers are 6 bytes long (0xD1, 0x03, <payload length>, <type: 3 ASCII chars>).
//
// The complete NDEF is written to ndef_buffer and its total length is returned in ndef_length.
//
// ========================================================
// Header (6 bytes):
//   Byte 0: 0xD1 (MB=1, ME=1, SR=1, TNF=0x04: external) The first and the last message
//           0x94 (MB=1, ME=0, SR=1, TNF=0x04: external) The first message
//           0x54 (MB=0, ME=1, SR=1, TNF=0x04: external) The last message
//   	Bits:
//			7    6    5    4    3    2    1    0
//		   MB   ME   CF   SR   IL   TNF2 TNF1 TNF0
//		TNF:
//			0x00: Empty
//			0x01: Well-known type name format
//			0x02: MIME media-type
//			0x03: Absolute URI
//			0x04: External type name format
//			0x05: Unknown
//			0x06: Unchanged
//			0x07: Reserved
//   Byte 1: 0x03 (Type Length = 3)
//   Byte 2: 0x02 (Payload Length = 2 bytes)
//   Bytes 3-5: 'n', 'g', 'r'
// ========================================================
void ConstructNegotiateNDEF(SmartTapSessionData *sessionData, uint8_t *ndef_buffer, uint8_t *ndef_length)
{
    uint16_t current_offset       = 0;

// ========================================================
// 1. Build the "ngr" record (Negotiate Request)
// --------------------------------------------------------
    // Header (6 bytes): Payload Length = 0x02 (calculated)
    // Format: { 0x94, 0x03, <ngr_payload_length>, 'n', 'g', 'r' }
    uint8_t *ngr_len = NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "ngr");
    // Payload: Version number (2 bytes: 0x00, 0x01)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x00)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x01)

// ========================================================
// 2. Build the "ses" record (Session)
// --------------------------------------------------------
    // Header (6 bytes): Payload Length = 0x0A (10 bytes)
    // Format: { 0x94, 0x03, 0x0A, 's', 'e', 's' }
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "ses")[0] = 0x0A;
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, sessionData->session_id)		// 8-byte Session ID
    NDEF_PUT_BYTE(ndef_buffer, current_offset, sessionData->sequence_number)	// 1-byte Sequence Number
    NDEF_PUT_BYTE(ndef_buffer, current_offset, sessionData->status_byte)		// 1-byte Status

// ========================================================
// 3. Build the "cpr" record (Cryptography Parameters)
// --------------------------------------------------------
    // Build the outer "cpr" record header (6 bytes):
    // Format: { 0x54, 0x03, <cpr_payload_length>, 'c', 'p', 'r' }
    uint8_t *cpr_len = NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "cpr");
    uint8_t *cpr_payload = ndef_buffer + current_offset;						// Start the CPR record payload from current position in the buffer.
    uint16_t cpr_offset = 0;
    NDEF_PUT_TO_BUF(cpr_payload, cpr_offset, sessionData->terminal_nonce)					// (a) Terminal nonce (32 bytes) – generate random nonce.
    NDEF_PUT_BYTE(cpr_payload, cpr_offset, sessionData->authentication_byte)				// (b) Authentication byte (1 byte) – set to 0x01 (live auth flag).
    NDEF_PUT_TO_BUF(cpr_payload, cpr_offset, sessionData->terminal_compressed_public_key)	// (c) Merchant ephemeral public key (33 bytes) – compute compressed key.
    NDEF_PUT_TO_BUF(cpr_payload, cpr_offset, sessionData-> merchant_long_term_key_version)// (d) Merchant long-term key version (4 bytes) – fixed to 0x00000001.

// ========================================================
// 4. Build the "sig" record (Signature record)
// --------------------------------------------------------
    // Build nested "sig" record header (6 bytes):
    // Format: { 0x94, 0x03, <payload length>, 's', 'i', 'g' }
    uint8_t *sig_len = NDEF_HEADER(cpr_payload, cpr_offset, NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "sig");
    NDEF_PUT_BYTE(cpr_payload, cpr_offset, 0x04) // Binary data
    size_t der_sig_len = SignSessionData(sessionData, cpr_payload + cpr_offset);
    cpr_offset += der_sig_len;
    sig_len[0] = der_sig_len + 1;

// ========================================================
// 5. Build the "cld" record (Collector ID record)
// --------------------------------------------------------
	// Build nested "cld" record header (6 bytes), Payload Length = 0x05 (5 bytes)
	// Format: { 0x54, 0x03, 0x05, 'c', 'l', 'd' }
    NDEF_HEADER(cpr_payload, cpr_offset, NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "cld")[0] = 0x05;
    NDEF_PUT_BYTE(cpr_payload, cpr_offset, 0x04)          // Binary data following
    NDEF_PUT_TO_BUF(cpr_payload, cpr_offset, sessionData->collector_id) // Append the 4-byte collector ID.
    current_offset += cpr_offset;								// Append the CPR payload.
    cpr_len[0] = cpr_offset;									// Now, the total CPR payload length is in cpr_offset.
    ngr_len[0] = current_offset - 6; // Now, the total NGR payload length is in current_offset minus 6 - header length

    // ========================================================
    // Finalize: set the overall NDEF length.
    *ndef_length = (uint8_t)current_offset;
}

void ConstructGetDataNDEF(SmartTapSessionData *sessionData, uint8_t *ndef_buffer, uint8_t *ndef_length) {
    uint16_t current_offset = 0;

    // --- "srq" (Service Request) ---
    uint8_t *srq_len = NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "srq");
    ndef_buffer[current_offset++] = 0x00;
    ndef_buffer[current_offset++] = 0x01;

    // --- "ses" (Session) ---
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "ses")[0] = 0x0A;
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, sessionData->session_id)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, sessionData->sequence_number)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, sessionData->status_byte)

    // --- "mer" (Merchant) ---
	uint8_t *mer_len = NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "mer"); //[0] = 0x0B;
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "cld")[0] = 0x05;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04)
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, sessionData->collector_id)
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "lid")[0] = 0x05;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04)
    uint8_t test_lid[] = {0x00, 0x00, 0x01, 0x01};
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, test_lid)
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "tid")[0] = 0x05;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04)
    uint8_t test_tid[] = {0x00, 0x00, 0x01, 0x02};
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, test_tid)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, NDEF_FLAG_SR | NDEF_FLAG_IL | NDEF_TNF_WELL_KNOWN)
    uint8_t test_test[] = {0x01, 0x08, 0x03, 'T', 'm', 'n', 'r', 0x02, 'e', 'n', 'S', 'P', 'K', 'e', 'y'};
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, test_test)
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "mcr")[0] = 0x03;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04)
    uint8_t test_mcr[] = {0x12, 0xd0};
    NDEF_PUT_TO_BUF(ndef_buffer, current_offset, test_mcr)
	mer_len[0] = (ndef_buffer + current_offset) - mer_len - 4;

    // --- "slr" (Service List Request) ---
    uint8_t *slr_len = NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "slr");
//    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "str")[0] = 0x01;
//    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x03) // Payload = 0x00
//    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "str")[0] = 0x01;
//    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04) // Payload = 0x00
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_MB | NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "str")[0] = 0x01;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x00) // Payload = 0x00
    slr_len[0] = (ndef_buffer + current_offset) - slr_len - 4;

    // --- "pcr" (Payment Capability Request) ---
    NDEF_HEADER(ndef_buffer, current_offset, NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL, "pcr")[0] = 0x05;
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x41) // SYSTEM_ZLIB_SUPPORTED(40) + SYSTEM_STANDALONE(01)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x00)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x00)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x00)
    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x04) // TAP_PASS_AND_PAYMENT(04)
//    NDEF_PUT_BYTE(ndef_buffer, current_offset, 0x01) // TAP_PASS_ONLY(02)

    *srq_len = current_offset - 6;
    *ndef_length = (uint8_t)current_offset;
}
