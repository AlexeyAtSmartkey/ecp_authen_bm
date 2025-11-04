#pragma once
#include <stdio.h>
#include <string.h>
#include "ph_Status.h"
#include "phalMfdfEVx.h"
#include "phKeyStore.h"
#include "key_manager.h"   // for KEY_get(), KEY_Type_e

// Strong assumption in your project (enforce it once):
_Static_assert(APP_MASTER_KEY == 0x00, "APP_MASTER_KEY must be 0 (app master key #0)");

/* Pretty names for common return codes (extend as you like) */
static inline const char* mfdf_status_str(phStatus_t st) {
    switch (st & PH_ERR_MASK) {
        case PH_ERR_SUCCESS:        return "SUCCESS";
        case 0x0007:                return "AUTH_FAILED (0x2007 if AL component)";
        case 0x0083:                return "INTEGRITY/MAC_ERROR (0x2083 if AL component)";
        case PH_ERR_INVALID_PARAMETER:  return "INVALID_PARAM";
        default:                    return "UNKNOWN";
    }
}

/* Best-effort peek: for AES keys PN76xx returns 'K','I','D',index instead of raw bytes. */
static inline void ks_dump_slot(void* pKeyStore, uint16_t keyno, uint16_t keyver, const char* tag) {
    uint16_t typ = 0;
    uint8_t  buf[32] = {0};
    phStatus_t st = phKeyStore_GetKey(pKeyStore, keyno, keyver, sizeof(buf), buf, &typ);
    if (st != PH_ERR_SUCCESS) {
        printf("[KS] %s keyno=%u ver=%u -> GetKey FAILED: 0x%04X\n", tag, keyno, keyver, st);
        return;
    }
    if (typ == PH_KEYSTORE_KEY_TYPE_AES128 || typ == PH_KEYSTORE_KEY_TYPE_AES256) {
        if (buf[0]=='K' && buf[1]=='I' && buf[2]=='D') {
            printf("[KS] %s keyno=%u ver=%u type=AES kid=%u\n", tag, keyno, keyver, buf[3]);
        } else {
            printf("[KS] %s keyno=%u ver=%u type=AES kid=? (non-PN76xx keystore?)\n", tag, keyno, keyver);
        }
    } else {
        printf("[KS] %s keyno=%u ver=%u type=%u bytes=", tag, keyno, keyver, typ);
        for (uint8_t i=0;i<16 && i<sizeof(buf);++i) printf("%02X", buf[i]);
        printf("\n");
    }
}

/* One-liners for your common logical keys */
#define KS_DUMP(lbl, keytype) do { \
    KEY_Params_t* _k = KEY_get(keytype); \
    if (_k) ks_dump_slot(pKeyStore, _k->keyno, _k->version, lbl); \
    else    printf("[KS] %s <NULL>\n", lbl); \
} while(0)

/* Log + wrap EV2 auth (FIRST or NONFIRST) */
static inline phStatus_t dbg_AuthenticateEv2(
    void* pKeyStore, phalMfdfEVx_Sw_DataParams_t* al,
    uint8_t bFirstOrNonFirst,
    KEY_Type_e hostKey, uint8_t cardKeyNo,
    uint8_t bLenPcdCapsIn, uint8_t* PCDcap2, uint8_t* PCDcap2In, uint8_t* PDcap2In)
{
    KEY_Params_t* k = KEY_get(hostKey);
    if (!k) { printf("[AUTH] hostKey=%d -> KEY_get NULL\n", hostKey); return PH_ERR_INVALID_PARAMETER; }
    printf("[AUTH] %s hostKey=%d keyno=%u ver=%u cardKeyNo=%u capsLen=%u\n",
           bFirstOrNonFirst ? "FIRST":"NONFIRST", hostKey, k->keyno, k->version, cardKeyNo, bLenPcdCapsIn);
    ks_dump_slot(pKeyStore, k->keyno, k->version, "AUTH-slot");

    phStatus_t st = phalMfdfEVx_AuthenticateEv2(
        al, bFirstOrNonFirst, PHAL_MFDFEVX_NO_DIVERSIFICATION,
        k->keyno, k->version, cardKeyNo,
        NULL, 0, bLenPcdCapsIn, PCDcap2, PCDcap2In, PDcap2In);

    printf("[AUTH] -> 0x%04X (%s)\n", st, mfdf_status_str(st));
    return st;
}

/* Log + wrap ChangeKeyEv2 (old->new) */
static inline phStatus_t dbg_ChangeKeyEv2(
    void* pKeyStore, phalMfdfEVx_Sw_DataParams_t* al,
    KEY_Type_e oldHostKey, KEY_Type_e newHostKey,
    uint8_t bKeySetNo, uint8_t bKeyNoCard)
{
    KEY_Params_t *oldk = KEY_get(oldHostKey), *newk = KEY_get(newHostKey);
    if (!oldk || !newk) {
        printf("[CKEY] KEY_get(old=%d/new=%d) NULL\n", oldHostKey, newHostKey);
        return PH_ERR_INVALID_PARAMETER;
    }
    printf("[CKEY] appKey#=%u set=%u old(keyno=%u ver=%u) -> new(keyno=%u ver=%u)\n",
           bKeyNoCard, bKeySetNo, oldk->keyno, oldk->version, newk->keyno, newk->version);
    ks_dump_slot(pKeyStore, oldk->keyno, oldk->version, "OLD");
    ks_dump_slot(pKeyStore, newk->keyno, newk->version, "NEW");

    phStatus_t st = phalMfdfEVx_ChangeKeyEv2(
        al, PHAL_MFDFEVX_NO_DIVERSIFICATION,
        oldk->keyno, oldk->version,
        newk->keyno, newk->version,
        bKeySetNo, bKeyNoCard, NULL, 0);

    printf("[CKEY] -> 0x%04X (%s)\n", st, mfdf_status_str(st));
    return st;
}
