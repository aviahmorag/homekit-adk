/*
 * Pairing forensics: summarizes every pairing-store mutation and hands it to the app.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include "mgos_hap_pairing_events.h"

#include <string.h>

#include "HAP+Internal.h"
#include "mgos.h"

extern const char* HAPPlatformTCPStreamLastPeer(void);

#define PAIRING_RECORD_SIZE 70
#define PAIRING_PERMS_OFFSET 69
#define PAIRING_ID_LEN_OFFSET 36

typedef struct {
    int num_pairings;
    int num_admins;
} CountContext;

static HAPError CountPairingsCallback(
        void* _Nullable context,
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain,
        HAPPlatformKeyValueStoreKey key,
        bool* shouldContinue) {
    CountContext* ctx = context;
    uint8_t bytes[PAIRING_RECORD_SIZE];
    size_t numBytes = 0;
    bool found = false;
    HAPError err = HAPPlatformKeyValueStoreGet(keyValueStore, domain, key, bytes, sizeof(bytes), &numBytes, &found);
    if (err != kHAPError_None) {
        return err;
    }
    if (found && numBytes == sizeof(bytes)) {
        ctx->num_pairings++;
        if (bytes[PAIRING_PERMS_OFFSET] & 0x01) {
            ctx->num_admins++;
        }
    }
    *shouldContinue = true;
    return kHAPError_None;
}

static void CopyId(char* dst, size_t dstSize, const uint8_t* id, size_t idLen) {
    size_t n = idLen < dstSize - 1 ? idLen : dstSize - 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = id[i];
        dst[i] = (c >= 0x20 && c < 0x7f) ? (char) c : '?';
    }
    dst[n] = '\0';
}

__attribute__((weak)) void mgos_hap_pairing_event(const struct mgos_hap_pairing_event* ev) {
    (void) ev;
}

void HAPPairingEventNotify(
        HAPPlatformKeyValueStoreRef keyValueStore,
        const HAPSessionRef* _Nullable session_,
        const char* event,
        const uint8_t* _Nullable id,
        size_t idLen,
        int permissions) {
    struct mgos_hap_pairing_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.event = event;
    ev.subject_perms = permissions;
    ev.requester_perms = -1;
    ev.requester_key = -1;
    if (id != NULL) {
        CopyId(ev.subject_id, sizeof(ev.subject_id), id, idLen);
    }

    CountContext counts = { 0, 0 };
    if (HAPPlatformKeyValueStoreEnumerate(
                keyValueStore, kHAPKeyValueStoreDomain_Pairings, CountPairingsCallback, &counts) != kHAPError_None) {
        counts.num_pairings = counts.num_admins = -1;
    }
    ev.num_pairings = counts.num_pairings;
    ev.num_admins = counts.num_admins;

    const HAPSession* session = (const HAPSession*) session_;
    if (session != NULL) {
        ev.has_session = true;
        // The peer is the stream most recently read, which is the requester for a synchronously handled request.
        strncpy(ev.peer, HAPPlatformTCPStreamLastPeer(), sizeof(ev.peer) - 1);
        if (session->hap.active && session->hap.pairingID >= 0) {
            ev.requester_key = session->hap.pairingID;
            uint8_t bytes[PAIRING_RECORD_SIZE];
            size_t numBytes = 0;
            bool found = false;
            if (HAPPlatformKeyValueStoreGet(
                        keyValueStore,
                        kHAPKeyValueStoreDomain_Pairings,
                        (HAPPlatformKeyValueStoreKey) session->hap.pairingID,
                        bytes,
                        sizeof(bytes),
                        &numBytes,
                        &found) == kHAPError_None &&
                found && numBytes == sizeof(bytes)) {
                CopyId(ev.requester_id, sizeof(ev.requester_id), bytes, bytes[PAIRING_ID_LEN_OFFSET]);
                ev.requester_perms = bytes[PAIRING_PERMS_OFFSET];
            }
        }
    }

#if CS_PLATFORM != CS_P_ESP8266
    // Gen1 has no room for this string; it relies on the app-persisted record alone.
    LOG(LL_WARN,
        ("HAP pairing event %s subj %s p %d req %s/%d p %d peer %s n %d/%d",
         ev.event,
         ev.subject_id,
         ev.subject_perms,
         ev.requester_id,
         ev.requester_key,
         ev.requester_perms,
         ev.peer,
         ev.num_pairings,
         ev.num_admins));
#endif
    mgos_hap_pairing_event(&ev);
}
