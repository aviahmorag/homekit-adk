/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mgos_hap_pairing_event {
    const char* event;
    // Pairing identifiers are 36-char UUID strings; requester is the controller whose session made the request.
    char subject_id[37];
    int subject_perms;
    char requester_id[37];
    int requester_perms;
    int requester_key;
    bool has_session;
    char peer[48];
    // Counts BEFORE the mutation is applied.
    int num_pairings;
    int num_admins;
};

// Called for every pairing-store mutation; the default is a no-op. Override in the app to persist events.
void mgos_hap_pairing_event(const struct mgos_hap_pairing_event* ev);

#ifdef __cplusplus
}
#endif
