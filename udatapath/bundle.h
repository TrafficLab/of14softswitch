/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil
 * Copyright (c) 2013, Netronome Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef BUNDLE_H
#define BUNDLE_H 1
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "pipeline.h"
#include "timeval.h"

/****************************************************************************
 * Implementation of a bundle message.
 ****************************************************************************/

struct bundle_message {
    struct list        node;
    struct ofp_header *message;
};

/****************************************************************************
 * Implementation of a bundle table entry.
 ****************************************************************************/

struct bundle_table_entry {
    struct list        node;
    struct list        bundle_message_list;
    uint32_t           bundle_id;
    uint16_t           flags;
    bool               closed;
};

/****************************************************************************
 * Implementation of a bundle table.
 ****************************************************************************/

struct bundle_table {
    struct datapath *dp;
    struct list      bundle_table_entries;  /* List of entries in random order. */
};

/* Create a bundle table. */
struct bundle_table *
bundle_table_create(struct datapath *dp);

/* Destroy a bundle table. */
void
bundle_table_destroy(struct bundle_table *table);


/****************************************************************************
 * Handlers for messages.
 ****************************************************************************/

ofl_err
bundle_handle_control(struct datapath *dp,
                      struct bundle_table *table,
                      struct ofl_msg_bundle_control *ctl,
                      const struct sender *sender);

ofl_err
bundle_handle_append(struct bundle_table *table,
                     struct ofl_msg_bundle_append *append,
                     const struct sender *sender);

#endif /* BUNDLE_H */
