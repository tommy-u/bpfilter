/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>
#include <string.h>

#include "core/chain.h"
#include "core/front.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "libbpfilter/generic.h"

int bf_cli_set_chain(const struct bf_chain *chain)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    int r;

    r = bf_chain_marsh(chain, &marsh);
    if (r)
        return bf_err_r(r, "failed to marsh chain");

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_SET_RULES;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

// How to send the chain to the daemon
int bf_cli_get_ctrs(const char *chain_name, const char *rule_name, uint64_t *ctr_response)
{
    fprintf(stderr, "bf_cli_get_ctrs\n");
    // Copying the origional function for now
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;


    // Allocate char buffer size of chain name and rule name
    // + : + null terminator
    char *chain_name_buf = calloc(strlen(chain_name) + strlen(rule_name) + 1 + 1, sizeof(char));
    if (!chain_name_buf) {
        return bf_err_r(-1, "failed to allocate memory for chain_name_buf");
    }

    // Copy chain name and rule name into char buffer
    strcpy(chain_name_buf, chain_name);
    strcat(chain_name_buf, ":");
    strcat(chain_name_buf, rule_name);

    // print out the string
    fprintf(stderr, "chain_name_buf: %s\n", chain_name_buf);
    // print out the size
    fprintf(stderr, "chain_name_buf size: %lu\n", strlen(chain_name_buf));

    // r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    r = bf_request_new(&request, chain_name_buf, strlen(chain_name_buf) + 1);
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_GET_COUNTERS;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    free(chain_name_buf);

    ctr_response[0] = *(uint64_t *) response->data;
    ctr_response[1] = *(uint64_t *) (response->data + 8);

    return response->type == BF_RES_FAILURE ? response->error : 0;
}
