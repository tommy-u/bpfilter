/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/ctx.h"
#include "bpfilter/xlate/front.h"
#include "core/chain.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"

static int _bf_cli_setup(void);
static int _bf_cli_teardown(void);
static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_cli_marsh(struct bf_marsh **marsh);
static int _bf_cli_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops cli_front = {
    .setup = _bf_cli_setup,
    .teardown = _bf_cli_teardown,
    .request_handler = _bf_cli_request_handler,
    .marsh = _bf_cli_marsh,
    .unmarsh = _bf_cli_unmarsh,
};

static int _bf_cli_setup(void)
{
    return 0;
}

static int _bf_cli_teardown(void)
{
    return 0;
}

int _bf_cli_ruleset_flush(const struct bf_request *request,
                          struct bf_response **response)
{
    int r;

    UNUSED(request);

    r = bf_ctx_flush();
    if (r)
        return bf_err_r(r, "failed to flush the context");

    return bf_response_new_success(response, NULL, 0);
}

static size_t _bf_cli_num_rules(bf_list *chains)
{
    bf_assert(chains);

    size_t count = 0;
    bf_list_foreach (chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);

        count += bf_list_size(&chain->rules);
    }

    return count;
}

static int _bf_get_ctr_vals(bf_list *chains, struct bf_counter *counters)
{
    int counter_index = 0;
    int r;

    bf_assert(chains && counters);

    bf_list_foreach (chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);

        struct bf_cgen *cgen = bf_ctx_get_cgen(chain->hook, NULL);
        if (!cgen)
            bf_err("got a null cgen for chain element\n");

        // Iterate over each rule in the current chain
        int map_idx = 0;
        bf_list_foreach (&chain->rules, rule_node) {
            struct bf_rule *rule = bf_list_node_get_data(rule_node);
            if (!chain)
                bf_err("rule list element pointed to null data\n");

            if (rule->counters) {
                // Query the BPF map for the counter values
                r = bf_cgen_get_counter(cgen, map_idx,
                                        &counters[counter_index]);
                if (r < 0)
                    return bf_err_r(r, "failed to get rule counter\n");
            }

            /* Note: The map has entries for every rule regardless of whether the
             * input rule specified "COUNTERS" or not. Thus, advancing map_index
             * is unconditional. When rule->counters == false, the corresponding
             * counter value will remain {0,0}. */
            counter_index++;
            map_idx++;
        }

        // Chain's policy counter
        r = bf_cgen_get_counter(cgen, BF_COUNTER_POLICY,
                                &counters[counter_index]);
        if (r < 0)
            return bf_err_r(r, "failed to get policy counter\n");
        counter_index++;

        // Chain's error counter
        r = bf_cgen_get_counter(cgen, BF_COUNTER_ERRORS,
                                &counters[counter_index]);
        if (r < 0)
            return bf_err_r(r, "failed to get error counter\n");
    }

    return 0;
}

static int _bf_cli_get_chain_list(bf_list **chains)
{
    _cleanup_bf_list_ bf_list *_chains = NULL;
    bf_list_ops ops = {// chains will only contain the chains, not own them.
                       .free = (bf_list_ops_free)bf_list_nop_free,
                       .marsh = (bf_list_ops_marsh)bf_chain_marsh};

    int r = bf_list_new(&_chains, &ops);
    if (r < 0)
        return bf_err_r(r, "failed to create the chain list");

    // Loop over codegens which correspond to hooks
    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        struct bf_cgen *cgen;

        cgen = bf_ctx_get_cgen(i, NULL);

        if (!cgen || !cgen->chain)
            continue;

        r = bf_list_add_tail(_chains, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to add chain to list");
    }

    *chains = TAKE_PTR(_chains);

    return 0;
}

static int _bf_cli_get_counters_marsh(struct bf_marsh **counter_marsh,
                                      bf_list *chains, bool with_counters)
{
    int r;
    size_t num_counters = 0;
    _cleanup_free_ struct bf_counter *counters = NULL;

    bf_assert(counter_marsh && chains);

    // If we don't want counters, return an empty marsh
    if (!with_counters) {
        r = bf_marsh_new(counter_marsh, NULL, 0);
        return r;
    }

    /* Each chain has a policy counter and an error counter.
     * Each rule has a counter, though it may be unused. */
    num_counters = (2 * bf_list_size(chains)) + _bf_cli_num_rules(chains);

    counters = calloc(num_counters, sizeof(struct bf_counter));
    if (!counters)
        bf_err_r(-ENOMEM, "failed to allocate memory for counters\n");

    r = _bf_get_ctr_vals(chains, counters);
    if (r < 0)
        return bf_err_r(r, "could not get ctr vals\n");

    size_t marsh_size = num_counters * sizeof(struct bf_counter);

    r = bf_marsh_new(counter_marsh, counters, marsh_size);
    if (r < 0)
        if (r < 0)
            return bf_err_r(r, "failed to make new marsh\n");

    return 0;
}

static int _bf_cli_get_rules(const struct bf_request *request,
                             struct bf_response **response)
{
    _cleanup_bf_marsh_ struct bf_marsh *chains_marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *counter_marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *result_marsh = NULL;
    int r;

    // Empty context, nothing to return
    if (bf_ctx_is_empty())
        return bf_response_new_success(response, NULL, 0);

    {
        _cleanup_bf_list_ bf_list *chains = NULL;

        r = _bf_cli_get_chain_list(&chains);
        if (r < 0)
            return bf_err_r(r, "failed to create the chain list");

        // Marsh the chain list
        r = bf_list_marsh(chains, &chains_marsh);
        if (r < 0)
            return bf_err_r(r, "failed to marshal list\n");

        // Marsh the counters
        r = _bf_cli_get_counters_marsh(&counter_marsh, chains,
                                       request->cli_with_counters);
        if (r < 0)
            return bf_err_r(r, "failed to get counters marsh\n");
    }

    // Marsh the chain list and counters marshes into a single response
    r = bf_marsh_new(&result_marsh, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to get new marsh\n");

    r = bf_marsh_add_child_obj(&result_marsh, chains_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add chain list to marsh\n");

    r = bf_marsh_add_child_obj(&result_marsh, counter_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add counter to marsh\n");

    return bf_response_new_success(response, (void *)result_marsh,
                                   bf_marsh_size(result_marsh));
}

int _bf_cli_set_rules(const struct bf_request *request,
                      struct bf_response **response)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen;
    int r;

    bf_assert(request);
    bf_assert(response);

    if (request->data_len < sizeof(struct bf_marsh))
        return bf_response_new_failure(response, -EINVAL);

    r = bf_chain_new_from_marsh(&chain, (void *)request->data);
    if (r)
        return bf_err_r(r, "failed to create chain from marsh");

    cgen = bf_ctx_get_cgen(chain->hook, &chain->hook_opts);
    if (!cgen) {
        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            return r;

        r = bf_cgen_up(cgen, request->ns);
        if (r < 0) {
            bf_cgen_free(&cgen);
            return bf_err_r(r, "failed to generate and load new program");
        }

        r = bf_ctx_set_cgen(cgen);
        if (r < 0) {
            bf_cgen_free(&cgen);
            return bf_err_r(r, "failed to store codegen in runtime context");
        }
    } else {
        r = bf_cgen_update(cgen, &chain, request->ns);
        if (r < 0)
            return bf_warn_r(r, "failed to update existing codegen");
    }

    return bf_response_new_success(response, NULL, 0);
}

static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    bf_assert(request);
    bf_assert(response);

    switch (request->cmd) {
    case BF_REQ_RULESET_FLUSH:
        r = _bf_cli_ruleset_flush(request, response);
        break;
    case BF_REQ_RULES_SET:
        r = _bf_cli_set_rules(request, response);
        break;
    case BF_REQ_RULES_GET:
        r = _bf_cli_get_rules(request, response);
        break;
    default:
        r = bf_err_r(-EINVAL, "unsupported command %d for CLI front-end",
                     request->cmd);
        break;
    }

    return r;
}

static int _bf_cli_marsh(struct bf_marsh **marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _bf_cli_unmarsh(struct bf_marsh *marsh)
{
    UNUSED(marsh);

    return 0;
}
