/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "print.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/rule.h"
#include "core/verdict.h"

#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

/**
 * Dump a block of memory in hexadecimal format.
 *
 * @param data Pointer to the data to be dumped. Must be non-NULL.
 * @param len Length of the data in bytes.
 */
static void bf_dump_hex_local(const void *data, size_t len)
{
    bf_assert(data);
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];
    const void *end = data + len;

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        (void)fprintf(stderr, "%s", buf);
    }
}

/**
 * Dump the details of a chain, including its rules and counters.
 *
 * @param chain Pointer to the chain to be dumped. Must be non-NULL.
 * @param with_counters Boolean flag indicating whether to include
 *        counters in the dump.
 * @param counter Pointer to the array of counters associated with the
 *        chain. Must be non-NULL if with_counters is true.
 */
static int bf_cli_chain_dump(struct bf_chain *chain, bool with_counters,
                             bf_list *counters)
{
    bf_assert(chain);
    bf_assert(!with_counters || counters);

    struct bf_hook_opts *opts = &chain->hook_opts;
    struct bf_counter *counter = NULL;

    (void)fprintf(stderr, "chain %s", bf_hook_to_str(chain->hook));
    (void)fprintf(stderr, "{");

    (void)fprintf(stderr, "attach=%s,", opts->attach ? "yes" : "no");
    (void)fprintf(stderr, "ifindex=%d", opts->ifindex);
    if (opts->name)
        (void)fprintf(stderr, ",name=%s", opts->name);
    (void)fprintf(stderr, "}");
    (void)fprintf(stderr, " policy: %s\n", bf_verdict_to_str(chain->policy));

    if (with_counters) {
        /**
         * Rule counters are followed by policy and error counters.
         * These bf_list_get_at() calls cost linear time.
        */
        counter = (struct bf_counter *)bf_list_get_at(
            counters, bf_list_size(&chain->rules));
        if (!counter) {
            return bf_err_r(-ENOENT, "got null policy counter\n");
        }

        (void)fprintf(stderr, "\tcounters: policy %lu bytes %lu packets; ",
                      counter->bytes, counter->packets);

        counter = (struct bf_counter *)bf_list_get_at(
            counters, bf_list_size(&chain->rules) + 1);
        if (!counter) {
            return bf_err_r(-ENOENT, "got null error counter\n");
        }

        (void)fprintf(stderr, "error %lu bytes %lu packets\n", counter->bytes,
                      counter->packets);
    }

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stderr, "\trule: %d\n", rule->index);
        // Matchers
        (void)fprintf(stderr, "\t\tmatcher(s):\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            (void)fprintf(stderr, "\t\t\t\%s",
                          bf_matcher_type_to_str(matcher->type));
            (void)fprintf(stderr, " %s ", bf_matcher_op_to_str(matcher->op));

            bf_dump_hex_local(matcher->payload,
                              matcher->len - sizeof(struct bf_matcher));
            (void)fprintf(stderr, "\n");
        }

        // Print the counters and remove the head
        if (with_counters && rule->counters) {
            struct bf_list_node *head = bf_list_get_head(counters);
            if (!head) {
                return bf_err_r(-ENOENT, "no entry in list \n");
            }

            counter = (struct bf_counter *)bf_list_node_get_data(head);
            if (!counter) {
                return bf_err_r(-ENOENT, "got null error counter\n");
            }

            (void)fprintf(stderr, "\t\tcounters: %lu bytes %lu packets\n",
                          counter->bytes, counter->packets);
            bf_list_delete(counters, head);
        }

        (void)fprintf(stderr, "\t\tverdict: %s\n",
                      bf_verdict_to_str(rule->verdict));
    }

    if (with_counters) {
        // remove the next 2 counters for privacy and error
        bf_list_delete(counters, bf_list_get_head(counters));
        bf_list_delete(counters, bf_list_get_head(counters));
    }

    (void)fprintf(stderr, "\n");

    return 0;
}

int bf_cli_dump_ruleset(struct bf_marsh *chains_and_counters_marsh,
                        bool with_counters)
{
    struct bf_marsh *chains_marsh, *chain_marsh = NULL, *counters_marsh;
    // struct bf_counter *counters;
    int r;

    bf_assert(chains_and_counters_marsh);

    // Get the chain list
    chains_marsh = bf_marsh_next_child(chains_and_counters_marsh, NULL);
    if (!chains_marsh) {
        bf_err("failed to locate chain list from daemon response\n");
        return -EINVAL;
    }

    // Get the marshaled list of counters
    counters_marsh =
        bf_marsh_next_child(chains_and_counters_marsh, chains_marsh);
    if (!counters_marsh) {
        bf_err("failed to locate counter array from daemon response\n");
        return -EINVAL;
    }

    _clean_bf_list_ bf_list counters = bf_list_default(bf_counter_free, NULL);

    struct bf_marsh *child = NULL;
    while (true) {
        _cleanup_bf_counter_ struct bf_counter *counter = NULL;

        // Get the next child
        child = bf_marsh_next_child(counters_marsh, child);
        if (!child) {
            break;
        }

        r = bf_counter_new_from_marsh(&counter, child);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh counter");

        r = bf_list_add_tail(&counters, counter);
        TAKE_PTR(counter);
    }

    // Loop over the chains
    while (true) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;

        // Get the next child
        chain_marsh = bf_marsh_next_child(chains_marsh, chain_marsh);
        if (!chain_marsh) {
            break;
        }

        r = bf_chain_new_from_marsh(&chain, chain_marsh);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh chain");

        r = bf_cli_chain_dump(chain, with_counters, &counters);
        if (r < 0)
            return bf_err_r(r, "failed to dump chain");
    }

    return 0;
}
