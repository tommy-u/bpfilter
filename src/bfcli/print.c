/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "print.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
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
 * @param chain Chain to be dumped. Can't be NULL.
 * @param counters List of counters to be dumped. Can't be NULL if
 *                 with_counters is true.
 * @param with_counters Boolean flag indicating whether to include
 *        counters in the dump.
 */
static int bf_cli_chain_dump(struct bf_chain *chain, bf_list *counters,
                             bool with_counters)
{
    struct bf_hook_opts *opts = &chain->hook_opts;
    struct bf_counter *counter = NULL;
    uint32_t used_opts = chain->hook_opts.used_opts;
    bool need_comma = false;

    bf_assert(chain);
    bf_assert(!with_counters || counters);

    (void)fprintf(stderr, "chain %s", bf_hook_to_str(chain->hook));
    (void)fprintf(stderr, "{");

    if (used_opts & (1 << BF_HOOK_OPT_ATTACH)) {
        (void)fprintf(stderr, "attach=%s", opts->attach ? "yes" : "no");
        need_comma = true;
    }

    if (used_opts & (1 << BF_HOOK_OPT_IFINDEX)) {
        if (need_comma)
            (void)fprintf(stderr, ",");
        (void)fprintf(stderr, "ifindex=%d", opts->ifindex);
        need_comma = true;
    }

    if (used_opts & (1 << BF_HOOK_OPT_NAME)) {
        if (need_comma)
            (void)fprintf(stderr, ",");
        (void)fprintf(stderr, "name=%s", opts->name);
        need_comma = true;
    }

    (void)fprintf(stderr, "}");
    (void)fprintf(stderr, " policy: %s\n", bf_verdict_to_str(chain->policy));

    if (with_counters) {
        // List order is Error, Policy, and then Rules counters.
        struct bf_list_node *error_node, *policy_node;

        error_node = bf_list_get_head(counters);
        if (!error_node)
            return bf_err_r(-ENOENT, "expected error counter\n");

        policy_node = bf_list_node_next(error_node);
        if (!policy_node)
            return bf_err_r(-ENOENT, "expected policy counter\n");

        counter = bf_list_node_get_data(policy_node);
        (void)fprintf(stderr, "    counters policy %lu packets %lu bytes; ",
                      counter->packets, counter->bytes);
        bf_list_delete(counters, policy_node);

        counter = (struct bf_counter *)bf_list_node_get_data(error_node);
        (void)fprintf(stderr, "error %lu packets %lu bytes \n",
                      counter->packets, counter->bytes);

        bf_list_delete(counters, bf_list_get_head(counters));
    }

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stderr, "    rule\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            (void)fprintf(stderr, "        \%s",
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

            (void)fprintf(stderr, "        counters %lu packets %lu bytes\n",
                          counter->packets, counter->bytes);
            bf_list_delete(counters, head);
        }

        (void)fprintf(stderr, "        %s\n", bf_verdict_to_str(rule->verdict));
    }

    (void)fprintf(stderr, "\n");

    return 0;
}

int bf_cli_dump_ruleset(bf_list *chains, bf_list *counters, bool with_counters)
{
    int r;

    bf_assert(chains);
    bf_assert(!with_counters || counters);

    // loop over all chains and print them
    bf_list_foreach (chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);

        r = bf_cli_chain_dump(chain, counters, with_counters);
        if (r < 0)
            return bf_err_r(r, "failed to dump chain");
    }

    return 0;
}
