/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/verdict.h"

struct bf_marsh;
struct bf_rule;

#define _cleanup_bf_chain_ __attribute__((cleanup(bf_chain_free)))

/**
 * Convenience macro to initialize a list of @ref bf_chain .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_chain objects.
 */
#define bf_chain_list()                                                        \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_chain_free,               \
                        .marsh = (bf_list_ops_marsh)bf_chain_marsh}})

struct bf_chain
{
    enum bf_hook hook;
    struct bf_hook_opts hook_opts;

    enum bf_verdict policy;
    bf_list sets;
    bf_list rules;
};

/**
 * Allocate and initialize a new bf_chain object.
 *
 * The rules defined in @p rules are stolen by the constructor. Hence, @p rules
 * will still exist after the function succeeds, but it will be empty. If the
 * function fails during the copy of the rules, then only the rules that haven't
 * be copied yet are still in @p rules .
 *
 * @param chain Chain to allocate an intialize. Can't be NULL.
 * @param hook Kernel attach point.
 * @param policy Default action of the chain if no rule matched.
 * @param sets List of sets used by @p rules . The content of the list will be
 *        stolen. On success, @p sets will be in a usable state, but empty.
 * @param rules List of rules.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_chain_new(struct bf_chain **chain, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules);

/**
 * Allocate a new chain object and intialize it from serialized data.
 *
 * @param chain On success, points to the newly allocated and initialized chain
 *        object. Can't be NULL.
 * @param marsh Serialized data to use to initialize the chain object. Can't be
 *        NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_chain_new_from_marsh(struct bf_chain **chain,
                            const struct bf_marsh *marsh);

/**
 * Deinitialise and deallocate a chain object.
 *
 * @param chain Chain object. Can't be NULL.
 */
void bf_chain_free(struct bf_chain **chain);

/**
 * Serialize a chain object.
 *
 * @param chain Chain object to serialize. Can't be NULL.
 * @param marsh On success, contains the serialized chain object. Can't be NULL.
 */
int bf_chain_marsh(const struct bf_chain *chain, struct bf_marsh **marsh);

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix);

/**
 * Insert a rule into the chain.
 *
 * The chain will own the rule and is responsible for freeing it. The rule's
 * index will automatically be updated.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param rule Rule to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule);
