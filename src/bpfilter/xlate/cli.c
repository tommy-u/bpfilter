/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/ctx.h"
#include "bpfilter/xlate/front.h"
#include "core/chain.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"

// For variable argument functions
#include <stdarg.h>

// Define ANSI color codes as macros
#define NORMAL "\033[0m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RED "\033[1;31m"
// General function to print colored text
void fprintf_color(FILE *stream, const char *color, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stream, "%s", color);  // Set text color
    vfprintf(stream, format, args);
    fprintf(stream, "%s", NORMAL); // Reset text color to normal
    va_end(args);
}
#define fprintf_green(stream, format, ...) fprintf_color(stream, GREEN, format, ##__VA_ARGS__)
#define fprintf_yellow(stream, format, ...) fprintf_color(stream, YELLOW, format, ##__VA_ARGS__)
#define fprintf_red(stream, format, ...) fprintf_color(stream, RED, format, ##__VA_ARGS__)

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

int _bf_cli_get_ctrs(const struct bf_request *request,
                     struct bf_response **response)
{
    bf_assert(request);
    bf_assert(response);

    // Get characters up to the colon and store as chain string
    char *chain_str = strtok((char *)request->data, ":");

    // Get characters after the colon and store as rule string
    char *rule_str = strtok(NULL, ":");

    fprintf_red(stderr, "pretend to lookup chain and rule here\n");

    // print the chain and rule strings
    fprintf_green(stderr, "chain: %s, rule: %s\n", chain_str, rule_str);

    // query the map for the given chain and rule and return the counters

    int response_val = 42;
    return bf_response_new_success(response, (const char *) &response_val, sizeof(int));
}

int _bf_cli_set_rules(const struct bf_request *request,
                      struct bf_response **response)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen;
    int r;

    bf_assert(request);
    bf_assert(response);

    r = bf_chain_new_from_marsh(&chain, (void *)request->data);
    if (r)
        return bf_err_r(r, "failed to create chain from marsh");

    cgen = bf_ctx_get_cgen(chain->hook, &chain->hook_opts);
    if (!cgen) {
        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            return r;

        r = bf_cgen_up(cgen);
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
        r = bf_cgen_update(cgen, &chain);
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

    if (request->data_len < sizeof(struct bf_marsh))
        return bf_response_new_failure(response, -EINVAL);

    switch (request->cmd) {
    case BF_REQ_SET_RULES:
        r = _bf_cli_set_rules(request, response);
        break;
    case BF_REQ_GET_COUNTERS:
        r = _bf_cli_get_ctrs(request, response);
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
