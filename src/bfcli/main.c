/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"

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

int bf_send(const struct bf_request *request, struct bf_response **response);

// Unsure if all these are needed
static struct bf_options
{
    const char *input_file;
    const char *input_string;
    bool get_ctrs;
    const char *chain_name;
    const char *rule_name;
} _bf_opts = {
    .input_file = NULL,
    .get_ctrs = false,
    .chain_name = NULL,
    .rule_name = NULL,
};

static struct argp_option options[] = {
    {"file", 'f', "INPUT_FILE", 0, "Input file to use a rules source", 0},
    {"str", 's', "INPUT_STRING", 0, "String to use as rules", 0},
    {"get-ctrs", 'g', "CHAIN_NAME::RULE_NAME", 0, "Get counters for chain CHAIN_NAME and rule RULE_NAME", 0},
    {0},
};

static error_t _bf_opts_parser(int key, const char *arg,
                               struct argp_state *state)
{
    UNUSED(arg);

    struct bf_options *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = arg;
        break;
    case 's':
        opts->input_string = arg;
        break;
    case 'g':
        // Handle the "get-ctrs" subcommand
        char *chain_name, *rule_name, *colon_ptr;
        colon_ptr = strchr(arg, ':');
        if (!colon_ptr) {
            return bf_err_r(-EINVAL, "Invalid get-ctrs argument, expected <chain>:<rule>");
        }
        // this allocated memory. prob want to change it
        chain_name = strndup(arg, colon_ptr - arg);
        rule_name = strdup(colon_ptr + 1);

        opts->chain_name = chain_name;
        opts->rule_name = rule_name;

        opts->get_ctrs = true;

        fprintf(stderr, "Done configuring g case\n");
        break;
    case ARGP_KEY_END:
        if (opts->get_ctrs) return 0;

        if (!opts->input_file && !opts->input_string)
            return bf_err_r(-EINVAL, "--file or --str argument is required");
        if (opts->input_file && opts->input_string)
            return bf_err_r(-EINVAL, "--file is incompatible with --str");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_cli_parse_file(const char *file, struct bf_ruleset *ruleset)
{
    FILE *rules;
    int r;

    rules = fopen(file, "r");
    if (!rules) {
        return bf_err_r(errno,
                        "failed to read rules from %s:", _bf_opts.input_file);
    }

    yyin = rules;

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    return r;
}

static int _bf_cli_parse_str(const char *str, struct bf_ruleset *ruleset)
{
    YY_BUFFER_STATE buffer;
    int r;

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}

int main(int argc, char *argv[])
{
    struct argp argp = {
        options, (argp_parser_t)_bf_opts_parser, NULL, NULL, 0, NULL, NULL};
    struct bf_ruleset ruleset = {
        .chains = bf_chain_list(),
        .sets = bf_set_list(),
    };
    int r;

    bf_logger_setup();

    r = argp_parse(&argp, argc, argv, 0, 0, &_bf_opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (! _bf_opts.get_ctrs) {
        if (_bf_opts.input_file)
            r = _bf_cli_parse_file(_bf_opts.input_file, &ruleset);
        else
            r = _bf_cli_parse_str(_bf_opts.input_string, &ruleset);
        if (r) {
            bf_err_r(r, "failed to parse ruleset");
            goto end_clean;
        }
    }

    // Set rules indexes
    bf_list_foreach (&ruleset.chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        uint32_t index = 0;

        bf_list_foreach (&chain->rules, rule_node) {
            struct bf_rule *rule = bf_list_node_get_data(rule_node);
            rule->index = index++;
        }
    }

    // Send the chains to the daemon
    bf_list_foreach (&ruleset.chains, chain_node) {
        const struct bf_chain *chain = bf_list_node_get_data(chain_node);

        r = bf_cli_set_chain(chain);
        if (r < 0) {
            bf_err("failed to set chain for '%s', skipping remaining chains",
                   bf_hook_to_str(chain->hook));
            goto end_clean;
        }
    }

    if (_bf_opts.get_ctrs) {
        fprintf(stderr, "This is the magic ctrs request\n");
        uint64_t ctr_vals[2];
        r = bf_cli_get_ctrs(_bf_opts.chain_name, _bf_opts.rule_name, ctr_vals);

        fprintf_green(stderr, "packets: %d\n", ctr_vals[0]);
        fprintf_green(stderr, "bytes:   %d\n", ctr_vals[1]);

    }


end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);

    return r;
}

void yyerror(struct bf_ruleset *ruleset, const char *fmt, ...)
{
    UNUSED(ruleset);

    va_list args;

    va_start(args, fmt);
    bf_err_v(fmt, args);
    va_end(args);
}
