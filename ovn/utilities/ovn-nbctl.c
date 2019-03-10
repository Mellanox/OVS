/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "command-line.h"
#include "daemon.h"
#include "db-ctl-base.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "jsonrpc.h"
#include "openvswitch/json.h"
#include "ovn/lib/acl-log.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "svec.h"
#include "table.h"
#include "timeval.h"
#include "timer.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(nbctl);

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --wait=TYPE: Wait for configuration change to take effect? */
enum nbctl_wait_type {
    NBCTL_WAIT_NONE,            /* Do not wait. */
    NBCTL_WAIT_SB,              /* Wait for southbound database updates. */
    NBCTL_WAIT_HV               /* Wait for hypervisors to catch up. */
};
static enum nbctl_wait_type wait_type = NBCTL_WAIT_NONE;

/* Should we wait (if specified by 'wait_type') even if the commands don't
 * change the database at all? */
static bool force_wait = false;

/* --timeout: Time to wait for a connection to 'db'. */
static unsigned int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* The IDL we're using and the current transaction, if any.
 * This is for use by nbctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;
OVS_NO_RETURN static void nbctl_exit(int status);

/* --leader-only, --no-leader-only: Only accept the leader in a cluster. */
static int leader_only = true;

/* --unixctl-path: Path to use for unixctl server, for "monitor" and "snoop"
     commands. */
static char *unixctl_path;

static unixctl_cb_func server_cmd_exit;
static unixctl_cb_func server_cmd_run;

static void nbctl_cmd_init(void);
OVS_NO_RETURN static void usage(void);
static struct option *get_all_options(void);
static bool has_option(const struct ovs_cmdl_parsed_option *, size_t n,
                       int option);
static void nbctl_client(const char *socket_name,
                         const struct ovs_cmdl_parsed_option *, size_t n,
                         int argc, char *argv[]);
static bool will_detach(const struct ovs_cmdl_parsed_option *, size_t n);
static void apply_options_direct(const struct ovs_cmdl_parsed_option *,
                                 size_t n, struct shash *local_options);
static char * OVS_WARN_UNUSED_RESULT run_prerequisites(struct ctl_command[],
                                                       size_t n_commands,
                                                       struct ovsdb_idl *);
static char * OVS_WARN_UNUSED_RESULT do_nbctl(const char *args,
                                              struct ctl_command *, size_t n,
                                              struct ovsdb_idl *,
                                              const struct timer *,
                                              bool *retry);
static char * OVS_WARN_UNUSED_RESULT dhcp_options_get(
    struct ctl_context *ctx, const char *id, bool must_exist,
    const struct nbrec_dhcp_options **);
static char * OVS_WARN_UNUSED_RESULT main_loop(const char *args,
                                               struct ctl_command *commands,
                                               size_t n_commands,
                                               struct ovsdb_idl *idl,
                                               const struct timer *);
static void server_loop(struct ovsdb_idl *idl, int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    struct shash local_options;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");

    nbctl_cmd_init();

    /* ovn-nbctl has three operation modes:
     *
     *    - Direct: Executes commands by contacting ovsdb-server directly.
     *
     *    - Server: Runs in the background as a daemon waiting for requests
     *      from ovn-nbctl running in client mode.
     *
     *    - Client: Executes commands by passing them to an ovn-nbctl running
     *      in the server mode.
     *
     * At this point we don't know what mode we're running in.  The mode partly
     * depends on the command line.  So, for now we transform the command line
     * into a parsed form, and figure out what to do with it later.
     */
    char *args = process_escape_args(argv);
    struct ovs_cmdl_parsed_option *parsed_options;
    size_t n_parsed_options;
    char *error_s = ovs_cmdl_parse_all(argc, argv, get_all_options(),
                                       &parsed_options, &n_parsed_options);
    if (error_s) {
        ctl_fatal("%s", error_s);
    }

    /* Now figure out the operation mode:
     *
     *    - A --detach option implies server mode.
     *
     *    - An OVN_NB_DAEMON environment variable implies client mode.
     *
     *    - Otherwise, we're in direct mode. */
    char *socket_name = getenv("OVN_NB_DAEMON");
    if (socket_name && socket_name[0]
        && !will_detach(parsed_options, n_parsed_options)) {
        nbctl_client(socket_name, parsed_options, n_parsed_options,
                     argc, argv);
    }

    /* Parse command line. */
    shash_init(&local_options);
    apply_options_direct(parsed_options, n_parsed_options, &local_options);
    free(parsed_options);

    bool daemon_mode = false;
    if (get_detach()) {
        if (argc != optind) {
            ctl_fatal("non-option arguments not supported with --detach "
                      "(use --help for help)");
        }
        daemon_mode = true;
    }
    /* Initialize IDL. "retry" is true iff in daemon mode. */
    idl = the_idl = ovsdb_idl_create(db, &nbrec_idl_class, true, daemon_mode);
    ovsdb_idl_set_leader_only(idl, leader_only);

    if (daemon_mode) {
        server_loop(idl, argc, argv);
    } else {
        struct ctl_command *commands;
        size_t n_commands;
        char *error;

        error = ctl_parse_commands(argc - optind, argv + optind,
                                   &local_options, &commands, &n_commands);
        if (error) {
            ctl_fatal("%s", error);
        }
        VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
             "Called as %s", args);

        ctl_timeout_setup(timeout);

        error = run_prerequisites(commands, n_commands, idl);
        if (error) {
            ctl_fatal("%s", error);
        }

        error = main_loop(args, commands, n_commands, idl, NULL);
        if (error) {
            ctl_fatal("%s", error);
        }

        struct ctl_command *c;
        for (c = commands; c < &commands[n_commands]; c++) {
            ds_destroy(&c->output);
            table_destroy(c->table);
            free(c->table);
            shash_destroy_free_data(&c->options);
        }
        free(commands);
    }

    ovsdb_idl_destroy(idl);
    idl = the_idl = NULL;

    free(args);
    exit(EXIT_SUCCESS);
}

static char *
main_loop(const char *args, struct ctl_command *commands, size_t n_commands,
          struct ovsdb_idl *idl, const struct timer *wait_timeout)
{
    unsigned int seqno;
    bool idl_ready;

    /* Execute the commands.
     *
     * 'seqno' is the database sequence number for which we last tried to
     * execute our transaction.  There's no point in trying to commit more than
     * once for any given sequence number, because if the transaction fails
     * it's because the database changed and we need to obtain an up-to-date
     * view of the database before we try the transaction again. */
    seqno = ovsdb_idl_get_seqno(idl);

    /* IDL might have already obtained the database copy during previous
     * invocation. If so, we can't expect the sequence number to change before
     * we issue any new requests. */
    idl_ready = ovsdb_idl_has_ever_connected(idl);
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                      db, ovs_retval_to_string(retval));
        }

        if (idl_ready || seqno != ovsdb_idl_get_seqno(idl)) {
            idl_ready = false;
            seqno = ovsdb_idl_get_seqno(idl);

            bool retry;
            char *error = do_nbctl(args, commands, n_commands, idl,
                                   wait_timeout, &retry);
            if (error) {
                return error;
            }
            if (!retry) {
                return NULL;
            }
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }

    return NULL;
}

/* All options that affect the main loop and are not external. */
#define MAIN_LOOP_OPTION_ENUMS                  \
        OPT_NO_WAIT,                            \
        OPT_WAIT,                               \
        OPT_DRY_RUN,                            \
        OPT_ONELINE

#define MAIN_LOOP_LONG_OPTIONS                           \
        {"no-wait", no_argument, NULL, OPT_NO_WAIT},     \
        {"wait", required_argument, NULL, OPT_WAIT},     \
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},     \
        {"oneline", no_argument, NULL, OPT_ONELINE},     \
        {"timeout", required_argument, NULL, 't'}

enum {
    OPT_DB = UCHAR_MAX + 1,
    OPT_NO_SYSLOG,
    OPT_LOCAL,
    OPT_COMMANDS,
    OPT_OPTIONS,
    OPT_LEADER_ONLY,
    OPT_NO_LEADER_ONLY,
    OPT_BOOTSTRAP_CA_CERT,
    MAIN_LOOP_OPTION_ENUMS,
    DAEMON_OPTION_ENUMS,
    VLOG_OPTION_ENUMS,
    TABLE_OPTION_ENUMS,
    SSL_OPTION_ENUMS,
};

static char * OVS_WARN_UNUSED_RESULT
handle_main_loop_option(int opt, const char *arg, bool *handled)
{
    ovs_assert(handled);
    *handled = true;

    switch (opt) {
    case OPT_ONELINE:
        oneline = true;
        break;

    case OPT_NO_WAIT:
        wait_type = NBCTL_WAIT_NONE;
        break;

    case OPT_WAIT:
        if (!strcmp(arg, "none")) {
            wait_type = NBCTL_WAIT_NONE;
        } else if (!strcmp(arg, "sb")) {
            wait_type = NBCTL_WAIT_SB;
        } else if (!strcmp(arg, "hv")) {
            wait_type = NBCTL_WAIT_HV;
        } else {
            return xstrdup("argument to --wait must be "
                           "\"none\", \"sb\", or \"hv\"");
        }
        break;

    case OPT_DRY_RUN:
        dry_run = true;
        break;

    case 't':
        if (!str_to_uint(arg, 10, &timeout) || !timeout) {
            return xasprintf("value %s on -t or --timeout is invalid", arg);
        }
        break;

    default:
        *handled = false;
        break;
    }

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
build_short_options(const struct option *long_options, bool print_errors)
{
    char *tmp, *short_options;

    tmp = ovs_cmdl_long_options_to_short_options(long_options);
    short_options = xasprintf("+%s%s", print_errors ? "" : ":", tmp);
    free(tmp);

    return short_options;
}

static struct option * OVS_WARN_UNUSED_RESULT
append_command_options(const struct option *options, int opt_val)
{
    struct option *o;
    size_t n_allocated;
    size_t n_existing;
    int i;

    for (i = 0; options[i].name; i++) {
        ;
    }
    n_allocated = i + 1;
    n_existing = i;

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    o = xmemdup(options, n_allocated * sizeof *options);
    ctl_add_cmd_options(&o, &n_existing, &n_allocated, opt_val);

    return o;
}

static struct option *
get_all_options(void)
{
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"help", no_argument, NULL, 'h'},
        {"commands", no_argument, NULL, OPT_COMMANDS},
        {"options", no_argument, NULL, OPT_OPTIONS},
        {"leader-only", no_argument, NULL, OPT_LEADER_ONLY},
        {"no-leader-only", no_argument, NULL, OPT_NO_LEADER_ONLY},
        {"version", no_argument, NULL, 'V'},
        MAIN_LOOP_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };

    static struct option *options;
    if (!options) {
        options = append_command_options(global_long_options, OPT_LOCAL);
    }

    return options;
}

static bool
has_option(const struct ovs_cmdl_parsed_option *parsed_options, size_t n,
           int option)
{
    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        if (po->o->val == option) {
            return true;
        }
    }
    return false;
}

static bool
will_detach(const struct ovs_cmdl_parsed_option *parsed_options, size_t n)
{
    return has_option(parsed_options, n, OPT_DETACH);
}

static char * OVS_WARN_UNUSED_RESULT
add_local_option(const char *name, const char *arg,
                 struct shash *local_options)
{
    char *full_name = xasprintf("--%s", name);
    if (shash_find(local_options, full_name)) {
        char *error = xasprintf("'%s' option specified multiple times",
                                full_name);
        free(full_name);
        return error;
    }
    shash_add_nocopy(local_options, full_name, nullable_xstrdup(arg));
    return NULL;
}

static void
apply_options_direct(const struct ovs_cmdl_parsed_option *parsed_options,
                     size_t n, struct shash *local_options)
{
    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        bool handled;
        char *error = handle_main_loop_option(po->o->val, po->arg, &handled);
        if (error) {
            ctl_fatal("%s", error);
        }
        if (handled) {
            continue;
        }

        optarg = po->arg;
        switch (po->o->val) {
        case OPT_DB:
            db = po->arg;
            break;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_LOCAL:
            error = add_local_option(po->o->name, po->arg, local_options);
            if (error) {
                ctl_fatal("%s", error);
            }
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case OPT_COMMANDS:
            ctl_print_commands();
            /* fall through */

        case OPT_OPTIONS:
            ctl_print_options(get_all_options());
            /* fall through */

        case OPT_LEADER_ONLY:
            leader_only = true;
            break;

        case OPT_NO_LEADER_ONLY:
            leader_only = false;
            break;

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", nbrec_get_db_version());
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(po->arg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();

        case 0:
            break;
        }
    }

    if (!db) {
        db = default_nb_db();
    }
}

static void
usage(void)
{
    printf("\
%s: OVN northbound DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  init                      initialize the database\n\
  show                      print overview of database contents\n\
  show SWITCH               print overview of database contents for SWITCH\n\
  show ROUTER               print overview of database contents for ROUTER\n\
\n\
Logical switch commands:\n\
  ls-add [SWITCH]           create a logical switch named SWITCH\n\
  ls-del SWITCH             delete SWITCH and all its ports\n\
  ls-list                   print the names of all logical switches\n\
\n\
ACL commands:\n\
  [--type={switch | port-group}] [--log] [--severity=SEVERITY] [--name=NAME] [--may-exist]\n\
  acl-add {SWITCH | PORTGROUP} DIRECTION PRIORITY MATCH ACTION\n\
                            add an ACL to SWITCH/PORTGROUP\n\
  [--type={switch | port-group}]\n\
  acl-del {SWITCH | PORTGROUP} [DIRECTION [PRIORITY MATCH]]\n\
                            remove ACLs from SWITCH/PORTGROUP\n\
  [--type={switch | port-group}]\n\
  acl-list {SWITCH | PORTGROUP}\n\
                            print ACLs for SWITCH\n\
\n\
QoS commands:\n\
  qos-add SWITCH DIRECTION PRIORITY MATCH [rate=RATE [burst=BURST]] [dscp=DSCP]\n\
                            add an QoS rule to SWITCH\n\
  qos-del SWITCH [DIRECTION [PRIORITY MATCH]]\n\
                            remove QoS rules from SWITCH\n\
  qos-list SWITCH           print QoS rules for SWITCH\n\
\n\
Meter commands:\n\
  meter-add NAME ACTION RATE UNIT [BURST]\n\
                            add a meter\n\
  meter-del [NAME]          remove meters\n\
  meter-list                print meters\n\
\n\
Logical switch port commands:\n\
  lsp-add SWITCH PORT       add logical port PORT on SWITCH\n\
  lsp-add SWITCH PORT PARENT TAG\n\
                            add logical port PORT on SWITCH with PARENT\n\
                            on TAG\n\
  lsp-del PORT              delete PORT from its attached switch\n\
  lsp-list SWITCH           print the names of all logical ports on SWITCH\n\
  lsp-get-parent PORT       get the parent of PORT if set\n\
  lsp-get-tag PORT          get the PORT's tag if set\n\
  lsp-set-addresses PORT [ADDRESS]...\n\
                            set MAC or MAC+IP addresses for PORT.\n\
  lsp-get-addresses PORT    get a list of MAC or MAC+IP addresses on PORT\n\
  lsp-set-port-security PORT [ADDRS]...\n\
                            set port security addresses for PORT.\n\
  lsp-get-port-security PORT    get PORT's port security addresses\n\
  lsp-get-up PORT           get state of PORT ('up' or 'down')\n\
  lsp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-set-type PORT TYPE    set the type for PORT\n\
  lsp-get-type PORT         get the type for PORT\n\
  lsp-set-options PORT KEY=VALUE [KEY=VALUE]...\n\
                            set options related to the type of PORT\n\
  lsp-get-options PORT      get the type specific options for PORT\n\
  lsp-set-dhcpv4-options PORT [DHCP_OPTIONS_UUID]\n\
                            set dhcpv4 options for PORT\n\
  lsp-get-dhcpv4-options PORT  get the dhcpv4 options for PORT\n\
  lsp-set-dhcpv6-options PORT [DHCP_OPTIONS_UUID]\n\
                            set dhcpv6 options for PORT\n\
  lsp-get-dhcpv6-options PORT  get the dhcpv6 options for PORT\n\
\n\
Logical router commands:\n\
  lr-add [ROUTER]           create a logical router named ROUTER\n\
  lr-del ROUTER             delete ROUTER and all its ports\n\
  lr-list                   print the names of all logical routers\n\
\n\
Logical router port commands:\n\
  lrp-add ROUTER PORT MAC NETWORK... [peer=PEER]\n\
                            add logical port PORT on ROUTER\n\
  lrp-set-gateway-chassis PORT CHASSIS [PRIORITY]\n\
                            set gateway chassis for port PORT\n\
  lrp-del-gateway-chassis PORT CHASSIS\n\
                            delete gateway chassis from port PORT\n\
  lrp-get-gateway-chassis PORT\n\
                            print the names of all gateway chassis on PORT\n\
                            with PRIORITY\n\
  lrp-del PORT              delete PORT from its attached router\n\
  lrp-list ROUTER           print the names of all ports on ROUTER\n\
  lrp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lrp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
\n\
Route commands:\n\
  [--policy=POLICY] lr-route-add ROUTER PREFIX NEXTHOP [PORT]\n\
                            add a route to ROUTER\n\
  lr-route-del ROUTER [PREFIX]\n\
                            remove routes from ROUTER\n\
  lr-route-list ROUTER      print routes for ROUTER\n\
\n\
NAT commands:\n\
  lr-nat-add ROUTER TYPE EXTERNAL_IP LOGICAL_IP [LOGICAL_PORT EXTERNAL_MAC]\n\
                            add a NAT to ROUTER\n\
  lr-nat-del ROUTER [TYPE [IP]]\n\
                            remove NATs from ROUTER\n\
  lr-nat-list ROUTER        print NATs for ROUTER\n\
\n\
LB commands:\n\
  lb-add LB VIP[:PORT] IP[:PORT]... [PROTOCOL]\n\
                            create a load-balancer or add a VIP to an\n\
                            existing load balancer\n\
  lb-del LB [VIP]           remove a load-balancer or just the VIP from\n\
                            the load balancer\n\
  lb-list [LB]              print load-balancers\n\
  lr-lb-add ROUTER LB       add a load-balancer to ROUTER\n\
  lr-lb-del ROUTER [LB]     remove load-balancers from ROUTER\n\
  lr-lb-list ROUTER         print load-balancers\n\
  ls-lb-add SWITCH LB       add a load-balancer to SWITCH\n\
  ls-lb-del SWITCH [LB]     remove load-balancers from SWITCH\n\
  ls-lb-list SWITCH         print load-balancers\n\
\n\
DHCP Options commands:\n\
  dhcp-options-create CIDR [EXTERNAL_IDS]\n\
                           create a DHCP options row with CIDR\n\
  dhcp-options-del DHCP_OPTIONS_UUID\n\
                           delete DHCP_OPTIONS_UUID\n\
  dhcp-options-list        \n\
                           lists the DHCP_Options rows\n\
  dhcp-options-set-options DHCP_OPTIONS_UUID  KEY=VALUE [KEY=VALUE]...\n\
                           set DHCP options for DHCP_OPTIONS_UUID\n\
  dhcp-options-get-options DHCO_OPTIONS_UUID \n\
                           displays the DHCP options for DHCP_OPTIONS_UUID\n\
\n\
Connection commands:\n\
  get-connection             print the connections\n\
  del-connection             delete the connections\n\
  [--inactivity-probe=MSECS]\n\
  set-connection TARGET...   set the list of connections to TARGET...\n\
\n\
SSL commands:\n\
  get-ssl                     print the SSL configuration\n\
  del-ssl                     delete the SSL configuration\n\
  set-ssl PRIV-KEY CERT CA-CERT [SSL-PROTOS [SSL-CIPHERS]] \
set the SSL configuration\n\
Port group commands:\n\
  pg-add PG [PORTS]           Create port group PG with optional PORTS\n\
  pg-set-ports PG PORTS       Set PORTS on port group PG\n\
  pg-del PG                   Delete port group PG\n\
\n\
%s\
%s\
\n\
Synchronization command (use with --wait=sb|hv):\n\
  sync                     wait even for earlier changes to take effect\n\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  --no-wait, --wait=none      do not wait for OVN reconfiguration (default)\n\
  --no-leader-only            accept any cluster member, not just the leader\n\
  --wait=sb                   wait for southbound database update\n\
  --wait=hv                   wait for all chassis to catch up\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), default_nb_db());
    table_usage();
    daemon_usage();
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=nbctl:syslog:warn\n");
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    stream_usage("database", true, true, true);
    exit(EXIT_SUCCESS);
}

/* One should not use ctl_fatal() within commands because it will kill the
 * daemon if we're in daemon mode.  Use ctl_error() instead and return
 * gracefully.  */
#define ctl_fatal dont_use_ctl_fatal_use_ctl_error_and_return

/* Find a logical router given its id. */
static char * OVS_WARN_UNUSED_RESULT
lr_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                   bool must_exist, const struct nbrec_logical_router **lr_p)
{
    const struct nbrec_logical_router *lr = NULL;
    bool is_uuid = false;
    struct uuid lr_uuid;

    *lr_p = NULL;
    if (uuid_from_string(&lr_uuid, id)) {
        is_uuid = true;
        lr = nbrec_logical_router_get_for_uuid(ctx->idl, &lr_uuid);
    }

    if (!lr) {
        const struct nbrec_logical_router *iter;

        NBREC_LOGICAL_ROUTER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lr) {
                return xasprintf("Multiple logical routers named '%s'.  "
                                 "Use a UUID.", id);
            }
            lr = iter;
        }
    }

    if (!lr && must_exist) {
        return xasprintf("%s: router %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lr_p = lr;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
ls_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_logical_switch **ls_p)
{
    const struct nbrec_logical_switch *ls = NULL;
    *ls_p = NULL;

    struct uuid ls_uuid;
    bool is_uuid = uuid_from_string(&ls_uuid, id);
    if (is_uuid) {
        ls = nbrec_logical_switch_get_for_uuid(ctx->idl, &ls_uuid);
    }

    if (!ls) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (ls) {
                return xasprintf("Multiple logical switches named '%s'.  "
                                 "Use a UUID.", id);
            }
            ls = iter;
        }
    }

    if (!ls && must_exist) {
        return xasprintf("%s: switch %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *ls_p = ls;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
lb_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_load_balancer **lb_p)
{
    const struct nbrec_load_balancer *lb = NULL;

    struct uuid lb_uuid;
    bool is_uuid = uuid_from_string(&lb_uuid, id);
    if (is_uuid) {
        lb = nbrec_load_balancer_get_for_uuid(ctx->idl, &lb_uuid);
    }

    if (!lb) {
        const struct nbrec_load_balancer *iter;

        NBREC_LOAD_BALANCER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lb) {
                return xasprintf("Multiple load balancers named '%s'.  "
                                 "Use a UUID.", id);
            }
            lb = iter;
        }
    }

    if (!lb && must_exist) {
        return xasprintf("%s: load balancer %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    if (lb_p) {
        *lb_p = lb;
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
pg_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_port_group **pg_p)
{
    const struct nbrec_port_group *pg = NULL;
    *pg_p = NULL;

    struct uuid pg_uuid;
    bool is_uuid = uuid_from_string(&pg_uuid, id);
    if (is_uuid) {
        pg = nbrec_port_group_get_for_uuid(ctx->idl, &pg_uuid);
    }

    if (!pg) {
        const struct nbrec_port_group *iter;

        NBREC_PORT_GROUP_FOR_EACH (iter, ctx->idl) {
            if (!strcmp(iter->name, id)) {
                pg = iter;
                break;
            }
        }
    }

    if (!pg && must_exist) {
        return xasprintf("%s: port group %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    *pg_p = pg;
    return NULL;
}

static void
print_alias(const struct smap *external_ids, const char *key, struct ds *s)
{
    const char *alias = smap_get(external_ids, key);
    if (alias && alias[0]) {
        ds_put_format(s, " (aka %s)", alias);
    }
}

/* gateway_chassis ordering
 *  */
static int
compare_chassis_prio_(const void *gc1_, const void *gc2_)
{
    const struct nbrec_gateway_chassis *const *gc1p = gc1_;
    const struct nbrec_gateway_chassis *const *gc2p = gc2_;
    const struct nbrec_gateway_chassis *gc1 = *gc1p;
    const struct nbrec_gateway_chassis *gc2 = *gc2p;

    int prio_diff = gc2->priority - gc1->priority;
    if (!prio_diff) {
        return strcmp(gc2->name, gc1->name);
    }
    return prio_diff;
}

static const struct nbrec_gateway_chassis **
get_ordered_gw_chassis_prio_list(const struct nbrec_logical_router_port *lrp)
{
    const struct nbrec_gateway_chassis **gcs;
    int i;

    gcs = xmalloc(sizeof *gcs * lrp->n_gateway_chassis);
    for (i = 0; i < lrp->n_gateway_chassis; i++) {
        gcs[i] = lrp->gateway_chassis[i];
    }

    qsort(gcs, lrp->n_gateway_chassis, sizeof *gcs, compare_chassis_prio_);
    return gcs;
}

/* Given pointer to logical router, this routine prints the router
 * information.  */
static void
print_lr(const struct nbrec_logical_router *lr, struct ds *s)
{
    ds_put_format(s, "router "UUID_FMT" (%s)",
                  UUID_ARGS(&lr->header_.uuid), lr->name);
    print_alias(&lr->external_ids, "neutron:router_name", s);
    ds_put_char(s, '\n');

    for (size_t i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        ds_put_format(s, "    port %s\n", lrp->name);
        if (lrp->mac) {
            ds_put_cstr(s, "        mac: ");
            ds_put_format(s, "\"%s\"\n", lrp->mac);
        }
        if (lrp->n_networks) {
            ds_put_cstr(s, "        networks: [");
            for (size_t j = 0; j < lrp->n_networks; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lrp->networks[j]);
            }
            ds_put_cstr(s, "]\n");
        }

        if (lrp->n_gateway_chassis) {
            const struct nbrec_gateway_chassis **gcs;

            gcs = get_ordered_gw_chassis_prio_list(lrp);
            ds_put_cstr(s, "        gateway chassis: [");
            for (size_t j = 0; j < lrp->n_gateway_chassis; j++) {
                const struct nbrec_gateway_chassis *gc = gcs[j];
                ds_put_format(s, "%s ", gc->chassis_name);
            }
            ds_chomp(s, ' ');
            ds_put_cstr(s, "]\n");
            free(gcs);
        }
    }

    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];
        ds_put_format(s, "    nat "UUID_FMT"\n",
                  UUID_ARGS(&nat->header_.uuid));
        ds_put_cstr(s, "        external ip: ");
        ds_put_format(s, "\"%s\"\n", nat->external_ip);
        ds_put_cstr(s, "        logical ip: ");
        ds_put_format(s, "\"%s\"\n", nat->logical_ip);
        ds_put_cstr(s, "        type: ");
        ds_put_format(s, "\"%s\"\n", nat->type);
    }
}

static void
print_ls(const struct nbrec_logical_switch *ls, struct ds *s)
{
    ds_put_format(s, "switch "UUID_FMT" (%s)",
                  UUID_ARGS(&ls->header_.uuid), ls->name);
    print_alias(&ls->external_ids, "neutron:network_name", s);
    ds_put_char(s, '\n');

    for (size_t i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];

        ds_put_format(s, "    port %s", lsp->name);
        print_alias(&lsp->external_ids, "neutron:port_name", s);
        ds_put_char(s, '\n');

        if (lsp->type[0]) {
            ds_put_format(s, "        type: %s\n", lsp->type);
        }
        if (lsp->parent_name) {
            ds_put_format(s, "        parent: %s\n", lsp->parent_name);
        }
        if (lsp->n_tag) {
            ds_put_format(s, "        tag: %"PRIu64"\n", lsp->tag[0]);
        }

        /* Print the addresses, but not if there's just a single "router"
         * address because that's just clutter. */
        if (lsp->n_addresses
            && !(lsp->n_addresses == 1
                 && !strcmp(lsp->addresses[0], "router"))) {
            ds_put_cstr(s, "        addresses: [");
            for (size_t j = 0; j < lsp->n_addresses; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lsp->addresses[j]);
            }
            ds_put_cstr(s, "]\n");
        }

        const char *router_port = smap_get(&lsp->options, "router-port");
        if (router_port) {
            ds_put_format(s, "        router-port: %s\n", router_port);
        }
    }
}

static void
nbctl_init(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
nbctl_pre_sync(struct ctl_context *ctx OVS_UNUSED)
{
    if (wait_type != NBCTL_WAIT_NONE) {
        force_wait = true;
    } else {
        VLOG_INFO("\"sync\" command has no effect without --wait");
    }
}

static void
nbctl_sync(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
nbctl_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;

    if (ctx->argc == 2) {
        char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], false, &ls);
        if (error) {
            ctx->error = error;
            return;
        }
        if (ls) {
            print_ls(ls, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
            print_ls(ls, &ctx->output);
        }
    }
    const struct nbrec_logical_router *lr;

    if (ctx->argc == 2) {
        char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], false, &lr);
        if (error) {
            ctx->error = error;
            return;
        }
        if (lr) {
            print_lr(lr, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
            print_lr(lr, &ctx->output);
        }
    }
}

static void
nbctl_ls_add(struct ctl_context *ctx)
{
    const char *ls_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_error(ctx, "--may-exist and --add-duplicate may not be used "
                  "together");
        return;
    }

    if (ls_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_switch *ls;
            NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->idl) {
                if (!strcmp(ls->name, ls_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_error(ctx, "%s: a switch with this name already "
                              "exists", ls_name);
                    return;
                }
            }
        }
    } else if (may_exist) {
        ctl_error(ctx, "--may-exist requires specifying a name");
        return;
    } else if (add_duplicate) {
        ctl_error(ctx, "--add-duplicate requires specifying a name");
        return;
    }

    struct nbrec_logical_switch *ls;
    ls = nbrec_logical_switch_insert(ctx->txn);
    if (ls_name) {
        nbrec_logical_switch_set_name(ls, ls_name);
    }
}

static void
nbctl_ls_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls = NULL;

    char *error = ls_by_name_or_uuid(ctx, id, must_exist, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!ls) {
        return;
    }

    nbrec_logical_switch_delete(ls);
}

static void
nbctl_ls_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    struct smap switches;

    smap_init(&switches);
    NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
        smap_add_format(&switches, ls->name, UUID_FMT " (%s)",
                        UUID_ARGS(&ls->header_.uuid), ls->name);
    }
    const struct smap_node **nodes = smap_sort(&switches);
    for (size_t i = 0; i < smap_count(&switches); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&switches);
    free(nodes);
}

static char * OVS_WARN_UNUSED_RESULT
lsp_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                    bool must_exist,
                    const struct nbrec_logical_switch_port **lsp_p)
{
    const struct nbrec_logical_switch_port *lsp = NULL;
    *lsp_p = NULL;

    struct uuid lsp_uuid;
    bool is_uuid = uuid_from_string(&lsp_uuid, id);
    if (is_uuid) {
        lsp = nbrec_logical_switch_port_get_for_uuid(ctx->idl, &lsp_uuid);
    }

    if (!lsp) {
        NBREC_LOGICAL_SWITCH_PORT_FOR_EACH(lsp, ctx->idl) {
            if (!strcmp(lsp->name, id)) {
                break;
            }
        }
    }

    if (!lsp && must_exist) {
        return xasprintf("%s: port %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lsp_p = lsp;
    return NULL;
}

/* Returns the logical switch that contains 'lsp'. */
static char * OVS_WARN_UNUSED_RESULT
lsp_to_ls(const struct ovsdb_idl *idl,
          const struct nbrec_logical_switch_port *lsp,
          const struct nbrec_logical_switch **ls_p)
{
    const struct nbrec_logical_switch *ls;
    *ls_p = NULL;

    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            if (ls->ports[i] == lsp) {
                *ls_p = ls;
                return NULL;
            }
        }
    }

    /* Can't happen because of the database schema */
    return xasprintf("logical port %s is not part of any logical switch",
                     lsp->name);
}

static const char *
ls_get_name(const struct nbrec_logical_switch *ls,
                 char uuid_s[UUID_LEN + 1], size_t uuid_s_size)
{
    if (ls->name[0]) {
        return ls->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&ls->header_.uuid));
    return uuid_s;
}

static void
nbctl_lsp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_switch *ls = NULL;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *parent_name;
    int64_t tag;
    if (ctx->argc == 3) {
        parent_name = NULL;
        tag = -1;
    } else if (ctx->argc == 5) {
        /* Validate tag. */
        parent_name = ctx->argv[3];
        if (!ovs_scan(ctx->argv[4], "%"SCNd64, &tag)
            || tag < 0 || tag > 4095) {
            ctl_error(ctx, "%s: invalid tag (must be in range 0 to 4095)",
                      ctx->argv[4]);
            return;
        }
    } else {
        ctl_error(ctx, "lsp-add with parent must also specify a tag");
        return;
    }

    const char *lsp_name = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp;
    error = lsp_by_name_or_uuid(ctx, lsp_name, false, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp) {
        if (!may_exist) {
            ctl_error(ctx, "%s: a port with this name already exists",
                      lsp_name);
            return;
        }

        const struct nbrec_logical_switch *lsw;
        error = lsp_to_ls(ctx->idl, lsp, &lsw);
        if (error) {
            ctx->error = error;
            return;
        }
        if (lsw != ls) {
            char uuid_s[UUID_LEN + 1];
            ctl_error(ctx, "%s: port already exists but in switch %s",
                      lsp_name, ls_get_name(lsw, uuid_s, sizeof uuid_s));
            return;
        }

        if (parent_name) {
            if (!lsp->parent_name) {
                ctl_error(ctx, "%s: port already exists but has no parent",
                          lsp_name);
                return;
            } else if (strcmp(parent_name, lsp->parent_name)) {
                ctl_error(ctx, "%s: port already exists with different parent "
                          "%s", lsp_name, lsp->parent_name);
                return;
            }

            if (!lsp->n_tag_request) {
                ctl_error(ctx, "%s: port already exists but has no "
                          "tag_request", lsp_name);
                return;
            } else if (lsp->tag_request[0] != tag) {
                ctl_error(ctx, "%s: port already exists with different "
                          "tag_request %"PRId64, lsp_name,
                          lsp->tag_request[0]);
                return;
            }
        } else {
            if (lsp->parent_name) {
                ctl_error(ctx, "%s: port already exists but has parent %s",
                          lsp_name, lsp->parent_name);
                return;
            }
        }

        return;
    }

    /* Create the logical port. */
    lsp = nbrec_logical_switch_port_insert(ctx->txn);
    nbrec_logical_switch_port_set_name(lsp, lsp_name);
    if (tag >= 0) {
        nbrec_logical_switch_port_set_parent_name(lsp, parent_name);
        nbrec_logical_switch_port_set_tag_request(lsp, &tag, 1);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_switch_verify_ports(ls);
    struct nbrec_logical_switch_port **new_ports = xmalloc(sizeof *new_ports *
                                                    (ls->n_ports + 1));
    nullable_memcpy(new_ports, ls->ports, sizeof *new_ports * ls->n_ports);
    new_ports[ls->n_ports] = CONST_CAST(struct nbrec_logical_switch_port *,
                                             lsp);
    nbrec_logical_switch_set_ports(ls, new_ports, ls->n_ports + 1);
    free(new_ports);
}

/* Removes logical switch port 'ls->ports[idx]'. */
static void
remove_lsp(const struct nbrec_logical_switch *ls, size_t idx)
{
    const struct nbrec_logical_switch_port *lsp = ls->ports[idx];

    /* First remove 'lsp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_switch_port **new_ports
        = xmemdup(ls->ports, sizeof *new_ports * ls->n_ports);
    new_ports[idx] = new_ports[ls->n_ports - 1];
    nbrec_logical_switch_verify_ports(ls);
    nbrec_logical_switch_set_ports(ls, new_ports, ls->n_ports - 1);
    free(new_ports);

    /* Delete 'lsp' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_SWITCH_PORT_FOR_EACH
     * later. */
    nbrec_logical_switch_port_delete(lsp);
}

static void
nbctl_lsp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], must_exist, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lsp) {
        return;
    }

    /* Find the switch that contains 'lsp', then delete it. */
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            if (ls->ports[i] == lsp) {
                remove_lsp(ls, i);
                return;
            }
        }
    }

    /* Can't happen because of the database schema. */
    ctl_error(ctx, "logical port %s is not part of any logical switch",
              ctx->argv[1]);
}

static void
nbctl_lsp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls;
    struct smap lsps;
    size_t i;

    char *error = ls_by_name_or_uuid(ctx, id, true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    smap_init(&lsps);
    for (i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];
        smap_add_format(&lsps, lsp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lsp->header_.uuid), lsp->name);
    }
    const struct smap_node **nodes = smap_sort(&lsps);
    for (i = 0; i < smap_count(&lsps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lsps);
    free(nodes);
}

static void
nbctl_lsp_get_parent(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->parent_name) {
        ds_put_format(&ctx->output, "%s\n", lsp->parent_name);
    }
}

static void
nbctl_lsp_get_tag(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->n_tag > 0) {
        ds_put_format(&ctx->output, "%"PRId64"\n", lsp->tag[0]);
    }
}

static char *
lsp_contains_duplicate_ip(struct lport_addresses *laddrs1,
                          struct lport_addresses *laddrs2)
{
    for (size_t i = 0; i < laddrs1->n_ipv4_addrs; i++) {
        for (size_t j = 0; j < laddrs2->n_ipv4_addrs; j++) {
            if (laddrs1->ipv4_addrs[i].addr == laddrs2->ipv4_addrs[j].addr) {
                return xasprintf("duplicate IPv4 address %s",
                                 laddrs1->ipv4_addrs[i].addr_s);
            }
        }
    }

    for (size_t i = 0; i < laddrs1->n_ipv6_addrs; i++) {
        for (size_t j = 0; j < laddrs2->n_ipv6_addrs; j++) {
            if (IN6_ARE_ADDR_EQUAL(&laddrs1->ipv6_addrs[i].addr,
                                   &laddrs2->ipv6_addrs[j].addr)) {
                return xasprintf("duplicate IPv6 address %s",
                                 laddrs1->ipv6_addrs[i].addr_s);
            }
        }
    }

    return NULL;
}

static char *
lsp_contains_duplicates(const struct nbrec_logical_switch *ls,
                        const struct nbrec_logical_switch_port *lsp,
                        const char *address)
{
    struct lport_addresses laddrs;
    if (!extract_lsp_addresses(address, &laddrs)) {
        return NULL;
    }

    char *sub_error = NULL;
    for (size_t i = 0; i < ls->n_ports; i++) {
        struct nbrec_logical_switch_port *lsp_test = ls->ports[i];
        if (lsp_test == lsp) {
            continue;
        }
        for (size_t j = 0; j < lsp_test->n_addresses; j++) {
            struct lport_addresses laddrs_test;
            char *addr = lsp_test->addresses[j];
            if (is_dynamic_lsp_address(addr)) {
                addr = lsp_test->dynamic_addresses;
            }
            if (extract_lsp_addresses(addr, &laddrs_test)) {
                sub_error = lsp_contains_duplicate_ip(&laddrs, &laddrs_test);
                destroy_lport_addresses(&laddrs_test);
                if (sub_error) {
                    goto err_out;
                }
            }
        }
    }

err_out: ;
    char *error = NULL;
    if (sub_error) {
        error = xasprintf("Error on switch %s: %s", ls->name, sub_error);
        free(sub_error);
    }
    destroy_lport_addresses(&laddrs);
    return error;
}

static void
nbctl_lsp_set_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }

    const struct nbrec_logical_switch *ls;
    error = lsp_to_ls(ctx->idl, lsp, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    int i;
    for (i = 2; i < ctx->argc; i++) {
        struct eth_addr ea;
        ovs_be32 ip;

        if (strcmp(ctx->argv[i], "unknown") && strcmp(ctx->argv[i], "dynamic")
            && strcmp(ctx->argv[i], "router")
            && !ovs_scan(ctx->argv[i], ETH_ADDR_SCAN_FMT,
                         ETH_ADDR_SCAN_ARGS(ea))
            && !ovs_scan(ctx->argv[i], "dynamic "IP_SCAN_FMT,
                         IP_SCAN_ARGS(&ip))) {
            ctl_error(ctx, "%s: Invalid address format. See ovn-nb(5). "
                      "Hint: An Ethernet address must be "
                      "listed before an IP address, together as a single "
                      "argument.", ctx->argv[i]);
            return;
        }

        error = lsp_contains_duplicates(ls, lsp, ctx->argv[i]);
        if (error) {
            ctl_error(ctx, "%s", error);
            return;
        }
    }

    nbrec_logical_switch_port_set_addresses(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lsp_get_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct svec addresses;
    const char *mac;
    size_t i;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }

    svec_init(&addresses);
    for (i = 0; i < lsp->n_addresses; i++) {
        svec_add(&addresses, lsp->addresses[i]);
    }
    svec_sort(&addresses);
    SVEC_FOR_EACH(i, mac, &addresses) {
        ds_put_format(&ctx->output, "%s\n", mac);
    }
    svec_destroy(&addresses);
}

static void
nbctl_lsp_set_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_switch_port_set_port_security(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lsp_get_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct svec addrs;
    const char *addr;
    size_t i;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    svec_init(&addrs);
    for (i = 0; i < lsp->n_port_security; i++) {
        svec_add(&addrs, lsp->port_security[i]);
    }
    svec_sort(&addrs);
    SVEC_FOR_EACH(i, addr, &addrs) {
        ds_put_format(&ctx->output, "%s\n", addr);
    }
    svec_destroy(&addrs);
}

static void
nbctl_lsp_get_up(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output,
                  "%s\n", (lsp->up && *lsp->up) ? "up" : "down");
}

static char * OVS_WARN_UNUSED_RESULT
parse_enabled(const char *state, bool *enabled_p)
{
    ovs_assert(enabled_p);

    if (!strcasecmp(state, "enabled")) {
        *enabled_p = true;
    } else if (!strcasecmp(state, "disabled")) {
        *enabled_p = false;
    } else {
        return xasprintf("%s: state must be \"enabled\" or \"disabled\"",
                         state);
    }
    return NULL;
}

static void
nbctl_lsp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    bool enabled;
    error = parse_enabled(state, &enabled);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_switch_port_set_enabled(lsp, &enabled, 1);
}

static void
nbctl_lsp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output, "%s\n",
                  !lsp->enabled || *lsp->enabled ? "enabled" : "disabled");
}

static void
nbctl_lsp_set_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (ovn_is_known_nb_lsp_type(type)) {
        nbrec_logical_switch_port_set_type(lsp, type);
    } else {
        ctl_error(ctx, "Logical switch port type '%s' is unrecognized. "
                  "Not setting type.", type);
        return;
    }
}

static void
nbctl_lsp_get_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output, "%s\n", lsp->type);
}

static void
nbctl_lsp_set_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    size_t i;
    struct smap options = SMAP_INITIALIZER(&options);

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    for (i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&options, key, value);
        }
        free(key);
    }

    nbrec_logical_switch_port_set_options(lsp, &options);

    smap_destroy(&options);
}

static void
nbctl_lsp_get_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct smap_node *node;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    SMAP_FOR_EACH(node, &lsp->options) {
        ds_put_format(&ctx->output, "%s=%s\n", node->key, node->value);
    }
}

static void
nbctl_lsp_set_dhcpv4_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    const struct nbrec_dhcp_options *dhcp_opt = NULL;
    if (ctx->argc == 3 ) {
        error = dhcp_options_get(ctx, ctx->argv[2], true, &dhcp_opt);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    if (dhcp_opt) {
        ovs_be32 ip;
        unsigned int plen;
        error = ip_parse_cidr(dhcp_opt->cidr, &ip, &plen);
        if (error){
            free(error);
            ctl_error(ctx, "DHCP options cidr '%s' is not IPv4",
                      dhcp_opt->cidr);
            return;
        }
    }
    nbrec_logical_switch_port_set_dhcpv4_options(lsp, dhcp_opt);
}

static void
nbctl_lsp_set_dhcpv6_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    const struct nbrec_dhcp_options *dhcp_opt = NULL;
    if (ctx->argc == 3) {
        error = dhcp_options_get(ctx, ctx->argv[2], true, &dhcp_opt);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    if (dhcp_opt) {
        struct in6_addr ip;
        unsigned int plen;
        error = ipv6_parse_cidr(dhcp_opt->cidr, &ip, &plen);
        if (error) {
            free(error);
            ctl_error(ctx, "DHCP options cidr '%s' is not IPv6",
                      dhcp_opt->cidr);
            return;
        }
    }
    nbrec_logical_switch_port_set_dhcpv6_options(lsp, dhcp_opt);
}

static void
nbctl_lsp_get_dhcpv4_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->dhcpv4_options) {
        ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&lsp->dhcpv4_options->header_.uuid),
                      lsp->dhcpv4_options->cidr);
    }
}

static void
nbctl_lsp_get_dhcpv6_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->dhcpv6_options) {
        ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&lsp->dhcpv6_options->header_.uuid),
                      lsp->dhcpv6_options->cidr);
    }
}

enum {
    DIR_FROM_LPORT,
    DIR_TO_LPORT
};

static int
dir_encode(const char *dir)
{
    if (!strcmp(dir, "from-lport")) {
        return DIR_FROM_LPORT;
    } else if (!strcmp(dir, "to-lport")) {
        return DIR_TO_LPORT;
    }

    OVS_NOT_REACHED();
}

static int
acl_cmp(const void *acl1_, const void *acl2_)
{
    const struct nbrec_acl *const *acl1p = acl1_;
    const struct nbrec_acl *const *acl2p = acl2_;
    const struct nbrec_acl *acl1 = *acl1p;
    const struct nbrec_acl *acl2 = *acl2p;

    int dir1 = dir_encode(acl1->direction);
    int dir2 = dir_encode(acl2->direction);

    if (dir1 != dir2) {
        return dir1 < dir2 ? -1 : 1;
    } else if (acl1->priority != acl2->priority) {
        return acl1->priority > acl2->priority ? -1 : 1;
    } else {
        return strcmp(acl1->match, acl2->match);
    }
}

static char * OVS_WARN_UNUSED_RESULT
acl_cmd_get_pg_or_ls(struct ctl_context *ctx,
                     const struct nbrec_logical_switch **ls,
                     const struct nbrec_port_group **pg)
{
    const char *opt_type = shash_find_data(&ctx->options, "--type");
    char *error;

    if (!opt_type) {
        error = pg_by_name_or_uuid(ctx, ctx->argv[1], false, pg);
        if (error) {
            return error;
        }
        error = ls_by_name_or_uuid(ctx, ctx->argv[1], false, ls);
        if (error) {
            return error;
        }
        if (*pg && *ls) {
            return xasprintf("Same name '%s' exists in both port-groups and "
                             "logical switches. Specify --type=port-group or "
                             "switch, or use a UUID.", ctx->argv[1]);
        }
        if (!*pg && !*ls) {
            return xasprintf("'%s' is not found for port-group or switch.",
                             ctx->argv[1]);
        }
    } else if (!strcmp(opt_type, "port-group")) {
        error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, pg);
        if (error) {
            return error;
        }
        *ls = NULL;
    } else if (!strcmp(opt_type, "switch")) {
        error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, ls);
        if (error) {
            return error;
        }
        *pg = NULL;
    } else {
        return xasprintf("Invalid value '%s' for option --type", opt_type);
    }

    return NULL;
}

static void
nbctl_acl_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;
    const struct nbrec_acl **acls;
    size_t i;

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **nb_acls = pg ? pg->acls : ls->acls;

    acls = xmalloc(sizeof *acls * n_acls);
    for (i = 0; i < n_acls; i++) {
        acls[i] = nb_acls[i];
    }

    qsort(acls, n_acls, sizeof *acls, acl_cmp);

    for (i = 0; i < n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        ds_put_format(&ctx->output, "%10s %5"PRId64" (%s) %s",
                      acl->direction, acl->priority, acl->match,
                      acl->action);
        if (acl->log) {
            ds_put_cstr(&ctx->output, " log(");
            if (acl->name) {
                ds_put_format(&ctx->output, "name=%s,", acl->name);
            }
            if (acl->severity) {
                ds_put_format(&ctx->output, "severity=%s,", acl->severity);
            }
            if (acl->meter) {
                ds_put_format(&ctx->output, "meter=\"%s\",", acl->meter);
            }
            ds_chomp(&ctx->output, ',');
            ds_put_cstr(&ctx->output, ")");
        }
        ds_put_cstr(&ctx->output, "\n");
    }

    free(acls);
}

static int
qos_cmp(const void *qos1_, const void *qos2_)
{
    const struct nbrec_qos *const *qos1p = qos1_;
    const struct nbrec_qos *const *qos2p = qos2_;
    const struct nbrec_qos *qos1 = *qos1p;
    const struct nbrec_qos *qos2 = *qos2p;

    int dir1 = dir_encode(qos1->direction);
    int dir2 = dir_encode(qos2->direction);

    if (dir1 != dir2) {
        return dir1 < dir2 ? -1 : 1;
    } else if (qos1->priority != qos2->priority) {
        return qos1->priority > qos2->priority ? -1 : 1;
    } else {
        return strcmp(qos1->match, qos2->match);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_direction(const char *arg, const char **direction_p)
{
    /* Validate direction.  Only require the first letter. */
    if (arg[0] == 't') {
        *direction_p = "to-lport";
    } else if (arg[0] == 'f') {
        *direction_p = "from-lport";
    } else {
        *direction_p = NULL;
        return xasprintf("%s: direction must be \"to-lport\" or "
                         "\"from-lport\"", arg);
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_priority(const char *arg, int64_t *priority_p)
{
    /* Validate priority. */
    int64_t priority;
    if (!ovs_scan(arg, "%"SCNd64, &priority)
        || priority < 0 || priority > 32767) {
        /* Priority_p could be uninitialized as no valid priority was
         * input, initialize it to a valid value of 0 before returning */
        *priority_p = 0;
        return xasprintf("%s: priority must in range 0...32767", arg);
    }
    *priority_p = priority;
    return NULL;
}

static void
nbctl_acl_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;
    const char *action = ctx->argv[5];

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *direction;
    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }
    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    /* Validate action. */
    if (strcmp(action, "allow") && strcmp(action, "allow-related")
        && strcmp(action, "drop") && strcmp(action, "reject")) {
        ctl_error(ctx, "%s: action must be one of \"allow\", "
                  "\"allow-related\", \"drop\", and \"reject\"", action);
        return;
    }

    /* Create the acl. */
    struct nbrec_acl *acl = nbrec_acl_insert(ctx->txn);
    nbrec_acl_set_priority(acl, priority);
    nbrec_acl_set_direction(acl, direction);
    nbrec_acl_set_match(acl, ctx->argv[4]);
    nbrec_acl_set_action(acl, action);

    /* Logging options. */
    bool log = shash_find(&ctx->options, "--log") != NULL;
    const char *severity = shash_find_data(&ctx->options, "--severity");
    const char *name = shash_find_data(&ctx->options, "--name");
    const char *meter = shash_find_data(&ctx->options, "--meter");
    if (log || severity || name || meter) {
        nbrec_acl_set_log(acl, true);
    }
    if (severity) {
        if (log_severity_from_string(severity) == UINT8_MAX) {
            ctl_error(ctx, "bad severity: %s", severity);
            return;
        }
        nbrec_acl_set_severity(acl, severity);
    }
    if (name) {
        nbrec_acl_set_name(acl, name);
    }
    if (meter) {
        nbrec_acl_set_meter(acl, meter);
    }

    /* Check if same acl already exists for the ls/portgroup */
    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **acls = pg ? pg->acls : ls->acls;
    for (size_t i = 0; i < n_acls; i++) {
        if (!acl_cmp(&acls[i], &acl)) {
            bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
            if (!may_exist) {
                ctl_error(ctx, "Same ACL already existed on the ls %s.",
                          ctx->argv[1]);
                return;
            }
            return;
        }
    }

    /* Insert the acl into the logical switch/port group. */
    struct nbrec_acl **new_acls = xmalloc(sizeof *new_acls * (n_acls + 1));
    nullable_memcpy(new_acls, acls, sizeof *new_acls * n_acls);
    new_acls[n_acls] = acl;
    if (pg) {
        nbrec_port_group_verify_acls(pg);
        nbrec_port_group_set_acls(pg, new_acls, n_acls + 1);
    } else {
        nbrec_logical_switch_verify_acls(ls);
        nbrec_logical_switch_set_acls(ls, new_acls, n_acls + 1);
    }
    free(new_acls);
}

static void
nbctl_acl_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all ACLs. */
        if (pg) {
            nbrec_port_group_verify_acls(pg);
            nbrec_port_group_set_acls(pg, NULL, 0);
        } else {
            nbrec_logical_switch_verify_acls(ls);
            nbrec_logical_switch_set_acls(ls, NULL, 0);
        }
        return;
    }

    const char *direction;
    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }

    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **acls = pg ? pg->acls : ls->acls;
    /* If priority and match are not specified, delete all ACLs with the
     * specified direction. */
    if (ctx->argc == 3) {
        struct nbrec_acl **new_acls = xmalloc(sizeof *new_acls * n_acls);

        int n_new_acls = 0;
        for (size_t i = 0; i < n_acls; i++) {
            if (strcmp(direction, acls[i]->direction)) {
                new_acls[n_new_acls++] = acls[i];
            }
        }

        if (pg) {
            nbrec_port_group_verify_acls(pg);
            nbrec_port_group_set_acls(pg, new_acls, n_new_acls);
        } else {
            nbrec_logical_switch_verify_acls(ls);
            nbrec_logical_switch_set_acls(ls, new_acls, n_new_acls);
        }
        free(new_acls);
        return;
    }

    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 4) {
        ctl_error(ctx, "cannot specify priority without match");
        return;
    }

    /* Remove the matching rule. */
    for (size_t i = 0; i < n_acls; i++) {
        struct nbrec_acl *acl = acls[i];

        if (priority == acl->priority && !strcmp(ctx->argv[4], acl->match) &&
             !strcmp(direction, acl->direction)) {
            struct nbrec_acl **new_acls
                = xmemdup(acls, sizeof *new_acls * n_acls);
            new_acls[i] = acls[n_acls - 1];
            if (pg) {
                nbrec_port_group_verify_acls(pg);
                nbrec_port_group_set_acls(pg, new_acls,
                                          n_acls - 1);
            } else {
                nbrec_logical_switch_verify_acls(ls);
                nbrec_logical_switch_set_acls(ls, new_acls,
                                              n_acls - 1);
            }
            free(new_acls);
            return;
        }
    }
}

static void
nbctl_qos_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const struct nbrec_qos **qos_rules;
    size_t i;

    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    qos_rules = xmalloc(sizeof *qos_rules * ls->n_qos_rules);
    for (i = 0; i < ls->n_qos_rules; i++) {
        qos_rules[i] = ls->qos_rules[i];
    }

    qsort(qos_rules, ls->n_qos_rules, sizeof *qos_rules, qos_cmp);

    for (i = 0; i < ls->n_qos_rules; i++) {
        const struct nbrec_qos *qos_rule = qos_rules[i];
        ds_put_format(&ctx->output, "%10s %5"PRId64" (%s)",
                      qos_rule->direction, qos_rule->priority,
                      qos_rule->match);
        for (size_t j = 0; j < qos_rule->n_bandwidth; j++) {
            if (!strcmp(qos_rule->key_bandwidth[j], "rate")) {
                ds_put_format(&ctx->output, " rate=%"PRId64"",
                              qos_rule->value_bandwidth[j]);
            }
        }
        for (size_t j = 0; j < qos_rule->n_bandwidth; j++) {
            if (!strcmp(qos_rule->key_bandwidth[j], "burst")) {
                ds_put_format(&ctx->output, " burst=%"PRId64"",
                              qos_rule->value_bandwidth[j]);
            }
        }
        for (size_t j = 0; j < qos_rule->n_action; j++) {
            if (!strcmp(qos_rule->key_action[j], "dscp")) {
                ds_put_format(&ctx->output, " dscp=%"PRId64"",
                              qos_rule->value_action[j]);
            }
        }
        ds_put_cstr(&ctx->output, "\n");
    }

    free(qos_rules);
}

static void
nbctl_qos_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const char *direction;
    int64_t priority;
    int64_t dscp = -1;
    int64_t rate = 0;
    int64_t burst = 0;
    char *error;

    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }
    error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    for (int i = 5; i < ctx->argc; i++) {
        if (!strncmp(ctx->argv[i], "dscp=", 5)) {
            if (!ovs_scan(ctx->argv[i] + 5, "%"SCNd64, &dscp)
                || dscp < 0 || dscp > 63) {
                ctl_error(ctx, "%s: dscp must be in the range 0...63",
                          ctx->argv[i] + 5);
                return;
            }
        }
        else if (!strncmp(ctx->argv[i], "rate=", 5)) {
            if (!ovs_scan(ctx->argv[i] + 5, "%"SCNd64, &rate)
                || rate < 1 || rate > UINT32_MAX) {
                ctl_error(ctx, "%s: rate must be in the range 1...4294967295",
                          ctx->argv[i] + 5);
                return;
            }
        }
        else if (!strncmp(ctx->argv[i], "burst=", 6)) {
            if (!ovs_scan(ctx->argv[i] + 6, "%"SCNd64, &burst)
                || burst < 1 || burst > UINT32_MAX) {
                ctl_error(ctx, "%s: burst must be in the range 1...4294967295",
                          ctx->argv[i] + 6);
                return;
            }
        } else {
            ctl_error(ctx, "%s: supported arguments are \"dscp=\", \"rate=\", "
                      "and \"burst=\"", ctx->argv[i]);
            return;
        }
    }

    /* Validate rate and dscp. */
    if (-1 == dscp && !rate) {
        ctl_error(ctx, "Either \"rate\" and/or \"dscp\" must be specified");
        return;
    }

    /* Create the qos. */
    struct nbrec_qos *qos = nbrec_qos_insert(ctx->txn);
    nbrec_qos_set_priority(qos, priority);
    nbrec_qos_set_direction(qos, direction);
    nbrec_qos_set_match(qos, ctx->argv[4]);
    if (-1 != dscp) {
        const char *dscp_key = "dscp";
        nbrec_qos_set_action(qos, &dscp_key, &dscp, 1);
    }
    if (rate) {
        const char *bandwidth_key[2] = {"rate", "burst"};
        const int64_t bandwidth_value[2] = {rate, burst};
        size_t n_bandwidth = 1;
        if (burst) {
            n_bandwidth = 2;
        }
        nbrec_qos_set_bandwidth(qos, bandwidth_key, bandwidth_value,
                                n_bandwidth);
    }

    /* Check if same qos rule already exists for the ls */
    for (size_t i = 0; i < ls->n_qos_rules; i++) {
        if (!qos_cmp(&ls->qos_rules[i], &qos)) {
            bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
            if (!may_exist) {
                ctl_error(ctx, "Same qos already existed on the ls %s.",
                          ctx->argv[1]);
                return;
            }
            return;
        }
    }

    /* Insert the qos rule the logical switch. */
    nbrec_logical_switch_verify_qos_rules(ls);
    struct nbrec_qos **new_qos_rules
        = xmalloc(sizeof *new_qos_rules * (ls->n_qos_rules + 1));
    nullable_memcpy(new_qos_rules,
                    ls->qos_rules, sizeof *new_qos_rules * ls->n_qos_rules);
    new_qos_rules[ls->n_qos_rules] = qos;
    nbrec_logical_switch_set_qos_rules(ls, new_qos_rules,
                                       ls->n_qos_rules + 1);
    free(new_qos_rules);
}

static void
nbctl_qos_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all QoS rules. */
        nbrec_logical_switch_verify_qos_rules(ls);
        nbrec_logical_switch_set_qos_rules(ls, NULL, 0);
        return;
    }

    const char *direction;
    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }

    /* If priority and match are not specified, delete all qos_rules with the
     * specified direction. */
    if (ctx->argc == 3) {
        struct nbrec_qos **new_qos_rules
            = xmalloc(sizeof *new_qos_rules * ls->n_qos_rules);

        int n_qos_rules = 0;
        for (size_t i = 0; i < ls->n_qos_rules; i++) {
            if (strcmp(direction, ls->qos_rules[i]->direction)) {
                new_qos_rules[n_qos_rules++] = ls->qos_rules[i];
            }
        }

        nbrec_logical_switch_verify_qos_rules(ls);
        nbrec_logical_switch_set_qos_rules(ls, new_qos_rules, n_qos_rules);
        free(new_qos_rules);
        return;
    }

    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 4) {
        ctl_error(ctx, "cannot specify priority without match");
        return;
    }

    /* Remove the matching rule. */
    for (size_t i = 0; i < ls->n_qos_rules; i++) {
        struct nbrec_qos *qos = ls->qos_rules[i];

        if (priority == qos->priority && !strcmp(ctx->argv[4], qos->match) &&
             !strcmp(direction, qos->direction)) {
            struct nbrec_qos **new_qos_rules
                = xmemdup(ls->qos_rules,
                          sizeof *new_qos_rules * ls->n_qos_rules);
            new_qos_rules[i] = ls->qos_rules[ls->n_qos_rules - 1];
            nbrec_logical_switch_verify_qos_rules(ls);
            nbrec_logical_switch_set_qos_rules(ls, new_qos_rules,
                                          ls->n_qos_rules - 1);
            free(new_qos_rules);
            return;
        }
    }
}

static int
meter_cmp(const void *meter1_, const void *meter2_)
{
    struct nbrec_meter *const *meter1p = meter1_;
    struct nbrec_meter *const *meter2p = meter2_;
    const struct nbrec_meter *meter1 = *meter1p;
    const struct nbrec_meter *meter2 = *meter2p;

    return strcmp(meter1->name, meter2->name);
}

static void
nbctl_meter_list(struct ctl_context *ctx)
{
    const struct nbrec_meter **meters = NULL;
    const struct nbrec_meter *meter;
    size_t n_capacity = 0;
    size_t n_meters = 0;

    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (n_meters == n_capacity) {
            meters = x2nrealloc(meters, &n_capacity, sizeof *meters);
        }

        meters[n_meters] = meter;
        n_meters++;
    }

    if (n_meters) {
        qsort(meters, n_meters, sizeof *meters, meter_cmp);
    }

    for (size_t i = 0; i < n_meters; i++) {
        meter = meters[i];
        ds_put_format(&ctx->output, "%s: bands:\n", meter->name);

        for (size_t j = 0; j < meter->n_bands; j++) {
            const struct nbrec_meter_band *band = meter->bands[j];

            ds_put_format(&ctx->output, "  %s: %"PRId64" %s",
                          band->action, band->rate, meter->unit);
            if (band->burst_size) {
                ds_put_format(&ctx->output, ", %"PRId64" %s burst",
                              band->burst_size,
                              !strcmp(meter->unit, "kbps") ? "kb" : "packet" );
            }
        }

        ds_put_cstr(&ctx->output, "\n");
    }

    free(meters);
}

static void
nbctl_meter_add(struct ctl_context *ctx)
{
    const struct nbrec_meter *meter;

    const char *name = ctx->argv[1];
    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (!strcmp(meter->name, name)) {
            ctl_error(ctx, "meter with name \"%s\" already exists", name);
            return;
        }
    }

    if (!strncmp(name, "__", 2)) {
        ctl_error(ctx, "meter names that begin with \"__\" are reserved");
        return;
    }

    const char *action = ctx->argv[2];
    if (strcmp(action, "drop")) {
        ctl_error(ctx, "action must be \"drop\"");
        return;
    }

    int64_t rate;
    if (!ovs_scan(ctx->argv[3], "%"SCNd64, &rate)
        || rate < 1 || rate > UINT32_MAX) {
        ctl_error(ctx, "rate must be in the range 1...4294967295");
        return;
    }

    const char *unit = ctx->argv[4];
    if (strcmp(unit, "kbps") && strcmp(unit, "pktps")) {
        ctl_error(ctx, "unit must be \"kbps\" or \"pktps\"");
        return;
    }

    int64_t burst = 0;
    if (ctx->argc > 5) {
        if (!ovs_scan(ctx->argv[5], "%"SCNd64, &burst)
            || burst < 0 || burst > UINT32_MAX) {
            ctl_error(ctx, "burst must be in the range 0...4294967295");
            return;
        }
    }

    /* Create the band.  We only support adding a single band. */
    struct nbrec_meter_band *band = nbrec_meter_band_insert(ctx->txn);
    nbrec_meter_band_set_action(band, action);
    nbrec_meter_band_set_rate(band, rate);
    nbrec_meter_band_set_burst_size(band, burst);

    /* Create the meter. */
    meter = nbrec_meter_insert(ctx->txn);
    nbrec_meter_set_name(meter, name);
    nbrec_meter_set_unit(meter, unit);
    nbrec_meter_set_bands(meter, &band, 1);
}

static void
nbctl_meter_del(struct ctl_context *ctx)
{
    const struct nbrec_meter *meter, *next;

    /* If a name is not specified, delete all meters. */
    if (ctx->argc == 1) {
        NBREC_METER_FOR_EACH_SAFE (meter, next, ctx->idl) {
            nbrec_meter_delete(meter);
        }
        return;
    }

    /* Remove the matching meter. */
    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (strcmp(ctx->argv[1], meter->name)) {
            continue;
        }

        nbrec_meter_delete(meter);
        return;
    }
}

static void
nbctl_lb_add(struct ctl_context *ctx)
{
    const char *lb_name = ctx->argv[1];
    const char *lb_vip = ctx->argv[2];
    char *lb_ips = ctx->argv[3];

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;

    const char *lb_proto;
    bool is_update_proto = false;

    if (ctx->argc == 4) {
        /* Default protocol. */
        lb_proto = "tcp";
    } else {
        /* Validate protocol. */
        lb_proto = ctx->argv[4];
        is_update_proto = true;
        if (strcmp(lb_proto, "tcp") && strcmp(lb_proto, "udp")) {
            ctl_error(ctx, "%s: protocol must be one of \"tcp\", \"udp\".",
                      lb_proto);
            return;
        }
    }

    struct sockaddr_storage ss_vip;
    if (!inet_parse_active(lb_vip, 0, &ss_vip, false)) {
        ctl_error(ctx, "%s: should be an IP address (or an IP address "
                  "and a port number with : as a separator).", lb_vip);
        return;
    }

    struct ds lb_vip_normalized_ds = DS_EMPTY_INITIALIZER;
    uint16_t lb_vip_port = ss_get_port(&ss_vip);
    if (lb_vip_port) {
        ss_format_address(&ss_vip, &lb_vip_normalized_ds);
        ds_put_format(&lb_vip_normalized_ds, ":%d", lb_vip_port);
    } else {
        ss_format_address_nobracks(&ss_vip, &lb_vip_normalized_ds);
    }
    const char *lb_vip_normalized = ds_cstr(&lb_vip_normalized_ds);

    if (!lb_vip_port && is_update_proto) {
        ds_destroy(&lb_vip_normalized_ds);
        ctl_error(ctx, "Protocol is unnecessary when no port of vip "
                  "is given.");
        return;
    }

    char *token = NULL, *save_ptr = NULL;
    struct ds lb_ips_new = DS_EMPTY_INITIALIZER;
    for (token = strtok_r(lb_ips, ",", &save_ptr);
            token != NULL; token = strtok_r(NULL, ",", &save_ptr)) {
        struct sockaddr_storage ss_dst;

        if (lb_vip_port) {
            if (!inet_parse_active(token, -1, &ss_dst, false)) {
                ctl_error(ctx, "%s: should be an IP address and a port "
                          "number with : as a separator.", token);
                goto out;
            }
        } else {
            if (!inet_parse_address(token, &ss_dst)) {
                ctl_error(ctx, "%s: should be an IP address.", token);
                goto out;
            }
        }

        if (ss_vip.ss_family != ss_dst.ss_family) {
            ctl_error(ctx, "%s: IP address family is different from VIP %s.",
                      token, lb_vip_normalized);
            goto out;
        }
        ds_put_format(&lb_ips_new, "%s%s",
                lb_ips_new.length ? "," : "", token);
    }

    const struct nbrec_load_balancer *lb = NULL;
    if (!add_duplicate) {
        char *error = lb_by_name_or_uuid(ctx, lb_name, false, &lb);
        if (error) {
            ctx->error = error;
            goto out;
        }
        if (lb) {
            if (smap_get(&lb->vips, lb_vip_normalized)) {
                if (!may_exist) {
                    ctl_error(ctx, "%s: a load balancer with this vip (%s) "
                              "already exists", lb_name, lb_vip_normalized);
                    goto out;
                }
                /* Update the vips. */
                smap_replace(CONST_CAST(struct smap *, &lb->vips),
                        lb_vip_normalized, ds_cstr(&lb_ips_new));
            } else {
                /* Add the new vips. */
                smap_add(CONST_CAST(struct smap *, &lb->vips),
                        lb_vip_normalized, ds_cstr(&lb_ips_new));
            }

            /* Update the load balancer. */
            if (is_update_proto) {
                nbrec_load_balancer_verify_protocol(lb);
                nbrec_load_balancer_set_protocol(lb, lb_proto);
            }
            nbrec_load_balancer_verify_vips(lb);
            nbrec_load_balancer_set_vips(lb, &lb->vips);
            goto out;
        }
    }

    /* Create the load balancer. */
    lb = nbrec_load_balancer_insert(ctx->txn);
    nbrec_load_balancer_set_name(lb, lb_name);
    nbrec_load_balancer_set_protocol(lb, lb_proto);
    smap_add(CONST_CAST(struct smap *, &lb->vips),
            lb_vip_normalized, ds_cstr(&lb_ips_new));
    nbrec_load_balancer_set_vips(lb, &lb->vips);
out:
    ds_destroy(&lb_ips_new);

    ds_destroy(&lb_vip_normalized_ds);
}

static void
nbctl_lb_del(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_load_balancer *lb = NULL;
    bool must_exist = !shash_find(&ctx->options, "--if-exists");

    char *error = lb_by_name_or_uuid(ctx, id, false, &lb);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lb) {
        return;
    }

    if (ctx->argc == 3) {
        const char *lb_vip = ctx->argv[2];
        if (smap_get(&lb->vips, lb_vip)) {
            smap_remove(CONST_CAST(struct smap *, &lb->vips), lb_vip);
            if (smap_is_empty(&lb->vips)) {
                nbrec_load_balancer_delete(lb);
                return;
            }

            /* Delete the vip of the load balancer. */
            nbrec_load_balancer_verify_vips(lb);
            nbrec_load_balancer_set_vips(lb, &lb->vips);
            return;
        }
        if (must_exist) {
            ctl_error(ctx, "vip %s is not part of the load balancer.",
                      lb_vip);
            return;
        }
        return;
    }
    nbrec_load_balancer_delete(lb);
}

static void
lb_info_add_smap(const struct nbrec_load_balancer *lb,
                 struct smap *lbs, int vip_width)
{
    const struct smap_node **nodes = smap_sort(&lb->vips);
    if (nodes) {
        struct ds val = DS_EMPTY_INITIALIZER;
        for (int i = 0; i < smap_count(&lb->vips); i++) {
            const struct smap_node *node = nodes[i];

            struct sockaddr_storage ss;
            if (!inet_parse_active(node->key, 0, &ss, false)) {
                continue;
            }

            char *protocol = ss_get_port(&ss) ? lb->protocol : "tcp/udp";
            i == 0 ? ds_put_format(&val,
                        UUID_FMT "    %-20.16s%-11.7s%-*.*s%s",
                        UUID_ARGS(&lb->header_.uuid),
                        lb->name, protocol,
                        vip_width + 4, vip_width,
                        node->key, node->value)
                   : ds_put_format(&val, "\n%60s%-11.7s%-*.*s%s",
                        "", protocol,
                        vip_width + 4, vip_width,
                        node->key, node->value);
        }

        smap_add_nocopy(lbs, xasprintf("%-20.16s", lb->name),
                        ds_steal_cstr(&val));
        free(nodes);
    }
}

static void
lb_info_print(struct ctl_context *ctx, struct smap *lbs, int vip_width)
{
    const struct smap_node **nodes = smap_sort(lbs);
    if (nodes) {
        ds_put_format(&ctx->output, "%-40.36s%-20.16s%-11.7s%-*.*s%s\n",
                "UUID", "LB", "PROTO", vip_width + 4, vip_width, "VIP", "IPs");
        for (size_t i = 0; i < smap_count(lbs); i++) {
            const struct smap_node *node = nodes[i];
            ds_put_format(&ctx->output, "%s\n", node->value);
        }

        free(nodes);
    }
}

static int
lb_get_max_vip_length(const struct nbrec_load_balancer *lb, int vip_width)
{
    const struct smap_node *node;
    int max_length = vip_width;

    SMAP_FOR_EACH (node, &lb->vips) {
        size_t keylen = strlen(node->key);
        if (max_length < keylen) {
            max_length = keylen;
        }
    }

    return max_length;
}

static void
lb_info_list_all(struct ctl_context *ctx,
                 const char *lb_name, bool lb_check)
{
    const struct nbrec_load_balancer *lb;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    NBREC_LOAD_BALANCER_FOR_EACH (lb, ctx->idl) {
        if (lb_check && strcmp(lb->name, lb_name)) {
            continue;
        }
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }

    NBREC_LOAD_BALANCER_FOR_EACH(lb, ctx->idl) {
        if (lb_check && strcmp(lb->name, lb_name)) {
            continue;
        }
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_lb_list(struct ctl_context *ctx)
{
    if (ctx->argc == 1) {
        lb_info_list_all(ctx, NULL, false);
    } else if (ctx->argc == 2) {
        lb_info_list_all(ctx, ctx->argv[1], true);
    }
}

static void
nbctl_lr_lb_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    const struct nbrec_load_balancer *new_lb;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &new_lb);
    if (error) {
        ctx->error = error;
        return;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];

        if (uuid_equals(&new_lb->header_.uuid, &lb->header_.uuid)) {
            if (may_exist) {
                return;
            }
            ctl_error(ctx, UUID_FMT " : a load balancer with this UUID "
                      "already exists", UUID_ARGS(&lb->header_.uuid));
            return;
        }
    }

    /* Insert the load balancer into the logical router. */
    nbrec_logical_router_verify_load_balancer(lr);
    struct nbrec_load_balancer **new_lbs
        = xmalloc(sizeof *new_lbs * (lr->n_load_balancer + 1));

    nullable_memcpy(new_lbs, lr->load_balancer,
                    sizeof *new_lbs * lr->n_load_balancer);
    new_lbs[lr->n_load_balancer] = CONST_CAST(struct nbrec_load_balancer *,
            new_lb);
    nbrec_logical_router_set_load_balancer(lr, new_lbs,
            lr->n_load_balancer + 1);
    free(new_lbs);
}

static void
nbctl_lr_lb_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    const struct nbrec_load_balancer *del_lb;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If load-balancer is not specified, remove
         * all load-balancers from the logical router. */
        nbrec_logical_router_verify_load_balancer(lr);
        nbrec_logical_router_set_load_balancer(lr, NULL, 0);
        return;
    }

    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &del_lb);
    if (error) {
        ctx->error = error;
        return;
    }
    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];

        if (uuid_equals(&del_lb->header_.uuid, &lb->header_.uuid)) {
            /* Remove the matching rule. */
            nbrec_logical_router_verify_load_balancer(lr);

            struct nbrec_load_balancer **new_lbs
                = xmemdup(lr->load_balancer,
                    sizeof *new_lbs * lr->n_load_balancer);
            new_lbs[i] = lr->load_balancer[lr->n_load_balancer - 1];
            nbrec_logical_router_set_load_balancer(lr, new_lbs,
                                          lr->n_load_balancer - 1);
            free(new_lbs);
            return;
        }
    }

    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    if (must_exist) {
        ctl_error(ctx, "load balancer %s is not part of any logical router.",
                  del_lb->name);
        return;
    }
}

static void
nbctl_lr_lb_list(struct ctl_context *ctx)
{
    const char *lr_name = ctx->argv[1];
    const struct nbrec_logical_router *lr;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    char *error = lr_by_name_or_uuid(ctx, lr_name, true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_ls_lb_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_load_balancer *new_lb;

    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &new_lb);
    if (error) {
        ctx->error = error;
        return;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];

        if (uuid_equals(&new_lb->header_.uuid, &lb->header_.uuid)) {
            if (may_exist) {
                return;
            }
            ctl_error(ctx, UUID_FMT " : a load balancer with this UUID "
                      "already exists", UUID_ARGS(&lb->header_.uuid));
            return;
        }
    }

    /* Insert the load balancer into the logical switch. */
    nbrec_logical_switch_verify_load_balancer(ls);
    struct nbrec_load_balancer **new_lbs
        = xmalloc(sizeof *new_lbs * (ls->n_load_balancer + 1));

    nullable_memcpy(new_lbs, ls->load_balancer,
                    sizeof *new_lbs * ls->n_load_balancer);
    new_lbs[ls->n_load_balancer] = CONST_CAST(struct nbrec_load_balancer *,
            new_lb);
    nbrec_logical_switch_set_load_balancer(ls, new_lbs,
            ls->n_load_balancer + 1);
    free(new_lbs);
}

static void
nbctl_ls_lb_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const struct nbrec_load_balancer *del_lb;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If load-balancer is not specified, remove
         * all load-balancers from the logical switch. */
        nbrec_logical_switch_verify_load_balancer(ls);
        nbrec_logical_switch_set_load_balancer(ls, NULL, 0);
        return;
    }

    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &del_lb);
    if (error) {
        ctx->error = error;
        return;
    }
    for (size_t i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];

        if (uuid_equals(&del_lb->header_.uuid, &lb->header_.uuid)) {
            /* Remove the matching rule. */
            nbrec_logical_switch_verify_load_balancer(ls);

            struct nbrec_load_balancer **new_lbs
                = xmemdup(ls->load_balancer,
                        sizeof *new_lbs * ls->n_load_balancer);
            new_lbs[i] = ls->load_balancer[ls->n_load_balancer - 1];
            nbrec_logical_switch_set_load_balancer(ls, new_lbs,
                                          ls->n_load_balancer - 1);
            free(new_lbs);
            return;
        }
    }

    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    if (must_exist) {
        ctl_error(ctx, "load balancer %s is not part of any logical switch.",
                  del_lb->name);
        return;
    }
}

static void
nbctl_ls_lb_list(struct ctl_context *ctx)
{
    const char *ls_name = ctx->argv[1];
    const struct nbrec_logical_switch *ls;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    char *error = ls_by_name_or_uuid(ctx, ls_name, true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_lr_add(struct ctl_context *ctx)
{
    const char *lr_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_error(ctx, "--may-exist and --add-duplicate may not be used "
                  "together");
        return;
    }

    if (lr_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_router *lr;
            NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->idl) {
                if (!strcmp(lr->name, lr_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_error(ctx, "%s: a router with this name already "
                              "exists", lr_name);
                    return;
                }
            }
        }
    } else if (may_exist) {
        ctl_error(ctx, "--may-exist requires specifying a name");
        return;
    } else if (add_duplicate) {
        ctl_error(ctx, "--add-duplicate requires specifying a name");
        return;
    }

    struct nbrec_logical_router *lr;
    lr = nbrec_logical_router_insert(ctx->txn);
    if (lr_name) {
        nbrec_logical_router_set_name(lr, lr_name);
    }
}

static void
nbctl_lr_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr = NULL;

    char *error = lr_by_name_or_uuid(ctx, id, must_exist, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lr) {
        return;
    }

    nbrec_logical_router_delete(lr);
}

static void
nbctl_lr_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct smap lrs;

    smap_init(&lrs);
    NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
        smap_add_format(&lrs, lr->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lr->header_.uuid), lr->name);
    }
    const struct smap_node **nodes = smap_sort(&lrs);
    for (size_t i = 0; i < smap_count(&lrs); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrs);
    free(nodes);
}

static char *
dhcp_options_get(struct ctl_context *ctx, const char *id, bool must_exist,
                 const struct nbrec_dhcp_options **dhcp_opts_p)
{
    struct uuid dhcp_opts_uuid;
    const struct nbrec_dhcp_options *dhcp_opts = NULL;
    if (uuid_from_string(&dhcp_opts_uuid, id)) {
        dhcp_opts = nbrec_dhcp_options_get_for_uuid(ctx->idl, &dhcp_opts_uuid);
    }

    *dhcp_opts_p = dhcp_opts;
    if (!dhcp_opts && must_exist) {
        return xasprintf("%s: dhcp options UUID not found", id);
    }

    return NULL;
}

static void
nbctl_dhcp_options_create(struct ctl_context *ctx)
{
    /* Validate the cidr */
    ovs_be32 ip;
    unsigned int plen;
    char *error = ip_parse_cidr(ctx->argv[1], &ip, &plen);
    if (error){
        /* check if its IPv6 cidr */
        free(error);
        struct in6_addr ipv6;
        error = ipv6_parse_cidr(ctx->argv[1], &ipv6, &plen);
        if (error) {
            free(error);
            ctl_error(ctx, "Invalid cidr format '%s'", ctx->argv[1]);
            return;
        }
    }

    struct nbrec_dhcp_options *dhcp_opts = nbrec_dhcp_options_insert(ctx->txn);
    nbrec_dhcp_options_set_cidr(dhcp_opts, ctx->argv[1]);

    struct smap ext_ids = SMAP_INITIALIZER(&ext_ids);
    for (size_t i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&ext_ids, key, value);
        }
        free(key);
    }

    nbrec_dhcp_options_set_external_ids(dhcp_opts, &ext_ids);
    smap_destroy(&ext_ids);
}

static void
nbctl_dhcp_options_set_options(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    char *error = dhcp_options_get(ctx, ctx->argv[1], true, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap dhcp_options = SMAP_INITIALIZER(&dhcp_options);
    for (size_t i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&dhcp_options, key, value);
        }
        free(key);
    }

    nbrec_dhcp_options_set_options(dhcp_opts, &dhcp_options);
    smap_destroy(&dhcp_options);
}

static void
nbctl_dhcp_options_get_options(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    char *error = dhcp_options_get(ctx, ctx->argv[1], true, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH(node, &dhcp_opts->options) {
        ds_put_format(&ctx->output, "%s=%s\n", node->key, node->value);
    }
}

static void
nbctl_dhcp_options_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_dhcp_options *dhcp_opts;

    char *error = dhcp_options_get(ctx, id, must_exist, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!dhcp_opts) {
        return;
    }

    nbrec_dhcp_options_delete(dhcp_opts);
}

static void
nbctl_dhcp_options_list(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    struct smap dhcp_options;

    smap_init(&dhcp_options);
    NBREC_DHCP_OPTIONS_FOR_EACH(dhcp_opts, ctx->idl) {
        smap_add_format(&dhcp_options, dhcp_opts->cidr, UUID_FMT,
                        UUID_ARGS(&dhcp_opts->header_.uuid));
    }
    const struct smap_node **nodes = smap_sort(&dhcp_options);
    for (size_t i = 0; i < smap_count(&dhcp_options); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&dhcp_options);
    free(nodes);
}

/* The caller must free the returned string. */
static char *
normalize_ipv4_prefix(ovs_be32 ipv4, unsigned int plen)
{
    ovs_be32 network = ipv4 & be32_prefix_mask(plen);
    if (plen == 32) {
        return xasprintf(IP_FMT, IP_ARGS(network));
    } else {
        return xasprintf(IP_FMT"/%d", IP_ARGS(network), plen);
    }
}

/* The caller must free the returned string. */
static char *
normalize_ipv6_prefix(struct in6_addr ipv6, unsigned int plen)
{
    char network_s[INET6_ADDRSTRLEN];

    struct in6_addr mask = ipv6_create_mask(plen);
    struct in6_addr network = ipv6_addr_bitand(&ipv6, &mask);

    inet_ntop(AF_INET6, &network, network_s, INET6_ADDRSTRLEN);
    if (plen == 128) {
        return xasprintf("%s", network_s);
    } else {
        return xasprintf("%s/%d", network_s, plen);
    }
}

/* The caller must free the returned string. */
static char *
normalize_prefix_str(const char *orig_prefix)
{
    unsigned int plen;
    ovs_be32 ipv4;
    char *error;

    error = ip_parse_cidr(orig_prefix, &ipv4, &plen);
    if (!error) {
        return normalize_ipv4_prefix(ipv4, plen);
    } else {
        struct in6_addr ipv6;
        free(error);

        error = ipv6_parse_cidr(orig_prefix, &ipv6, &plen);
        if (error) {
            free(error);
            return NULL;
        }
        return normalize_ipv6_prefix(ipv6, plen);
    }
}

static void
nbctl_lr_route_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    char *prefix, *next_hop;

    const char *policy = shash_find_data(&ctx->options, "--policy");
    if (policy && strcmp(policy, "src-ip") && strcmp(policy, "dst-ip")) {
        ctl_error(ctx, "bad policy: %s", policy);
        return;
    }

    prefix = normalize_prefix_str(ctx->argv[2]);
    if (!prefix) {
        ctl_error(ctx, "bad prefix argument: %s", ctx->argv[2]);
        return;
    }

    next_hop = normalize_prefix_str(ctx->argv[3]);
    if (!next_hop) {
        free(prefix);
        ctl_error(ctx, "bad next hop argument: %s", ctx->argv[3]);
        return;
    }

    if (strchr(prefix, '.')) {
        ovs_be32 hop_ipv4;
        if (!ip_parse(ctx->argv[3], &hop_ipv4)) {
            free(prefix);
            free(next_hop);
            ctl_error(ctx, "bad IPv4 nexthop argument: %s", ctx->argv[3]);
            return;
        }
    } else {
        struct in6_addr hop_ipv6;
        if (!ipv6_parse(ctx->argv[3], &hop_ipv6)) {
            free(prefix);
            free(next_hop);
            ctl_error(ctx, "bad IPv6 nexthop argument: %s", ctx->argv[3]);
            return;
        }
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *route
            = lr->static_routes[i];
        char *rt_prefix;

        rt_prefix = normalize_prefix_str(lr->static_routes[i]->ip_prefix);
        if (!rt_prefix) {
            /* Ignore existing prefix we couldn't parse. */
            continue;
        }

        if (strcmp(rt_prefix, prefix)) {
            free(rt_prefix);
            continue;
        }

        if (!may_exist) {
            ctl_error(ctx, "duplicate prefix: %s", prefix);
            free(next_hop);
            free(rt_prefix);
            free(prefix);
            return;
        }

        /* Update the next hop for an existing route. */
        nbrec_logical_router_verify_static_routes(lr);
        nbrec_logical_router_static_route_verify_ip_prefix(route);
        nbrec_logical_router_static_route_verify_nexthop(route);
        nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
        nbrec_logical_router_static_route_set_nexthop(route, next_hop);
        if (ctx->argc == 5) {
            nbrec_logical_router_static_route_set_output_port(route,
                                                              ctx->argv[4]);
        }
        if (policy) {
             nbrec_logical_router_static_route_set_policy(route, policy);
        }
        free(rt_prefix);
        free(next_hop);
        free(prefix);
        return;
    }

    struct nbrec_logical_router_static_route *route;
    route = nbrec_logical_router_static_route_insert(ctx->txn);
    nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
    nbrec_logical_router_static_route_set_nexthop(route, next_hop);
    if (ctx->argc == 5) {
        nbrec_logical_router_static_route_set_output_port(route, ctx->argv[4]);
    }
    if (policy) {
        nbrec_logical_router_static_route_set_policy(route, policy);
    }

    nbrec_logical_router_verify_static_routes(lr);
    struct nbrec_logical_router_static_route **new_routes
        = xmalloc(sizeof *new_routes * (lr->n_static_routes + 1));
    nullable_memcpy(new_routes, lr->static_routes,
               sizeof *new_routes * lr->n_static_routes);
    new_routes[lr->n_static_routes] = route;
    nbrec_logical_router_set_static_routes(lr, new_routes,
                                           lr->n_static_routes + 1);
    free(new_routes);
    free(next_hop);
    free(prefix);
}

static void
nbctl_lr_route_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If a prefix is not specified, delete all routes. */
        nbrec_logical_router_set_static_routes(lr, NULL, 0);
        return;
    }

    char *prefix = normalize_prefix_str(ctx->argv[2]);
    if (!prefix) {
        ctl_error(ctx, "bad prefix argument: %s", ctx->argv[2]);
        return;
    }

    for (int i = 0; i < lr->n_static_routes; i++) {
        char *rt_prefix = normalize_prefix_str(lr->static_routes[i]->ip_prefix);
        if (!rt_prefix) {
            /* Ignore existing prefix we couldn't parse. */
            continue;
        }

        if (!strcmp(prefix, rt_prefix)) {
            struct nbrec_logical_router_static_route **new_routes
                = xmemdup(lr->static_routes,
                          sizeof *new_routes * lr->n_static_routes);

            new_routes[i] = lr->static_routes[lr->n_static_routes - 1];
            nbrec_logical_router_verify_static_routes(lr);
            nbrec_logical_router_set_static_routes(lr, new_routes,
                                                 lr->n_static_routes - 1);
            free(new_routes);
            free(rt_prefix);
            free(prefix);
            return;
        }
        free(rt_prefix);
    }

    if (!shash_find(&ctx->options, "--if-exists")) {
        ctl_error(ctx, "no matching prefix: %s", prefix);
    }
    free(prefix);
}

static void
nbctl_lr_nat_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    const char *nat_type = ctx->argv[2];
    const char *external_ip = ctx->argv[3];
    const char *logical_ip = ctx->argv[4];
    char *new_logical_ip = NULL;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (strcmp(nat_type, "dnat") && strcmp(nat_type, "snat")
            && strcmp(nat_type, "dnat_and_snat")) {
        ctl_error(ctx, "%s: type must be one of \"dnat\", \"snat\" and "
                  "\"dnat_and_snat\".", nat_type);
        return;
    }

    ovs_be32 ipv4 = 0;
    unsigned int plen;
    if (!ip_parse(external_ip, &ipv4)) {
        ctl_error(ctx, "%s: should be an IPv4 address.", external_ip);
        return;
    }

    if (strcmp("snat", nat_type)) {
        if (!ip_parse(logical_ip, &ipv4)) {
            ctl_error(ctx, "%s: should be an IPv4 address.", logical_ip);
            return;
        }
        new_logical_ip = xstrdup(logical_ip);
    } else {
        error = ip_parse_cidr(logical_ip, &ipv4, &plen);
        if (error) {
            free(error);
            ctl_error(ctx, "%s: should be an IPv4 address or network.",
                      logical_ip);
            return;
        }
        new_logical_ip = normalize_ipv4_prefix(ipv4, plen);
    }

    const char *logical_port;
    const char *external_mac;
    if (ctx->argc == 6) {
        ctl_error(ctx, "lr-nat-add with logical_port "
                  "must also specify external_mac.");
        free(new_logical_ip);
        return;
    } else if (ctx->argc == 7) {
        if (strcmp(nat_type, "dnat_and_snat")) {
            ctl_error(ctx, "logical_port and external_mac are only valid when "
                      "type is \"dnat_and_snat\".");
            free(new_logical_ip);
            return;
        }

        logical_port = ctx->argv[5];
        const struct nbrec_logical_switch_port *lsp;
        error = lsp_by_name_or_uuid(ctx, logical_port, true, &lsp);
        if (error) {
            ctx->error = error;
            free(new_logical_ip);
            return;
        }

        external_mac = ctx->argv[6];
        struct eth_addr ea;
        if (!eth_addr_from_string(external_mac, &ea)) {
            ctl_error(ctx, "invalid mac address %s.", external_mac);
            free(new_logical_ip);
            return;
        }
    } else {
        logical_port = NULL;
        external_mac = NULL;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    int is_snat = !strcmp("snat", nat_type);
    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];
        if (!strcmp(nat_type, nat->type)) {
            if (!strcmp(is_snat ? new_logical_ip : external_ip,
                        is_snat ? nat->logical_ip : nat->external_ip)) {
                if (!strcmp(is_snat ? external_ip : new_logical_ip,
                            is_snat ? nat->external_ip : nat->logical_ip)) {
                        if (may_exist) {
                            nbrec_nat_verify_logical_port(nat);
                            nbrec_nat_verify_external_mac(nat);
                            nbrec_nat_set_logical_port(nat, logical_port);
                            nbrec_nat_set_external_mac(nat, external_mac);
                            free(new_logical_ip);
                            return;
                        }
                        ctl_error(ctx, "%s, %s: a NAT with this external_ip "
                                  "and logical_ip already exists",
                                  external_ip, new_logical_ip);
                        free(new_logical_ip);
                        return;
                } else {
                    ctl_error(ctx, "a NAT with this type (%s) and %s (%s) "
                              "already exists",
                              nat_type,
                              is_snat ? "logical_ip" : "external_ip",
                              is_snat ? new_logical_ip : external_ip);
                    free(new_logical_ip);
                    return;
                }
            }
        }
    }

    /* Create the NAT. */
    struct nbrec_nat *nat = nbrec_nat_insert(ctx->txn);
    nbrec_nat_set_type(nat, nat_type);
    nbrec_nat_set_external_ip(nat, external_ip);
    nbrec_nat_set_logical_ip(nat, new_logical_ip);
    if (logical_port && external_mac) {
        nbrec_nat_set_logical_port(nat, logical_port);
        nbrec_nat_set_external_mac(nat, external_mac);
    }
    free(new_logical_ip);

    /* Insert the NAT into the logical router. */
    nbrec_logical_router_verify_nat(lr);
    struct nbrec_nat **new_nats = xmalloc(sizeof *new_nats * (lr->n_nat + 1));
    nullable_memcpy(new_nats, lr->nat, sizeof *new_nats * lr->n_nat);
    new_nats[lr->n_nat] = nat;
    nbrec_logical_router_set_nat(lr, new_nats, lr->n_nat + 1);
    free(new_nats);
}

static void
nbctl_lr_nat_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If type, external_ip and logical_ip are not specified, delete
         * all NATs. */
        nbrec_logical_router_verify_nat(lr);
        nbrec_logical_router_set_nat(lr, NULL, 0);
        return;
    }

    const char *nat_type = ctx->argv[2];
    if (strcmp(nat_type, "dnat") && strcmp(nat_type, "snat")
            && strcmp(nat_type, "dnat_and_snat")) {
        ctl_error(ctx, "%s: type must be one of \"dnat\", \"snat\" and "
                  "\"dnat_and_snat\".", nat_type);
        return;
    }

    if (ctx->argc == 3) {
        /*Deletes all NATs with the specified type. */
        struct nbrec_nat **new_nats = xmalloc(sizeof *new_nats * lr->n_nat);
        int n_nat = 0;
        for (size_t i = 0; i < lr->n_nat; i++) {
            if (strcmp(nat_type, lr->nat[i]->type)) {
                new_nats[n_nat++] = lr->nat[i];
            }
        }

        nbrec_logical_router_verify_nat(lr);
        nbrec_logical_router_set_nat(lr, new_nats, n_nat);
        free(new_nats);
        return;
    }

    const char *nat_ip = ctx->argv[3];
    int is_snat = !strcmp("snat", nat_type);
    /* Remove the matching NAT. */
    for (size_t i = 0; i < lr->n_nat; i++) {
        struct nbrec_nat *nat = lr->nat[i];
        if (!strcmp(nat_type, nat->type) &&
             !strcmp(nat_ip, is_snat ? nat->logical_ip : nat->external_ip)) {
            struct nbrec_nat **new_nats
                = xmemdup(lr->nat, sizeof *new_nats * lr->n_nat);
            new_nats[i] = lr->nat[lr->n_nat - 1];
            nbrec_logical_router_verify_nat(lr);
            nbrec_logical_router_set_nat(lr, new_nats,
                                          lr->n_nat - 1);
            free(new_nats);
            return;
        }
    }

    if (must_exist) {
        ctl_error(ctx, "no matching NAT with the type (%s) and %s (%s)",
                  nat_type, is_snat ? "logical_ip" : "external_ip", nat_ip);
        return;
    }
}

static void
nbctl_lr_nat_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap lr_nats = SMAP_INITIALIZER(&lr_nats);
    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];
        char *key = xasprintf("%-17.13s%s", nat->type, nat->external_ip);
        if (nat->external_mac && nat->logical_port) {
            smap_add_format(&lr_nats, key, "%-22.18s%-21.17s%s",
                            nat->logical_ip, nat->external_mac,
                            nat->logical_port);
        } else {
            smap_add_format(&lr_nats, key, "%s", nat->logical_ip);
        }
        free(key);
    }

    const struct smap_node **nodes = smap_sort(&lr_nats);
    if (nodes) {
        ds_put_format(&ctx->output, "%-17.13s%-19.15s%-22.18s%-21.17s%s\n",
                "TYPE", "EXTERNAL_IP", "LOGICAL_IP", "EXTERNAL_MAC",
                "LOGICAL_PORT");
        for (size_t i = 0; i < smap_count(&lr_nats); i++) {
            const struct smap_node *node = nodes[i];
            ds_put_format(&ctx->output, "%-36.32s%s\n",
                    node->key, node->value);
        }
        free(nodes);
    }
    smap_destroy(&lr_nats);
}


static char * OVS_WARN_UNUSED_RESULT
lrp_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                    const struct nbrec_logical_router_port **lrp_p)
{
    const struct nbrec_logical_router_port *lrp = NULL;
    *lrp_p = NULL;

    struct uuid lrp_uuid;
    bool is_uuid = uuid_from_string(&lrp_uuid, id);
    if (is_uuid) {
        lrp = nbrec_logical_router_port_get_for_uuid(ctx->idl, &lrp_uuid);
    }

    if (!lrp) {
        NBREC_LOGICAL_ROUTER_PORT_FOR_EACH(lrp, ctx->idl) {
            if (!strcmp(lrp->name, id)) {
                break;
            }
        }
    }

    if (!lrp && must_exist) {
        return xasprintf("%s: port %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lrp_p = lrp;
    return NULL;
}

/* Returns the logical router that contains 'lrp'. */
static char * OVS_WARN_UNUSED_RESULT
lrp_to_lr(const struct ovsdb_idl *idl,
          const struct nbrec_logical_router_port *lrp,
          const struct nbrec_logical_router **lr_p)
{
    const struct nbrec_logical_router *lr;
    *lr_p = NULL;

    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, idl) {
        for (size_t i = 0; i < lr->n_ports; i++) {
            if (lr->ports[i] == lrp) {
                *lr_p = lr;
                return NULL;
            }
        }
    }

    /* Can't happen because of the database schema */
    return xasprintf("port %s is not part of any logical router",
                     lrp->name);
}

static const char *
lr_get_name(const struct nbrec_logical_router *lr, char uuid_s[UUID_LEN + 1],
            size_t uuid_s_size)
{
    if (lr->name[0]) {
        return lr->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&lr->header_.uuid));
    return uuid_s;
}

static char * OVS_WARN_UNUSED_RESULT
gc_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_gateway_chassis **gc_p)
{
    const struct nbrec_gateway_chassis *gc = NULL;
    *gc_p = NULL;

    struct uuid gc_uuid;
    bool is_uuid = uuid_from_string(&gc_uuid, id);
    if (is_uuid) {
        gc = nbrec_gateway_chassis_get_for_uuid(ctx->idl, &gc_uuid);
    }

    if (!gc) {
        NBREC_GATEWAY_CHASSIS_FOR_EACH (gc, ctx->idl) {
            if (!strcmp(gc->name, id)) {
                break;
            }
        }
    }

    if (!gc && must_exist) {
        return xasprintf("%s: gateway chassis %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    *gc_p = gc;
    return NULL;
}

static void
nbctl_lrp_set_gateway_chassis(struct ctl_context *ctx)
{
    char *gc_name;
    int64_t priority = 0;
    const char *lrp_name = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;
    char *error = lrp_by_name_or_uuid(ctx, lrp_name, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        ctl_error(ctx, "router port %s is required", lrp_name);
        return;
    }

    const char *chassis_name = ctx->argv[2];
    if (ctx->argv[3]) {
        error = parse_priority(ctx->argv[3], &priority);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    gc_name = xasprintf("%s-%s", lrp_name, chassis_name);
    const struct nbrec_gateway_chassis *existing_gc;
    error = gc_by_name_or_uuid(ctx, gc_name, false, &existing_gc);
    if (error) {
        ctx->error = error;
        free(gc_name);
        return;
    }
    if (existing_gc) {
        nbrec_gateway_chassis_set_priority(existing_gc, priority);
        free(gc_name);
        return;
    }

    /* Create the logical gateway chassis. */
    struct nbrec_gateway_chassis *gc
        = nbrec_gateway_chassis_insert(ctx->txn);
    nbrec_gateway_chassis_set_name(gc, gc_name);
    nbrec_gateway_chassis_set_chassis_name(gc, chassis_name);
    nbrec_gateway_chassis_set_priority(gc, priority);

    /* Insert the logical gateway chassis into the logical router port. */
    nbrec_logical_router_port_verify_gateway_chassis(lrp);
    struct nbrec_gateway_chassis **new_gc = xmalloc(
        sizeof *new_gc * (lrp->n_gateway_chassis + 1));
    nullable_memcpy(new_gc, lrp->gateway_chassis,
                    sizeof *new_gc * lrp->n_gateway_chassis);
    new_gc[lrp->n_gateway_chassis] = gc;
    nbrec_logical_router_port_set_gateway_chassis(
        lrp, new_gc, lrp->n_gateway_chassis + 1);
    free(new_gc);
    free(gc_name);
}

/* Removes logical router port 'lrp->gateway_chassis[idx]'. */
static void
remove_gc(const struct nbrec_logical_router_port *lrp, size_t idx)
{
    const struct nbrec_gateway_chassis *gc = lrp->gateway_chassis[idx];

    if (lrp->n_gateway_chassis == 1) {
        nbrec_logical_router_port_set_gateway_chassis(lrp, NULL, 0);
    } else {
        /* First remove 'gc' from the array of gateway_chassis.  This is what
         * will actually cause the gateway chassis to be deleted when the
         * transaction is sent to the database server (due to garbage
         * collection). */
        struct nbrec_gateway_chassis **new_gc
            = xmemdup(lrp->gateway_chassis,
                      sizeof *new_gc * lrp->n_gateway_chassis);
        new_gc[idx] = new_gc[lrp->n_gateway_chassis - 1];
        nbrec_logical_router_port_verify_gateway_chassis(lrp);
        nbrec_logical_router_port_set_gateway_chassis(
            lrp, new_gc, lrp->n_gateway_chassis - 1);
        free(new_gc);
    }

    /* Delete 'gc' from the IDL.  This won't have a real effect on
     * the database server (the IDL will suppress it in fact) but it
     * means that it won't show up when we iterate with
     * NBREC_GATEWAY_CHASSIS_FOR_EACH later. */
    nbrec_gateway_chassis_delete(gc);
}

static void
nbctl_lrp_del_gateway_chassis(struct ctl_context *ctx)
{
    const struct nbrec_logical_router_port *lrp = NULL;
    char *error = lrp_by_name_or_uuid(ctx, ctx->argv[1], true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }
    /* Find the lrp that contains 'gc', then delete it. */
    const char *chassis_name = ctx->argv[2];
    for (size_t i = 0; i < lrp->n_gateway_chassis; i++) {
        if (!strncmp(lrp->gateway_chassis[i]->chassis_name,
                    chassis_name,
                    strlen(lrp->gateway_chassis[i]->chassis_name))) {
            remove_gc(lrp, i);
            return;
        }
    }

    /* Can't happen because of the database schema. */
    ctl_error(ctx, "chassis %s is not added to logical port %s",
              chassis_name, ctx->argv[1]);
}

/* Print a list of gateway chassis. */
static void
nbctl_lrp_get_gateway_chassis(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;
    const struct nbrec_gateway_chassis **gcs;
    size_t i;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    gcs = get_ordered_gw_chassis_prio_list(lrp);

    for (i = 0; i < lrp->n_gateway_chassis; i++) {
        const struct nbrec_gateway_chassis *gc = gcs[i];
        ds_put_format(&ctx->output, "%s %5"PRId64"\n",
                      gc->name, gc->priority);
    }

    free(gcs);
}

static void
nbctl_lrp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;

    const struct nbrec_logical_router *lr = NULL;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *lrp_name = ctx->argv[2];
    const char *mac = ctx->argv[3];
    const char **networks = (const char **) &ctx->argv[4];

    int n_networks = ctx->argc - 4;
    for (int i = 4; i < ctx->argc; i++) {
        if (strchr(ctx->argv[i], '=')) {
            n_networks = i - 4;
            break;
        }
    }

    if (!n_networks) {
        ctl_error(ctx, "%s: router port requires specifying a network",
                  lrp_name);
        return;
    }

    char **settings = (char **) &ctx->argv[n_networks + 4];
    int n_settings = ctx->argc - 4 - n_networks;

    const struct nbrec_logical_router_port *lrp;
    error = lrp_by_name_or_uuid(ctx, lrp_name, false, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lrp) {
        if (!may_exist) {
            ctl_error(ctx, "%s: a port with this name already exists",
                      lrp_name);
            return;
        }

        const struct nbrec_logical_router *bound_lr;
        error = lrp_to_lr(ctx->idl, lrp, &bound_lr);
        if (error) {
            ctx->error = error;
            return;
        }
        if (bound_lr != lr) {
            char uuid_s[UUID_LEN + 1];
            ctl_error(ctx, "%s: port already exists but in router %s",
                      lrp_name, lr_get_name(bound_lr, uuid_s, sizeof uuid_s));
            return;
        }

        if (strcmp(mac, lrp->mac)) {
            ctl_error(ctx, "%s: port already exists with mac %s", lrp_name,
                      lrp->mac);
            return;
        }

        struct sset new_networks = SSET_INITIALIZER(&new_networks);
        for (int i = 0; i < n_networks; i++) {
            sset_add(&new_networks, networks[i]);
        }

        struct sset orig_networks = SSET_INITIALIZER(&orig_networks);
        sset_add_array(&orig_networks, lrp->networks, lrp->n_networks);

        bool same_networks = sset_equals(&orig_networks, &new_networks);
        sset_destroy(&orig_networks);
        sset_destroy(&new_networks);
        if (!same_networks) {
            ctl_error(ctx, "%s: port already exists with different network",
                      lrp_name);
            return;
        }

        /* Special-case sanity-check of peer ports. */
        const char *peer = NULL;
        for (int i = 0; i < n_settings; i++) {
            if (!strncmp(settings[i], "peer=", 5)) {
                peer = settings[i] + 5;
                break;
            }
        }

        if ((!peer != !lrp->peer) ||
                (lrp->peer && strcmp(peer, lrp->peer))) {
            ctl_error(ctx, "%s: port already exists with mismatching peer",
                      lrp_name);
            return;
        }

        return;
    }

    struct eth_addr ea;
    if (!eth_addr_from_string(mac, &ea)) {
        ctl_error(ctx, "%s: invalid mac address %s", lrp_name, mac);
        return;
    }

    for (int i = 0; i < n_networks; i++) {
        ovs_be32 ipv4;
        unsigned int plen;
        error = ip_parse_cidr(networks[i], &ipv4, &plen);
        if (error) {
            free(error);
            struct in6_addr ipv6;
            error = ipv6_parse_cidr(networks[i], &ipv6, &plen);
            if (error) {
                free(error);
                ctl_error(ctx, "%s: invalid network address: %s", lrp_name,
                          networks[i]);
                return;
            }
        }
    }

    /* Create the logical port. */
    lrp = nbrec_logical_router_port_insert(ctx->txn);
    nbrec_logical_router_port_set_name(lrp, lrp_name);
    nbrec_logical_router_port_set_mac(lrp, mac);
    nbrec_logical_router_port_set_networks(lrp, networks, n_networks);

    for (int i = 0; i < n_settings; i++) {
        error = ctl_set_column("Logical_Router_Port", &lrp->header_,
                               settings[i], ctx->symtab);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    /* Insert the logical port into the logical router. */
    nbrec_logical_router_verify_ports(lr);
    struct nbrec_logical_router_port **new_ports = xmalloc(sizeof *new_ports *
                                                        (lr->n_ports + 1));
    nullable_memcpy(new_ports, lr->ports, sizeof *new_ports * lr->n_ports);
    new_ports[lr->n_ports] = CONST_CAST(struct nbrec_logical_router_port *,
                                             lrp);
    nbrec_logical_router_set_ports(lr, new_ports, lr->n_ports + 1);
    free(new_ports);
}

/* Removes logical router port 'lr->ports[idx]'. */
static void
remove_lrp(const struct nbrec_logical_router *lr, size_t idx)
{
    const struct nbrec_logical_router_port *lrp = lr->ports[idx];

    /* First remove 'lrp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    struct nbrec_logical_router_port **new_ports
        = xmemdup(lr->ports, sizeof *new_ports * lr->n_ports);
    new_ports[idx] = new_ports[lr->n_ports - 1];
    nbrec_logical_router_verify_ports(lr);
    nbrec_logical_router_set_ports(lr, new_ports, lr->n_ports - 1);
    free(new_ports);

    /* Delete 'lrp' from the IDL.  This won't have a real effect on
     * the database server (the IDL will suppress it in fact) but it
     * means that it won't show up when we iterate with
     * NBREC_LOGICAL_ROUTER_PORT_FOR_EACH later. */
    nbrec_logical_router_port_delete(lrp);
}

static void
nbctl_lrp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, ctx->argv[1], must_exist, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    /* Find the router that contains 'lrp', then delete it. */
    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->idl) {
        for (size_t i = 0; i < lr->n_ports; i++) {
            if (lr->ports[i] == lrp) {
                remove_lrp(lr, i);
                return;
            }
        }
    }

    /* Can't happen because of the database schema. */
    ctl_error(ctx, "logical port %s is not part of any logical router",
              ctx->argv[1]);
}

/* Print a list of logical router ports. */
static void
nbctl_lrp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr;
    struct smap lrps;
    size_t i;

    char *error = lr_by_name_or_uuid(ctx, id, true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    smap_init(&lrps);
    for (i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        smap_add_format(&lrps, lrp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lrp->header_.uuid), lrp->name);
    }
    const struct smap_node **nodes = smap_sort(&lrps);
    for (i = 0; i < smap_count(&lrps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrps);
    free(nodes);
}

/* Set the logical router port admin-enabled state. */
static void
nbctl_lrp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    bool enabled;
    error = parse_enabled(state, &enabled);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_router_port_set_enabled(lrp, &enabled, 1);
}

/* Print admin-enabled state for logical router port. */
static void
nbctl_lrp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n",
                  !lrp->enabled ||
                  *lrp->enabled ? "enabled" : "disabled");
}

struct ipv4_route {
    int priority;
    ovs_be32 addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
ipv4_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv4_route *route1p = route1_;
    const struct ipv4_route *route2p = route2_;

    if (route1p->priority != route2p->priority) {
        return route1p->priority > route2p->priority ? -1 : 1;
    } else if (route1p->addr != route2p->addr) {
        return ntohl(route1p->addr) < ntohl(route2p->addr) ? -1 : 1;
    } else {
        return 0;
    }
}

struct ipv6_route {
    int priority;
    struct in6_addr addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
ipv6_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv6_route *route1p = route1_;
    const struct ipv6_route *route2p = route2_;

    if (route1p->priority != route2p->priority) {
        return route1p->priority > route2p->priority ? -1 : 1;
    }
    return memcmp(&route1p->addr, &route2p->addr, sizeof(route1p->addr));
}

static void
print_route(const struct nbrec_logical_router_static_route *route, struct ds *s)
{

    char *prefix = normalize_prefix_str(route->ip_prefix);
    char *next_hop = normalize_prefix_str(route->nexthop);
    ds_put_format(s, "%25s %25s", prefix, next_hop);
    free(prefix);
    free(next_hop);

    if (route->policy) {
        ds_put_format(s, " %s", route->policy);
    } else {
        ds_put_format(s, " %s", "dst-ip");
    }

    if (route->output_port) {
        ds_put_format(s, " %s", route->output_port);
    }
    ds_put_char(s, '\n');
}

static void
nbctl_lr_route_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct ipv4_route *ipv4_routes;
    struct ipv6_route *ipv6_routes;
    size_t n_ipv4_routes = 0;
    size_t n_ipv6_routes = 0;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    ipv4_routes = xmalloc(sizeof *ipv4_routes * lr->n_static_routes);
    ipv6_routes = xmalloc(sizeof *ipv6_routes * lr->n_static_routes);

    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *route
            = lr->static_routes[i];
        unsigned int plen;
        ovs_be32 ipv4;
        const char *policy = route->policy ? route->policy : "dst-ip";
        error = ip_parse_cidr(route->ip_prefix, &ipv4, &plen);
        if (!error) {
            ipv4_routes[n_ipv4_routes].priority = !strcmp(policy, "dst-ip")
                                                    ? (2 * plen) + 1
                                                    : 2 * plen;
            ipv4_routes[n_ipv4_routes].addr = ipv4;
            ipv4_routes[n_ipv4_routes].route = route;
            n_ipv4_routes++;
        } else {
            free(error);

            struct in6_addr ipv6;
            error = ipv6_parse_cidr(route->ip_prefix, &ipv6, &plen);
            if (!error) {
                ipv6_routes[n_ipv6_routes].priority = !strcmp(policy, "dst-ip")
                                                        ? (2 * plen) + 1
                                                        : 2 * plen;
                ipv6_routes[n_ipv6_routes].addr = ipv6;
                ipv6_routes[n_ipv6_routes].route = route;
                n_ipv6_routes++;
            } else {
                /* Invalid prefix. */
                VLOG_WARN("router "UUID_FMT" (%s) has invalid prefix: %s",
                          UUID_ARGS(&lr->header_.uuid), lr->name,
                          route->ip_prefix);
                free(error);
                continue;
            }
        }
    }

    qsort(ipv4_routes, n_ipv4_routes, sizeof *ipv4_routes, ipv4_route_cmp);
    qsort(ipv6_routes, n_ipv6_routes, sizeof *ipv6_routes, ipv6_route_cmp);

    if (n_ipv4_routes) {
        ds_put_cstr(&ctx->output, "IPv4 Routes\n");
    }
    for (int i = 0; i < n_ipv4_routes; i++) {
        print_route(ipv4_routes[i].route, &ctx->output);
    }

    if (n_ipv6_routes) {
        ds_put_format(&ctx->output, "%sIPv6 Routes\n",
                      n_ipv4_routes ?  "\n" : "");
    }
    for (int i = 0; i < n_ipv6_routes; i++) {
        print_route(ipv6_routes[i].route, &ctx->output);
    }

    free(ipv4_routes);
    free(ipv6_routes);
}

static void
verify_connections(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_connection *conn;

    nbrec_nb_global_verify_connections(nb_global);

    NBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        nbrec_connection_verify_target(conn);
    }
}

static void
pre_connection(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_connections);
    ovsdb_idl_add_column(ctx->idl, &nbrec_connection_col_target);
    ovsdb_idl_add_column(ctx->idl, &nbrec_connection_col_inactivity_probe);
}

static void
cmd_get_connection(struct ctl_context *ctx)
{
    const struct nbrec_connection *conn;
    struct svec targets;
    size_t i;

    verify_connections(ctx);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    NBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        svec_add(&targets, conn->target);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_connections(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_connection *conn, *next;

    /* Delete Manager rows pointed to by 'connection_options' column. */
    NBREC_CONNECTION_FOR_EACH_SAFE(conn, next, ctx->idl) {
        nbrec_connection_delete(conn);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    nbrec_nb_global_set_connections(nb_global, NULL, 0);
}

static void
cmd_del_connection(struct ctl_context *ctx)
{
    verify_connections(ctx);
    delete_connections(ctx);
}

static void
insert_connections(struct ctl_context *ctx, char *targets[], size_t n)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    struct nbrec_connection **connections;
    size_t i, conns=0;
    const char *inactivity_probe = shash_find_data(&ctx->options,
                                                   "--inactivity-probe");

    /* Insert each connection in a new row in Connection table. */
    connections = xmalloc(n * sizeof *connections);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) &&
                   pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }

        connections[conns] = nbrec_connection_insert(ctx->txn);
        nbrec_connection_set_target(connections[conns], targets[i]);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            nbrec_connection_set_inactivity_probe(connections[conns],
                                                  &msecs, 1);
        }
        conns++;
    }

    /* Store uuids of new connection rows in 'connection' column. */
    nbrec_nb_global_set_connections(nb_global, connections, conns);
    free(connections);
}

static void
cmd_set_connection(struct ctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_connections(ctx);
    delete_connections(ctx);
    insert_connections(ctx, &ctx->argv[1], n);
}

static void
pre_cmd_get_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_private_key);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_certificate);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_bootstrap_ca_cert);
}

static void
cmd_get_ssl(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    nbrec_nb_global_verify_ssl(nb_global);
    if (ssl) {
        nbrec_ssl_verify_private_key(ssl);
        nbrec_ssl_verify_certificate(ssl);
        nbrec_ssl_verify_ca_cert(ssl);
        nbrec_ssl_verify_bootstrap_ca_cert(ssl);

        ds_put_format(&ctx->output, "Private key: %s\n", ssl->private_key);
        ds_put_format(&ctx->output, "Certificate: %s\n", ssl->certificate);
        ds_put_format(&ctx->output, "CA Certificate: %s\n", ssl->ca_cert);
        ds_put_format(&ctx->output, "Bootstrap: %s\n",
                ssl->bootstrap_ca_cert ? "true" : "false");
    }
}

static void
pre_cmd_del_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);
}

static void
cmd_del_ssl(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    if (ssl) {
        nbrec_nb_global_verify_ssl(nb_global);
        nbrec_ssl_delete(ssl);
        nbrec_nb_global_set_ssl(nb_global, NULL);
    }
}

static void
pre_cmd_set_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);
}

static void
cmd_set_ssl(struct ctl_context *ctx)
{
    bool bootstrap = shash_find(&ctx->options, "--bootstrap");
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    nbrec_nb_global_verify_ssl(nb_global);
    if (ssl) {
        nbrec_ssl_delete(ssl);
    }
    ssl = nbrec_ssl_insert(ctx->txn);

    nbrec_ssl_set_private_key(ssl, ctx->argv[1]);
    nbrec_ssl_set_certificate(ssl, ctx->argv[2]);
    nbrec_ssl_set_ca_cert(ssl, ctx->argv[3]);

    nbrec_ssl_set_bootstrap_ca_cert(ssl, bootstrap);

    if (ctx->argc == 5) {
        nbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
    } else if (ctx->argc == 6) {
        nbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
        nbrec_ssl_set_ssl_ciphers(ssl, ctx->argv[5]);
    }

    nbrec_nb_global_set_ssl(nb_global, ssl);
}

static char *
set_ports_on_pg(struct ctl_context *ctx, const struct nbrec_port_group *pg,
                char **new_ports, size_t num_new_ports)
{
    struct nbrec_logical_switch_port **lports;
    lports = xmalloc(sizeof *lports * num_new_ports);

    size_t i;
    char *error = NULL;
    for (i = 0; i < num_new_ports; i++) {
        const struct nbrec_logical_switch_port *lsp;
        error = lsp_by_name_or_uuid(ctx, new_ports[i], true, &lsp);
        if (error) {
            goto out;
        }
        lports[i] = (struct nbrec_logical_switch_port *) lsp;
    }

    nbrec_port_group_set_ports(pg, lports, num_new_ports);

out:
    free(lports);
    return error;
}

static void
cmd_pg_add(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    pg = nbrec_port_group_insert(ctx->txn);
    nbrec_port_group_set_name(pg, ctx->argv[1]);
    if (ctx->argc > 2) {
        ctx->error = set_ports_on_pg(ctx, pg, ctx->argv + 2, ctx->argc - 2);
    }
}

static void
cmd_pg_set_ports(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    char *error;
    error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    ctx->error = set_ports_on_pg(ctx, pg, ctx->argv + 2, ctx->argc - 2);
}

static void
cmd_pg_del(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    char *error;
    error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    nbrec_port_group_delete(pg);
}

static const struct ctl_table_class tables[NBREC_N_TABLES] = {
    [NBREC_TABLE_DHCP_OPTIONS].row_ids
    = {{&nbrec_logical_switch_port_col_name, NULL,
        &nbrec_logical_switch_port_col_dhcpv4_options},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", &nbrec_logical_switch_port_col_dhcpv4_options},
       {&nbrec_logical_switch_port_col_name, NULL,
        &nbrec_logical_switch_port_col_dhcpv6_options},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", &nbrec_logical_switch_port_col_dhcpv6_options}},

    [NBREC_TABLE_LOGICAL_SWITCH].row_ids
    = {{&nbrec_logical_switch_col_name, NULL, NULL},
       {&nbrec_logical_switch_col_external_ids, "neutron:network_name", NULL}},

    [NBREC_TABLE_LOGICAL_SWITCH_PORT].row_ids
    = {{&nbrec_logical_switch_port_col_name, NULL, NULL},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", NULL}},

    [NBREC_TABLE_LOGICAL_ROUTER].row_ids
    = {{&nbrec_logical_router_col_name, NULL, NULL},
       {&nbrec_logical_router_col_external_ids, "neutron:router_name", NULL}},

    [NBREC_TABLE_LOGICAL_ROUTER_PORT].row_ids[0]
    = {&nbrec_logical_router_port_col_name, NULL, NULL},

    [NBREC_TABLE_ADDRESS_SET].row_ids[0]
    = {&nbrec_address_set_col_name, NULL, NULL},

    [NBREC_TABLE_PORT_GROUP].row_ids[0]
    = {&nbrec_port_group_col_name, NULL, NULL},

    [NBREC_TABLE_ACL].row_ids[0] = {&nbrec_acl_col_name, NULL, NULL},
};

static char *
run_prerequisites(struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    ovsdb_idl_add_table(idl, &nbrec_table_nb_global);
    if (wait_type == NBCTL_WAIT_SB) {
        ovsdb_idl_add_column(idl, &nbrec_nb_global_col_sb_cfg);
    } else if (wait_type == NBCTL_WAIT_HV) {
        ovsdb_idl_add_column(idl, &nbrec_nb_global_col_hv_cfg);
    }

    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct ctl_context ctx;

            ds_init(&c->output);
            c->table = NULL;

            ctl_context_init(&ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&ctx);
            if (ctx.error) {
                char *error = xstrdup(ctx.error);
                ctl_context_done(&ctx, c);
                return error;
            }
            ctl_context_done(&ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }

    return NULL;
}

static void
oneline_format(struct ds *lines, struct ds *s)
{
    size_t j;

    ds_chomp(lines, '\n');
    for (j = 0; j < lines->length; j++) {
        int ch = lines->string[j];
        switch (ch) {
        case '\n':
            ds_put_cstr(s, "\\n");
            break;

        case '\\':
            ds_put_cstr(s, "\\\\");
            break;

        default:
            ds_put_char(s, ch);
        }
    }
    ds_put_char(s, '\n');
}

static void
oneline_print(struct ds *lines)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    oneline_format(lines, &s);
    fputs(ds_cstr(&s), stdout);
    ds_destroy(&s);
}

static char *
do_nbctl(const char *args, struct ctl_command *commands, size_t n_commands,
         struct ovsdb_idl *idl, const struct timer *wait_timeout, bool *retry)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct ctl_context ctx;
    struct ctl_command *c;
    struct shash_node *node;
    int64_t next_cfg = 0;
    char *error = NULL;

    ovs_assert(retry);

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "ovs-nbctl: %s", args);

    const struct nbrec_nb_global *nb = nbrec_nb_global_first(idl);
    if (!nb) {
        /* XXX add verification that table is empty */
        nb = nbrec_nb_global_insert(txn);
    }

    if (wait_type != NBCTL_WAIT_NONE) {
        ovsdb_idl_txn_increment(txn, &nb->header_, &nbrec_nb_global_col_nb_cfg,
                                force_wait);
    }

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    ctl_context_init(&ctx, NULL, idl, txn, symtab, NULL);
    for (c = commands; c < &commands[n_commands]; c++) {
        ctl_context_init_command(&ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&ctx);
        }
        if (ctx.error) {
            error = xstrdup(ctx.error);
            ctl_context_done(&ctx, c);
            goto out_error;
        }
        ctl_context_done_command(&ctx, c);

        if (ctx.try_again) {
            ctl_context_done(&ctx, NULL);
            goto try_again;
        }
    }
    ctl_context_done(&ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            error = xasprintf("row id \"%s\" is referenced but never created "
                              "(e.g. with \"-- --id=%s create ...\")",
                              node->name, node->name);
            goto out_error;
        }
        if (!symbol->strong_ref) {
            if (!symbol->weak_ref) {
                VLOG_WARN("row id \"%s\" was created but no reference to it "
                          "was inserted, so it will not actually appear in "
                          "the database", node->name);
            } else {
                VLOG_WARN("row id \"%s\" was created but only a weak "
                          "reference to it was inserted, so it will not "
                          "actually appear in the database", node->name);
            }
        }
    }

    status = ovsdb_idl_txn_commit_block(txn);
    if (wait_type != NBCTL_WAIT_NONE && status == TXN_SUCCESS) {
        next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    }
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                ctl_context_init(&ctx, c, idl, txn, symtab, NULL);
                (c->syntax->postprocess)(&ctx);
                if (ctx.error) {
                    error = xstrdup(ctx.error);
                    ctl_context_done(&ctx, c);
                    goto out_error;
                }
                ctl_context_done(&ctx, c);
            }
        }
    }

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        error = xstrdup("transaction aborted");
        goto out_error;

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        error = xasprintf("transaction error: %s",
                          ovsdb_idl_txn_get_error(txn));
        goto out_error;

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        error = xstrdup("database not locked");
        goto out_error;

    default:
        OVS_NOT_REACHED();
    }

    for (c = commands; c < &commands[n_commands]; c++) {
        struct ds *ds = &c->output;

        if (c->table) {
            table_print(c->table, &table_style);
        } else if (oneline) {
            oneline_print(ds);
        } else {
            fputs(ds_cstr(ds), stdout);
        }
    }

    if (wait_type != NBCTL_WAIT_NONE && status != TXN_UNCHANGED) {
        ovsdb_idl_enable_reconnect(idl);
        for (;;) {
            ovsdb_idl_run(idl);
            NBREC_NB_GLOBAL_FOR_EACH (nb, idl) {
                int64_t cur_cfg = (wait_type == NBCTL_WAIT_SB
                                   ? nb->sb_cfg
                                   : nb->hv_cfg);
                if (cur_cfg >= next_cfg) {
                    goto done;
                }
            }
            ovsdb_idl_wait(idl);
            if (wait_timeout) {
                timer_wait(wait_timeout);
            }
            poll_block();
            if (wait_timeout && timer_expired(wait_timeout)) {
                error = xstrdup("timeout expired");
                goto out_error;
            }
        }
    done: ;
    }

    ovsdb_symbol_table_destroy(symtab);
    ovsdb_idl_txn_destroy(txn);
    the_idl_txn = NULL;

    *retry = false;
    return NULL;

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    *retry = true;

out_error:
    ovsdb_idl_txn_abort(txn);
    ovsdb_idl_txn_destroy(txn);
    the_idl_txn = NULL;

    ovsdb_symbol_table_destroy(symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }

    return error;
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
nbctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

static const struct ctl_command_syntax nbctl_commands[] = {
    { "init", 0, 0, "", NULL, nbctl_init, NULL, "", RW },
    { "sync", 0, 0, "", nbctl_pre_sync, nbctl_sync, NULL, "", RO },
    { "show", 0, 1, "[SWITCH]", NULL, nbctl_show, NULL, "", RO },

    /* logical switch commands. */
    { "ls-add", 0, 1, "[SWITCH]", NULL, nbctl_ls_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "ls-del", 1, 1, "SWITCH", NULL, nbctl_ls_del, NULL, "--if-exists", RW },
    { "ls-list", 0, 0, "", NULL, nbctl_ls_list, NULL, "", RO },

    /* acl commands. */
    { "acl-add", 5, 6, "{SWITCH | PORTGROUP} DIRECTION PRIORITY MATCH ACTION",
      NULL, nbctl_acl_add, NULL,
      "--log,--may-exist,--type=,--name=,--severity=,--meter=", RW },
    { "acl-del", 1, 4, "{SWITCH | PORTGROUP} [DIRECTION [PRIORITY MATCH]]",
      NULL, nbctl_acl_del, NULL, "--type=", RW },
    { "acl-list", 1, 1, "{SWITCH | PORTGROUP}",
      NULL, nbctl_acl_list, NULL, "--type=", RO },

    /* qos commands. */
    { "qos-add", 5, 7,
      "SWITCH DIRECTION PRIORITY MATCH [rate=RATE [burst=BURST]] [dscp=DSCP]",
      NULL, nbctl_qos_add, NULL, "--may-exist", RW },
    { "qos-del", 1, 4, "SWITCH [DIRECTION [PRIORITY MATCH]]", NULL,
      nbctl_qos_del, NULL, "", RW },
    { "qos-list", 1, 1, "SWITCH", NULL, nbctl_qos_list, NULL, "", RO },

    /* meter commands. */
    { "meter-add", 4, 5, "NAME ACTION RATE UNIT [BURST]", NULL,
      nbctl_meter_add, NULL, "", RW },
    { "meter-del", 0, 1, "[NAME]", NULL, nbctl_meter_del, NULL, "", RW },
    { "meter-list", 0, 0, "", NULL, nbctl_meter_list, NULL, "", RO },

    /* logical switch port commands. */
    { "lsp-add", 2, 4, "SWITCH PORT [PARENT] [TAG]", NULL, nbctl_lsp_add,
      NULL, "--may-exist", RW },
    { "lsp-del", 1, 1, "PORT", NULL, nbctl_lsp_del, NULL, "--if-exists", RW },
    { "lsp-list", 1, 1, "SWITCH", NULL, nbctl_lsp_list, NULL, "", RO },
    { "lsp-get-parent", 1, 1, "PORT", NULL, nbctl_lsp_get_parent, NULL,
      "", RO },
    { "lsp-get-tag", 1, 1, "PORT", NULL, nbctl_lsp_get_tag, NULL, "", RO },
    { "lsp-set-addresses", 1, INT_MAX, "PORT [ADDRESS]...", NULL,
      nbctl_lsp_set_addresses, NULL, "", RW },
    { "lsp-get-addresses", 1, 1, "PORT", NULL, nbctl_lsp_get_addresses, NULL,
      "", RO },
    { "lsp-set-port-security", 0, INT_MAX, "PORT [ADDRS]...", NULL,
      nbctl_lsp_set_port_security, NULL, "", RW },
    { "lsp-get-port-security", 1, 1, "PORT", NULL,
      nbctl_lsp_get_port_security, NULL, "", RO },
    { "lsp-get-up", 1, 1, "PORT", NULL, nbctl_lsp_get_up, NULL, "", RO },
    { "lsp-set-enabled", 2, 2, "PORT STATE", NULL, nbctl_lsp_set_enabled,
      NULL, "", RW },
    { "lsp-get-enabled", 1, 1, "PORT", NULL, nbctl_lsp_get_enabled, NULL,
      "", RO },
    { "lsp-set-type", 2, 2, "PORT TYPE", NULL, nbctl_lsp_set_type, NULL,
      "", RW },
    { "lsp-get-type", 1, 1, "PORT", NULL, nbctl_lsp_get_type, NULL, "", RO },
    { "lsp-set-options", 1, INT_MAX, "PORT KEY=VALUE [KEY=VALUE]...", NULL,
      nbctl_lsp_set_options, NULL, "", RW },
    { "lsp-get-options", 1, 1, "PORT", NULL, nbctl_lsp_get_options, NULL,
      "", RO },
    { "lsp-set-dhcpv4-options", 1, 2, "PORT [DHCP_OPT_UUID]", NULL,
      nbctl_lsp_set_dhcpv4_options, NULL, "", RW },
    { "lsp-get-dhcpv4-options", 1, 1, "PORT", NULL,
      nbctl_lsp_get_dhcpv4_options, NULL, "", RO },
    { "lsp-set-dhcpv6-options", 1, 2, "PORT [DHCP_OPT_UUID]", NULL,
      nbctl_lsp_set_dhcpv6_options, NULL, "", RW },
    { "lsp-get-dhcpv6-options", 1, 1, "PORT", NULL,
      nbctl_lsp_get_dhcpv6_options, NULL, "", RO },

    /* logical router commands. */
    { "lr-add", 0, 1, "[ROUTER]", NULL, nbctl_lr_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "lr-del", 1, 1, "ROUTER", NULL, nbctl_lr_del, NULL, "--if-exists", RW },
    { "lr-list", 0, 0, "", NULL, nbctl_lr_list, NULL, "", RO },

    /* logical router port commands. */
    { "lrp-add", 4, INT_MAX,
      "ROUTER PORT MAC NETWORK... [COLUMN[:KEY]=VALUE]...",
      NULL, nbctl_lrp_add, NULL, "--may-exist", RW },
    { "lrp-set-gateway-chassis", 2, 3,
      "PORT CHASSIS [PRIORITY]",
      NULL, nbctl_lrp_set_gateway_chassis, NULL, "--may-exist", RW },
    { "lrp-del-gateway-chassis", 2, 2, "PORT CHASSIS", NULL,
      nbctl_lrp_del_gateway_chassis, NULL, "", RW },
    { "lrp-get-gateway-chassis", 1, 1, "PORT", NULL,
      nbctl_lrp_get_gateway_chassis, NULL, "", RO },
    { "lrp-del", 1, 1, "PORT", NULL, nbctl_lrp_del, NULL, "--if-exists", RW },
    { "lrp-list", 1, 1, "ROUTER", NULL, nbctl_lrp_list, NULL, "", RO },
    { "lrp-set-enabled", 2, 2, "PORT STATE", NULL, nbctl_lrp_set_enabled,
      NULL, "", RW },
    { "lrp-get-enabled", 1, 1, "PORT", NULL, nbctl_lrp_get_enabled,
      NULL, "", RO },

    /* logical router route commands. */
    { "lr-route-add", 3, 4, "ROUTER PREFIX NEXTHOP [PORT]", NULL,
      nbctl_lr_route_add, NULL, "--may-exist,--policy=", RW },
    { "lr-route-del", 1, 2, "ROUTER [PREFIX]", NULL, nbctl_lr_route_del,
      NULL, "--if-exists", RW },
    { "lr-route-list", 1, 1, "ROUTER", NULL, nbctl_lr_route_list, NULL,
      "", RO },

    /* NAT commands. */
    { "lr-nat-add", 4, 6,
      "ROUTER TYPE EXTERNAL_IP LOGICAL_IP [LOGICAL_PORT EXTERNAL_MAC]", NULL,
      nbctl_lr_nat_add, NULL, "--may-exist", RW },
    { "lr-nat-del", 1, 3, "ROUTER [TYPE [IP]]", NULL,
        nbctl_lr_nat_del, NULL, "--if-exists", RW },
    { "lr-nat-list", 1, 1, "ROUTER", NULL, nbctl_lr_nat_list, NULL, "", RO },

    /* load balancer commands. */
    { "lb-add", 3, 4, "LB VIP[:PORT] IP[:PORT]... [PROTOCOL]", NULL,
      nbctl_lb_add, NULL, "--may-exist,--add-duplicate", RW },
    { "lb-del", 1, 2, "LB [VIP]", NULL, nbctl_lb_del, NULL,
        "--if-exists", RW },
    { "lb-list", 0, 1, "[LB]", NULL, nbctl_lb_list, NULL, "", RO },
    { "lr-lb-add", 2, 2, "ROUTER LB", NULL, nbctl_lr_lb_add, NULL,
        "--may-exist", RW },
    { "lr-lb-del", 1, 2, "ROUTER [LB]", NULL, nbctl_lr_lb_del, NULL,
        "--if-exists", RW },
    { "lr-lb-list", 1, 1, "ROUTER", NULL, nbctl_lr_lb_list, NULL,
        "", RO },
    { "ls-lb-add", 2, 2, "SWITCH LB", NULL, nbctl_ls_lb_add, NULL,
        "--may-exist", RW },
    { "ls-lb-del", 1, 2, "SWITCH [LB]", NULL, nbctl_ls_lb_del, NULL,
        "--if-exists", RW },
    { "ls-lb-list", 1, 1, "SWITCH", NULL, nbctl_ls_lb_list, NULL,
        "", RO },

    /* DHCP_Options commands */
    {"dhcp-options-create", 1, INT_MAX, "CIDR [EXTERNAL:IDS]", NULL,
     nbctl_dhcp_options_create, NULL, "", RW },
    {"dhcp-options-del", 1, 1, "DHCP_OPT_UUID", NULL,
     nbctl_dhcp_options_del, NULL, "", RW},
    {"dhcp-options-list", 0, 0, "", NULL, nbctl_dhcp_options_list, NULL, "", RO},
    {"dhcp-options-set-options", 1, INT_MAX, "DHCP_OPT_UUID KEY=VALUE [KEY=VALUE]...",
    NULL, nbctl_dhcp_options_set_options, NULL, "", RW },
    {"dhcp-options-get-options", 1, 1, "DHCP_OPT_UUID", NULL,
     nbctl_dhcp_options_get_options, NULL, "", RO },

    /* Connection commands. */
    {"get-connection", 0, 0, "", pre_connection, cmd_get_connection, NULL, "", RO},
    {"del-connection", 0, 0, "", pre_connection, cmd_del_connection, NULL, "", RW},
    {"set-connection", 1, INT_MAX, "TARGET...", pre_connection, cmd_set_connection,
     NULL, "--inactivity-probe=", RW},

    /* SSL commands. */
    {"get-ssl", 0, 0, "", pre_cmd_get_ssl, cmd_get_ssl, NULL, "", RO},
    {"del-ssl", 0, 0, "", pre_cmd_del_ssl, cmd_del_ssl, NULL, "", RW},
    {"set-ssl", 3, 5,
        "PRIVATE-KEY CERTIFICATE CA-CERT [SSL-PROTOS [SSL-CIPHERS]]",
        pre_cmd_set_ssl, cmd_set_ssl, NULL, "--bootstrap", RW},

    /* Port Group Commands */
    {"pg-add", 1, INT_MAX, "", NULL, cmd_pg_add, NULL, "", RW },
    {"pg-set-ports", 2, INT_MAX, "", NULL, cmd_pg_set_ports, NULL, "", RW },
    {"pg-del", 1, 1, "", NULL, cmd_pg_del, NULL, "", RW },

    {NULL, 0, 0, NULL, NULL, NULL, NULL, "", RO},
};

/* Registers nbctl and common db commands. */
static void
nbctl_cmd_init(void)
{
    ctl_init(&nbrec_idl_class, nbrec_table_classes, tables, NULL, nbctl_exit);
    ctl_register_commands(nbctl_commands);
}

/* Server implementation. */

#undef ctl_fatal

static const struct option *
find_option_by_value(const struct option *options, int value)
{
    const struct option *o;

    for (o = options; o->name; o++) {
        if (o->val == value) {
            return o;
        }
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
server_parse_options(int argc, char *argv[], struct shash *local_options,
                     int *n_options_p)
{
    static const struct option global_long_options[] = {
        VLOG_LONG_OPTIONS,
        MAIN_LOOP_LONG_OPTIONS,
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *short_options;
    struct option *options;
    char *error = NULL;

    ovs_assert(n_options_p);

    short_options = build_short_options(global_long_options, false);
    options = append_command_options(global_long_options, OPT_LOCAL);

    optind = 0;
    opterr = 0;
    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, options, &idx);
        if (c == -1) {
            break;
        }

        bool handled;
        error = handle_main_loop_option(c, optarg, &handled);
        if (error) {
            goto out;
        }
        if (handled) {
            continue;
        }

        switch (c) {
        case OPT_LOCAL:
            error = add_local_option(options[idx].name, optarg, local_options);
            if (error) {
                goto out;
            }
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)

        case '?':
            if (find_option_by_value(options, optopt)) {
                error = xasprintf("option '%s' doesn't allow an argument",
                                  argv[optind-1]);
            } else if (optopt) {
                error = xasprintf("unrecognized option '%c'", optopt);
            } else {
                error = xasprintf("unrecognized option '%s'", argv[optind-1]);
            }
            goto out;
            break;

        case ':':
            error = xasprintf("option '%s' requires an argument",
                              argv[optind-1]);
            goto out;
            break;

        case 0:
            break;

        default:
            error = xasprintf("unhandled option '%c'", c);
            goto out;
            break;
        }
    }
    *n_options_p = optind;

out:
    for (int i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
    free(short_options);

    return error;
}

static void
server_cmd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
server_cmd_run(struct unixctl_conn *conn, int argc, const char **argv_,
               void *idl_)
{
    struct ovsdb_idl *idl = idl_;
    struct ctl_command *commands = NULL;
    struct shash local_options;
    size_t n_commands = 0;
    int n_options = 0;
    char *error = NULL;

    /* Copy args so that getopt() can permute them. Leave last entry NULL. */
    char **argv = xcalloc(argc + 1, sizeof *argv);
    for (int i = 0; i < argc; i++) {
        argv[i] = xstrdup(argv_[i]);
    }

    /* Reset global state. */
    oneline = false;
    dry_run = false;
    wait_type = NBCTL_WAIT_NONE;
    force_wait = false;
    timeout = 0;
    table_style = table_style_default;

    /* Parse commands & options. */
    char *args = process_escape_args(argv);
    shash_init(&local_options);
    error = server_parse_options(argc, argv, &local_options, &n_options);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    error = ctl_parse_commands(argc - n_options, argv + n_options,
                               &local_options, &commands, &n_commands);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
         "Running command %s", args);

    struct timer *wait_timeout = NULL;
    struct timer wait_timeout_;
    if (timeout) {
        wait_timeout = &wait_timeout_;
        timer_set_duration(wait_timeout, timeout * 1000);
    }

    error = run_prerequisites(commands, n_commands, idl);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    error = main_loop(args, commands, n_commands, idl, wait_timeout);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }

    struct ds output = DS_EMPTY_INITIALIZER;
    table_format_reset();
    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        if (c->table) {
            table_format(c->table, &table_style, &output);
        } else if (oneline) {
            oneline_format(&c->output, &output);
        } else {
            ds_put_cstr(&output, ds_cstr_ro(&c->output));
        }

        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }
    unixctl_command_reply(conn, ds_cstr_ro(&output));
    ds_destroy(&output);

out:
    free(error);
    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        shash_destroy_free_data(&c->options);
    }
    free(commands);
    shash_destroy_free_data(&local_options);
    free(args);
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

static void
server_cmd_init(struct ovsdb_idl *idl, bool *exiting)
{
    unixctl_command_register("exit", "", 0, 0, server_cmd_exit, exiting);
    unixctl_command_register("run", "", 0, INT_MAX, server_cmd_run, idl);
}

static void
server_loop(struct ovsdb_idl *idl, int argc, char *argv[])
{
    struct unixctl_server *server = NULL;
    bool exiting = false;

    service_start(&argc, &argv);
    daemonize_start(false);
    int error = unixctl_server_create(unixctl_path, &server);
    if (error) {
        ctl_fatal("failed to create unixctl server (%s)",
                  ovs_retval_to_string(error));
    }
    puts(unixctl_server_get_path(server));
    fflush(stdout);
    server_cmd_init(idl, &exiting);

    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                      db, ovs_retval_to_string(retval));
        }

        if (ovsdb_idl_has_ever_connected(idl)) {
            daemonize_complete();
            unixctl_server_run(server);
        }
        if (exiting) {
            break;
        }

        ovsdb_idl_wait(idl);
        unixctl_server_wait(server);
        poll_block();
    }

    unixctl_server_destroy(server);
}

static void
nbctl_client(const char *socket_name,
             const struct ovs_cmdl_parsed_option *parsed_options, size_t n,
             int argc, char *argv[])
{
    struct svec args = SVEC_EMPTY_INITIALIZER;

    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        optarg = po->arg;
        switch (po->o->val) {
        case OPT_DB:
            VLOG_WARN("not using ovn-nbctl daemon because of %s option",
                      po->o->name);
            svec_destroy(&args);
            return;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case OPT_COMMANDS:
            ctl_print_commands();
            /* fall through */

        case OPT_OPTIONS:
            ctl_print_options(get_all_options());
            /* fall through */

        case OPT_LEADER_ONLY:
        case OPT_NO_LEADER_ONLY:
        case OPT_BOOTSTRAP_CA_CERT:
        STREAM_SSL_CASES
        DAEMON_OPTION_CASES
            VLOG_INFO("using ovn-nbctl daemon, ignoring %s option",
                      po->o->name);
            break;

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", nbrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            if (!str_to_uint(po->arg, 10, &timeout) || !timeout) {
                ctl_fatal("value %s on -t or --timeout is invalid", po->arg);
            }
            break;

        VLOG_OPTION_HANDLERS

        case OPT_LOCAL:
        default:
            if (po->arg) {
                svec_add_nocopy(&args,
                                xasprintf("--%s=%s", po->o->name, po->arg));
            } else {
                svec_add_nocopy(&args, xasprintf("--%s", po->o->name));
            }
            break;
        }
    }
    svec_add(&args, "--");
    for (int i = optind; i < argc; i++) {
        svec_add(&args, argv[i]);
    }

    ctl_timeout_setup(timeout);

    struct jsonrpc *client;
    int error = unixctl_client_create(socket_name, &client);
    if (error) {
        ctl_fatal("%s: could not connect to ovn-nb daemon (%s); "
                  "unset OVN_NB_DAEMON to avoid using daemon",
                  socket_name, ovs_strerror(error));
    }

    char *cmd_result;
    char *cmd_error;
    error = unixctl_client_transact(client, "run",
                                    args.n, args.names,
                                    &cmd_result, &cmd_error);
    if (error) {
        ctl_fatal("%s: transaction error (%s)",
                  socket_name, ovs_strerror(error));
    }
    svec_destroy(&args);

    int exit_status;
    if (cmd_error) {
        exit_status = EXIT_FAILURE;
        fprintf(stderr, "%s: %s", program_name, cmd_error);
    } else {
        exit_status = EXIT_SUCCESS;
        fputs(cmd_result, stdout);
    }
    free(cmd_result);
    free(cmd_error);
    jsonrpc_close(client);
    exit(exit_status);
}
