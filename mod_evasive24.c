// vim:ts=4:shiftwidth=4:et
/*
   mod_evasive for Apache 2
   Copyright (c) by Jonathan A. Zdziarski

   LICENSE

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>  // getpid(2)

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "http_request.h"

/* BEGIN DoS Evasive Maneuvers Definitions */

AP_DECLARE_MODULE(evasive);

#define MAILER  "/bin/mail %s"

#define DEFAULT_HASH_TBL_SIZE   3079UL  // Default hash table size
#define DEFAULT_PAGE_COUNT      2       // Default maximum page hit count per interval
#define DEFAULT_SITE_COUNT      50      // Default maximum site hit count per interval
#define DEFAULT_PAGE_INTERVAL   1       // Default 1 Second page interval
#define DEFAULT_SITE_INTERVAL   1       // Default 1 Second site interval
#define DEFAULT_BLOCKING_PERIOD 10      // Default for Detected IPs; blocked for 10 seconds
#define DEFAULT_LOG_DIR         "/tmp"  // Default temp directory
#define DEFAULT_HTTP_REPLY      HTTP_FORBIDDEN // Default HTTP Reply code (403)

/* END DoS Evasive Maneuvers Definitions */

/* BEGIN NTT (Named Timestamp Tree) Headers */

enum { ntt_num_primes = 28 };

/* ntt root tree */
struct ntt {
    size_t size;
    size_t items;
    struct ntt_node **tbl;
};

/* ntt node (entry in the ntt root tree) */
struct ntt_node {
    char *key;
    apr_time_t timestamp;
    size_t count;
    struct ntt_node *next;
};

/* ntt cursor */
struct ntt_c {
    size_t iter_index;
    struct ntt_node *iter_next;
};

static struct ntt *ntt_create(size_t size);
static int ntt_destroy(struct ntt *ntt);
static struct ntt_node *ntt_find(struct ntt *ntt, const char *key);
static struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, apr_time_t timestamp);
static int ntt_delete(struct ntt *ntt, const char *key);
static size_t ntt_hashcode(const struct ntt *ntt, const char *key);
static struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c);
static struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c);

/* END NTT (Named Timestamp Tree) Headers */


/* BEGIN DoS Evasive Maneuvers Globals */

struct pcre_node {
    pcre2_code *re;
    pcre2_match_data *match_data;
};

struct pcre_vector {
    struct pcre_node *data;
    size_t size;
};

struct ip_node {
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip;

    union {
        uint32_t v4;
        struct in6_addr v6;
    } mask;

    char family; // AF_INET or AF_INET6
};

struct ip_vector {
    struct ip_node *data;
    size_t size;
};

typedef struct {
    int enabled;
    struct ntt *hit_list;   // Our dynamic hash table
    size_t hash_table_size;
    struct pcre_vector uri_whitelist;
    struct pcre_vector uri_targetlist;
    struct pcre_vector uri_blocklist;
    struct ip_vector ip_whitelist;
    unsigned int page_count;
    int page_interval;
    unsigned int site_count;
    int site_interval;
    int blocking_period;
    char *email_notify;
    char *log_dir;
    char *system_command;
    int http_reply;
} evasive_config;

static int is_whitelisted(const apr_sockaddr_t *client, const evasive_config *cfg);

static int is_uri_whitelisted(const char *uri, const evasive_config *cfg);
static int is_uri_targeted(const char *uri, const evasive_config *cfg);
static int is_uri_blocklisted(const char *uri, const evasive_config *cfg);

/* END DoS Evasive Maneuvers Globals */

static void * ev_reallocarray(void *ptr, size_t nmemb, size_t size)
{
        if (size && nmemb > SIZE_MAX / size) {
                errno = ENOMEM;
                return NULL;
        }

        return realloc(ptr, nmemb * size);
}


static void * create_dir_conf(apr_pool_t *p, __attribute__((unused)) char *context)
{
    /* Create a new hit list for this listener */
    evasive_config *cfg = apr_palloc(p, sizeof(evasive_config));
    if (!cfg) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate configuration");
        return NULL;
    }

    *cfg = (evasive_config) {
        .enabled = 0,
        .hit_list = ntt_create(DEFAULT_HASH_TBL_SIZE),
        .hash_table_size = DEFAULT_HASH_TBL_SIZE,
        .uri_whitelist = (struct pcre_vector) { .data = NULL, .size = 0 },
        .uri_targetlist = (struct pcre_vector) { .data = NULL, .size = 0 },
        .uri_blocklist = (struct pcre_vector) { .data = NULL, .size = 0 },
        .ip_whitelist = (struct ip_vector) { .data = NULL, .size = 0 },
        .page_count = DEFAULT_PAGE_COUNT,
        .page_interval = DEFAULT_PAGE_INTERVAL,
        .site_count = DEFAULT_SITE_COUNT,
        .site_interval = DEFAULT_SITE_INTERVAL,
        .blocking_period = DEFAULT_BLOCKING_PERIOD,
        .email_notify = NULL,
        .log_dir = NULL,
        .system_command = NULL,
        .http_reply = DEFAULT_HTTP_REPLY,
    };
    if (!cfg->hit_list)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate hashtable");

    return cfg;
}

static int parse_wildcard(const char *ip, struct in_addr *addr, uint32_t *mask)
{
    char *dip;
    const char *oct;
    char *safeptr;
    int i = 0;
    uint32_t ip_byte = 0, mask_byte = 0;
    unsigned long val;
    char *endptr;

    dip = strdup(ip);
    if (!dip)
        goto err;

    oct = strtok_r(dip, ".", &safeptr);
    while(oct != NULL && i < 4) {
        if (oct[0] == '\0' || strlen(oct) > 3)
            goto err;

        if (oct[0] == '*' && oct[1] == '\0') {
            ip_byte += 0;
            mask_byte += 0;
        } else {
            errno = 0;
            val = strtoul(oct, &endptr, 10);
            if (errno || *endptr != '\0' || val > 255)
                goto err;

            ip_byte += val;
            mask_byte += 255;
        }

        i++;
        if (i < 4) {
            ip_byte <<= 8;
            mask_byte <<= 8;
        }

        oct = strtok_r(NULL, ".", &safeptr);
    }

    if (oct || i != 4)
        goto err;

    free(dip);

    addr->s_addr = htobe32(ip_byte);
    *mask = htobe32(mask_byte);
    return 1;
err:
    free(dip);
    return -1;
}

static void ipv6_cidr_bits_to_mask(unsigned long cidr_bits, struct in6_addr *mask)
{
    for (unsigned i = 0; i < 4; i++) {
        if (cidr_bits == 0) {
            mask->s6_addr32[i] = 0;
        } else if (cidr_bits >= 32) {
            mask->s6_addr32[i] = ~UINT32_C(0);
        } else {
            mask->s6_addr32[i] = htobe32(~((UINT32_C(1) << (32 - cidr_bits)) - 1));
        }

        if (cidr_bits >= 32)
            cidr_bits -= 32;
        else
            cidr_bits = 0;
    }
}

static void ipv6_apply_mask(struct in6_addr *restrict addr, const struct in6_addr *restrict mask)
{
    for (unsigned i = 0; i < 4; i++)
        addr->s6_addr32[i] &= mask->s6_addr32[i];
}

static const char *whitelist_ip(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *ip)
{
    evasive_config *cfg = (evasive_config *) dconfig;
    struct in_addr ipv4;
    struct in6_addr ipv6, maskv6;
    struct ip_node *newdata;
    const char *ip_parse = ip;
    char *ip_copy = NULL;
    const char *cidr_split;
    char *endptr;
    char family;
    char wildcard = 0;
    unsigned long mask_bits;
    uint32_t maskv4;
    int rc;

    cidr_split = strchr(ip, '/');
    if (cidr_split) {
        ip_copy = strndup(ip, cidr_split - ip);
        if (!ip_copy) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "DOSWhitelist: OOM");
            return NULL;
        }

        ip_parse = ip_copy;
    }

    if (strchr(ip_parse, '*') != NULL) {
        family = AF_INET;
        wildcard = 1;
        rc = parse_wildcard(ip_parse, &ipv4, &maskv4);
    } else if (strchr(ip_parse, ':') != NULL) {
        family = AF_INET6;
        rc = inet_pton(AF_INET6, ip_parse, &ipv6);
    } else {
        family = AF_INET;
        rc = inet_pton(AF_INET, ip_parse, &ipv4);
    }

    if (cidr_split)
        free(ip_copy);

    if (rc != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "DOSWhitelist: Invalid IP address '%s'", ip);
        return NULL;
    }

    if (cidr_split) {
        errno = 0;
        mask_bits = strtoul(cidr_split + 1, &endptr, 10);
        if (errno || *endptr != '\0' || mask_bits == 0 || mask_bits > (family == AF_INET ? 32 : 128)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "DOSWhitelist: Invalid IP CIDR range '%s'", ip);
            return NULL;
        }
    } else {
        mask_bits = family == AF_INET ? 32 : 128;
    }

    if (!wildcard) {
        if (family == AF_INET) {
            maskv4 = ~((UINT32_C(1) << (32 - mask_bits)) - 1);
            maskv4 = htobe32(maskv4);
            ipv4.s_addr &= maskv4;
        } else {
            ipv6_cidr_bits_to_mask(mask_bits, &maskv6);
            ipv6_apply_mask(&ipv6, &maskv6);
        }
    }

    newdata = ev_reallocarray(cfg->ip_whitelist.data, cfg->ip_whitelist.size + 1, sizeof(*cfg->ip_whitelist.data));
    if (!newdata) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "DOSWhitelist: OOM");
        return NULL;
    }
    cfg->ip_whitelist.data = newdata;

    if (family == AF_INET) {
        cfg->ip_whitelist.data[cfg->ip_whitelist.size++] = (struct ip_node) {
            .family = AF_INET,
            .ip.v4 = ipv4,
            .mask.v4 = maskv4,
        };
    } else {
        cfg->ip_whitelist.data[cfg->ip_whitelist.size++] = (struct ip_node) {
            .family = AF_INET6,
            .ip.v6 = ipv6,
            .mask.v6 = maskv6,
        };
    }

    return NULL;
}

static const char *pcre_vector_push(struct pcre_vector *vec, const char *uri_re) {
    struct pcre_node *newdata;
    pcre2_code *re;
    int errornumber;
    PCRE2_SIZE erroroffset;
    PCRE2_SPTR pattern;
    pcre2_match_data *match_data;

    pattern = (PCRE2_SPTR) uri_re;

    re = pcre2_compile(
            pattern,               /* the pattern */
            PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
            PCRE2_NO_AUTO_CAPTURE, /* Disable numbered capturing parentheses */
            &errornumber,          /* for error number */
            &erroroffset,          /* for error offset */
            NULL);                 /* use default compile context */

    /* Compilation failed: print the error message and exit. */

    if (!re) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "PCRE2 compilation of regex '%s' failed at offset %lu: %s\n",
                     uri_re, (unsigned long) erroroffset, buffer);
        return NULL;
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (!match_data) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate PCRE2 match data");
        pcre2_code_free(re);
        return NULL;
    }

    newdata = ev_reallocarray(vec->data, vec->size + 1, sizeof(*(vec->data)));
    if (!newdata) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate array for URI list");
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        return NULL;
    }
    vec->data = newdata;

    vec->data[vec->size++] = (struct pcre_node) {
        .re = re,
        .match_data = match_data,
    };

    return NULL;
}

static const char *whitelist_uri(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *uri_re)
{
    evasive_config *cfg = (evasive_config *) dconfig;

    return pcre_vector_push(&cfg->uri_whitelist, uri_re);
}

static const char *target_uri(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *uri_re)
{
    evasive_config *cfg = (evasive_config *) dconfig;

    return pcre_vector_push(&cfg->uri_targetlist, uri_re);
}

static const char *blocklist_uri(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *uri_re)
{
    evasive_config *cfg = (evasive_config *) dconfig;

    return pcre_vector_push(&cfg->uri_blocklist, uri_re);
}

static void pcre_vector_destroy(struct pcre_vector *vec)
{
    for (size_t i = 0; i < vec->size; i++) {
        struct pcre_node *node = &vec->data[i];
        pcre2_code_free(node->re);
        pcre2_match_data_free(node->match_data);
    }

    free(vec->data);
}

static int access_checker(request_rec *r)
{
    evasive_config *cfg = (evasive_config *) ap_get_module_config(r->per_dir_config, &evasive_module);

    int ret = OK;
    const char *log_reason = NULL;

    /* BEGIN DoS Evasive Maneuvers Code */

    if (cfg->enabled && r->prev == NULL && r->main == NULL && cfg->hit_list != NULL) {
        char hash_key[2048];
        struct ntt_node *ip_node, *n;
        apr_time_t t = r->request_time / 1000 / 1000; /* convert us to s */

        /* Check whitelist */
        if (is_whitelisted(r->useragent_addr, cfg))
            return OK;

        /* First see if the IP itself is on "hold" */
        ip_node = ntt_find(cfg->hit_list, r->useragent_ip);

        if (ip_node != NULL && t-ip_node->timestamp<cfg->blocking_period) {

            /* If the IP is on "hold", make it wait longer in 403 land */
            ret = cfg->http_reply;
            ip_node->timestamp = t;

            /* Not on hold, check hit stats */
        } else {

            /* Check whitelisted uris */
            if (is_uri_whitelisted(r->uri, cfg))
                return OK;

            /* If a Targetlist is defined, and the URI is not one of the targets, then do not perform DoS detection */
            if (cfg->uri_targetlist.size && !is_uri_targeted(r->uri, cfg))
                return OK;

            /* Check blocklisted URIs */
            if (is_uri_blocklisted(r->uri, cfg)) {
                if (!ip_node || t-ip_node->timestamp>=cfg->blocking_period)
                    log_reason = "URI blocklist";
                ret = cfg->http_reply;
                ntt_insert(cfg->hit_list, r->useragent_ip, t);
            } else {
                /* Has URI been hit too much? */
                snprintf(hash_key, sizeof(hash_key), "%s_%s", r->useragent_ip, r->uri);

                n = ntt_find(cfg->hit_list, hash_key);
                if (n != NULL) {

                    /* If URI is being hit too much, add to "hold" list and 403 */
                    if (t-n->timestamp<cfg->page_interval && n->count>=cfg->page_count) {
                        if (!ip_node || t-ip_node->timestamp>=cfg->blocking_period)
                            log_reason = "URI DOS";
                        ret = cfg->http_reply;
                        ntt_insert(cfg->hit_list, r->useragent_ip, t);
                    } else {

                        /* Reset our hit count list as necessary */
                        if (t-n->timestamp>=cfg->page_interval) {
                            n->count=0;
                        }
                    }
                    n->timestamp = t;
                    n->count++;
                } else {
                    ntt_insert(cfg->hit_list, hash_key, t);
                }

                /* Has site been hit too much? */
                snprintf(hash_key, sizeof(hash_key), "%s_SITE", r->useragent_ip);
                n = ntt_find(cfg->hit_list, hash_key);
                if (n != NULL) {

                    /* If site is being hit too much, add to "hold" list and 403 */
                    if (t-n->timestamp<cfg->site_interval && n->count>=cfg->site_count) {
                        if (!ip_node || t-ip_node->timestamp>=cfg->blocking_period)
                            log_reason = "site DOS";
                        ret = cfg->http_reply;
                        ntt_insert(cfg->hit_list, r->useragent_ip, t);
                    } else {

                        /* Reset our hit count list as necessary */
                        if (t-n->timestamp>=cfg->site_interval) {
                            n->count=0;
                        }
                    }
                    n->timestamp = t;
                    n->count++;
                } else {
                    ntt_insert(cfg->hit_list, hash_key, t);
                }
            }
        }

        /* Perform email notification and system functions */
        if (ret == cfg->http_reply) {
            char filename[1024];
            struct stat s;
            FILE *file;

            snprintf(filename, sizeof(filename), "%s/dos-%s", cfg->log_dir != NULL ? cfg->log_dir : DEFAULT_LOG_DIR, r->useragent_ip);
            if (stat(filename, &s)) {
                file = fopen(filename, "w");
                if (file != NULL) {
                    fprintf(file, "%ld\n", getpid());
                    fclose(file);

                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Blacklisting address %s: possible DoS attack.", r->useragent_ip);
                    if (cfg->email_notify != NULL) {
                        snprintf(filename, sizeof(filename), MAILER, cfg->email_notify);
                        file = popen(filename, "w");
                        if (file != NULL) {
                            fprintf(file, "To: %s\n", cfg->email_notify);
                            fprintf(file, "Subject: HTTP BLACKLIST %s\n\n", r->useragent_ip);
                            fprintf(file, "mod_evasive HTTP Blacklisted %s\n", r->useragent_ip);
                            pclose(file);
                        }
                    }

                    if (cfg->system_command != NULL) {
                        snprintf(filename, sizeof(filename), cfg->system_command, r->useragent_ip);
                        system(filename);
                    }

                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Couldn't open logfile %s: %s",filename, strerror(errno));
                }

            } /* if (temp file does not exist) */

        } /* if (ret == cfg->http_reply) */

    } /* if (r->prev == NULL && r->main == NULL && cfg->hit_list != NULL) */

    /* END DoS Evasive Maneuvers Code */

    if (log_reason && ret == cfg->http_reply
            && (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                "[host %s] [resource \"%s\"] [reason %s] client denied by server configuration",
                r->hostname, r->filename, log_reason);
    }

    return ret;
}

static int is_whitelisted(const apr_sockaddr_t *client, const evasive_config *cfg) {
    switch (client->family) {
    case AF_INET:
    case AF_INET6:
        break;
    default:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Invalid client family 0x%x", client->family);
        return 0;
    }

    for (size_t i = 0; i < cfg->ip_whitelist.size; i++) {
        const struct ip_node *node = &cfg->ip_whitelist.data[i];
        int rc;

        if (node->family != client->family)
            continue;

        if (client->family == AF_INET) {
            struct in_addr addrv4 = client->sa.sin.sin_addr;
            addrv4.s_addr &= node->mask.v4;
            rc = memcmp(&node->ip.v4, &addrv4, sizeof(node->ip.v4));
        } else {
            struct in6_addr addrv6 = client->sa.sin6.sin6_addr;
            ipv6_apply_mask(&addrv6, &node->mask.v6);
            rc = memcmp(&node->ip.v6, &addrv6, sizeof(node->ip.v6));
        }

        if (rc == 0)
            return 1;
    }

    /* No match */
    return 0;
}

static int pcre_vector_match(const char *uri, const struct pcre_vector *vec) {
    int rc;

    PCRE2_SPTR subject;
    size_t subject_length;

    subject = (PCRE2_SPTR) uri;
    subject_length = strlen((const char *)subject);

    for (size_t i = 0; i < vec->size; i++) {
        const struct pcre_node *node = &vec->data[i];

        rc = pcre2_match(
                node->re,             /* the compiled pattern */
                subject,              /* the subject string */
                subject_length,       /* the length of the subject */
                0,                    /* start at offset 0 in the subject */
                0,                    /* default options */
                node->match_data,     /* block for storing the result */
                NULL);                /* use default match context */

        if (rc >= 0) {
            // match
            return 1;
        }
    }

    // no match
    return 0;
}

static int is_uri_whitelisted(const char *uri, const evasive_config *cfg) {
    return pcre_vector_match(uri, &cfg->uri_whitelist);
}

static int is_uri_targeted(const char *uri, const evasive_config *cfg) {
    return pcre_vector_match(uri, &cfg->uri_targetlist);
}

static int is_uri_blocklisted(const char *uri, const evasive_config *cfg) {
    return pcre_vector_match(uri, &cfg->uri_blocklist);
}

static apr_status_t destroy_config(void *dconfig) {
    evasive_config *cfg = (evasive_config *) dconfig;
    if (cfg != NULL) {
        ntt_destroy(cfg->hit_list);
        pcre_vector_destroy(&cfg->uri_whitelist);
        pcre_vector_destroy(&cfg->uri_targetlist);
        pcre_vector_destroy(&cfg->uri_blocklist);
        free(cfg->ip_whitelist.data);
        free(cfg->email_notify);
        free(cfg->log_dir);
        free(cfg->system_command);
        /* cfg is pool allocated */
   }
   return APR_SUCCESS;
}


/* BEGIN NTT (Named Timestamp Tree) Functions */

static const size_t ntt_prime_list[ntt_num_primes] =
{
    53UL,         97UL,         193UL,       389UL,       769UL,
    1543UL,       3079UL,       6151UL,      12289UL,     24593UL,
    49157UL,      98317UL,      196613UL,    393241UL,    786433UL,
    1572869UL,    3145739UL,    6291469UL,   12582917UL,  25165843UL,
    50331653UL,   100663319UL,  201326611UL, 402653189UL, 805306457UL,
    1610612741UL, 3221225473UL, 4294967291UL
};

/* Get the next prime bigger or equal than the given number */

static size_t ntt_prime_get_next(size_t n) {
    for (size_t i = 0; i < ntt_num_primes; i++) {
        if (ntt_prime_list[i] >= n)
            return ntt_prime_list[i];
    }

    return ntt_prime_list[ntt_num_primes - 1];
}


/* Find the numeric position in the hash table based on key and modulus */

static size_t ntt_hashcode(const struct ntt *ntt, const char *key) {
    size_t val = 0;
    for (; *key; ++key) val = 5 * val + *key;
    return(val % ntt->size);
}

/* Creates a single node in the tree */

static struct ntt_node *ntt_node_create(const char *key, apr_time_t timestamp) {
    char *node_key;
    struct ntt_node* node;

    node = (struct ntt_node *) malloc(sizeof(struct ntt_node));
    if (node == NULL) {
        return NULL;
    }
    if ((node_key = strdup(key)) == NULL) {
        free(node);
        return NULL;
    }
    *node = (struct ntt_node) {
        .key = node_key,
        .timestamp = timestamp,
        .count = 0,
        .next = NULL,
    };
    return(node);
}

/* Tree initializer */

static struct ntt *ntt_create(size_t size) {
    struct ntt *ntt = (struct ntt *) malloc(sizeof(struct ntt));

    if (ntt == NULL)
        return NULL;
    ntt->size  = ntt_prime_get_next(size);
    ntt->items = 0;
    ntt->tbl   = (struct ntt_node **) calloc(ntt->size, sizeof(struct ntt_node *));
    if (ntt->tbl == NULL) {
        free(ntt);
        return NULL;
    }
    return(ntt);
}

/* Find an object in the tree */

static struct ntt_node *ntt_find(struct ntt *ntt, const char *key) {
    size_t hash_code;
    struct ntt_node *node;

    if (ntt == NULL) return NULL;

    hash_code = ntt_hashcode(ntt, key);
    node = ntt->tbl[hash_code];

    while (node) {
        if (!strcmp(key, node->key)) {
            return(node);
        }
        node = node->next;
    }
    return((struct ntt_node *)NULL);
}

/* Whether a node is outdated */

static int ntt_node_is_outdated(const struct ntt_node *node, apr_time_t timestamp) {
    return timestamp - node->timestamp >= 6 * 60 * 60; /* 6 hours */
}

/* Copy a node into the tree; only used during tree growth */

static void ntt_grow_copy(struct ntt *ntt, struct ntt_node *node, apr_time_t timestamp) {
    size_t hash_code;
    struct ntt_node **curr;

    /* Ignore outdated entries */
    if (ntt_node_is_outdated(node, timestamp)) {
        free(node->key);
        free(node);
        return;
    }

    hash_code = ntt_hashcode(ntt, node->key);
    curr = &ntt->tbl[hash_code];

    while (*curr) {
        /* No need to compare keys, since the original tree should not have duplicates */
        curr = &(*curr)->next;
    }

    node->next = NULL;
    *curr = node;
    ntt->items++;
}

/* Grow the tree */

static int ntt_grow(struct ntt *ntt, apr_time_t timestamp) {
    struct ntt tmp_ntt;
    struct ntt_node **new_tbl;
    size_t new_size;

    new_size = ntt_prime_get_next(ntt->size + 1);
    if (new_size == ntt->size) {
        errno = EOVERFLOW;
        return -1;
    }

    new_tbl = calloc(new_size, sizeof(struct ntt_node *));
    if (!new_tbl)
        return -1;

    tmp_ntt = (struct ntt) {
        .size = new_size,
        .items = 0,
        .tbl = new_tbl,
    };

    for (size_t i = 0; i < ntt->size; i++) {
        struct ntt_node *node;

        node = ntt->tbl[i];
        while (node) {
            struct ntt_node *next;

            next = node->next;
            ntt_grow_copy(&tmp_ntt, node, timestamp);
            node = next;
        }
    }

    free(ntt->tbl);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, "Resized hash table from %zu to %zu",
                 ntt->size, new_size);

    *ntt = tmp_ntt;

    return 0;
}

/* Insert a node into the tree */

static struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, apr_time_t timestamp) {
    size_t hash_code;
    struct ntt_node *parent;
    struct ntt_node *node;
    struct ntt_node *new_node = NULL;

    if (ntt == NULL || ntt->items == SIZE_MAX) return NULL;

    /* Grow on 75% utilization */
    if (((ntt->size * 3) / 4) < ntt->items) {
        if (ntt_grow(ntt, timestamp) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to increase hashtable of size %zu and %zu entries: %s",
                         ntt->size, ntt->items, strerror(errno));
            return NULL;
        }
    }

    hash_code = ntt_hashcode(ntt, key);
    parent  = NULL;
    node    = ntt->tbl[hash_code];

    while (node != NULL) {
        if (strcmp(key, node->key) == 0) {
            new_node = node;
            node = NULL;
            break;
        }

        /* Delete outdated entries */
        if (ntt_node_is_outdated(node, timestamp)) {
            struct ntt_node *next = node->next;

            if (parent)
                parent->next = next;
            else
                ntt->tbl[hash_code] = next;

            free(node->key);
            free(node);
            ntt->items--;
            node = next;
            continue;
        }

        parent = node;
        node = node->next;
    }

    if (new_node != NULL) {
        new_node->timestamp = timestamp;
        new_node->count = 0;
        return new_node;
    }

    /* Create a new node */
    new_node = ntt_node_create(key, timestamp);

    ntt->items++;

    /* Insert */
    if (parent) {  /* Existing parent */
        parent->next = new_node;
        return new_node;  /* Return the locked node */
    }

    /* No existing parent; add directly to hash table */
    ntt->tbl[hash_code] = new_node;
    return new_node;
}

/* Tree destructor */

static int ntt_destroy(struct ntt *ntt) {
    struct ntt_node *node, *next;
    struct ntt_c c;

    if (ntt == NULL) return -1;

    node = c_ntt_first(ntt, &c);
    while(node != NULL) {
        next = c_ntt_next(ntt, &c);
        ntt_delete(ntt, node->key);
        node = next;
    }

    free(ntt->tbl);
    free(ntt);

    return 0;
}

/* Delete a single node in the tree */

static int ntt_delete(struct ntt *ntt, const char *key) {
    size_t hash_code;
    struct ntt_node *parent = NULL;
    struct ntt_node *node;
    struct ntt_node *del_node = NULL;

    if (ntt == NULL) return -1;

    hash_code = ntt_hashcode(ntt, key);
    node        = ntt->tbl[hash_code];

    while (node != NULL) {
        if (strcmp(key, node->key) == 0) {
            del_node = node;
            node = NULL;
        }

        if (del_node == NULL) {
            parent = node;
            node = node->next;
        }
    }

    if (del_node != NULL) {

        if (parent) {
            parent->next = del_node->next;
        } else {
            ntt->tbl[hash_code] = del_node->next;
        }

        free(del_node->key);
        free(del_node);
        ntt->items--;

        return 0;
    }

    return -5;
}

/* Point cursor to first item in tree */

static struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c) {

    c->iter_index = 0;
    c->iter_next = (struct ntt_node *)NULL;
    return(c_ntt_next(ntt, c));
}

/* Point cursor to next iteration in tree */

static struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c) {
    size_t index;
    struct ntt_node *node = c->iter_next;

    if (ntt == NULL) return NULL;

    if (node) {
        c->iter_next = node->next;
        return (node);
    }

    while (c->iter_index < ntt->size) {
        index = c->iter_index++;

        if (ntt->tbl[index]) {
            c->iter_next = ntt->tbl[index]->next;
            return(ntt->tbl[index]);
        }
    }

    return((struct ntt_node *)NULL);
}

/* END NTT (Named Pointer Tree) Functions */


/* BEGIN Configuration Functions */

static const char *
get_enabled(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;

    if (strcmp("true", value) == 0) {
        cfg->enabled = 1;
    } else if (strcmp("false", value) == 0) {
        cfg->enabled = 0;
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSEnabled value '%s', mod_evasive disabled.", value);
        cfg->enabled = 0;
    }

    return NULL;
}

static const char *
get_hash_tbl_size(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSHashTableSize value '%s', using default %lu.",
                     value, DEFAULT_HASH_TBL_SIZE);
        cfg->hash_table_size = DEFAULT_HASH_TBL_SIZE;
    } else {
        cfg->hash_table_size = n;

        ntt_destroy(cfg->hit_list);
        cfg->hit_list = ntt_create(cfg->hash_table_size);
        if (!cfg->hit_list)
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "Failed to allocate hashtable");
    }

    return NULL;
}

static const char *
get_page_count(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0 || n > UINT_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSPageCount value '%s', using default %d.",
                     value, DEFAULT_PAGE_COUNT);
        cfg->page_count = DEFAULT_PAGE_COUNT;
    } else {
        cfg->page_count = n;
    }

    return NULL;
}

static const char *
get_site_count(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0 || n > UINT_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSSiteCount value '%s', using default %d.",
                     value, DEFAULT_SITE_COUNT);
        cfg->site_count = DEFAULT_SITE_COUNT;
    } else {
        cfg->site_count = n;
    }

    return NULL;
}

static const char *
get_page_interval(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0 || n > INT_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSPageInterval value '%s', using default %d.",
                     value, DEFAULT_PAGE_INTERVAL);
        cfg->page_interval = DEFAULT_PAGE_INTERVAL;
    } else {
        cfg->page_interval = n;
    }

    return NULL;
}

static const char *
get_site_interval(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0 || n > INT_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSSiteInterval value '%s', using default %d.",
                     value, DEFAULT_SITE_INTERVAL);
        cfg->site_interval = DEFAULT_SITE_INTERVAL;
    } else {
        cfg->site_interval = n;
    }

    return NULL;
}

static const char *
get_blocking_period(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || n <= 0 || n > INT_MAX) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSBlockingPeriod value '%s', using default %d.",
                     value, DEFAULT_BLOCKING_PERIOD);
        cfg->blocking_period = DEFAULT_BLOCKING_PERIOD;
    } else {
        cfg->blocking_period = n;
    }

    return NULL;
}

static const char *
get_log_dir(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    if (value != NULL && value[0] != 0) {
        if (cfg->log_dir != NULL)
            free(cfg->log_dir);
        cfg->log_dir = strdup(value);
    }

    return NULL;
}

static const char *
get_email_notify(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    if (value != NULL && value[0] != 0) {
        if (cfg->email_notify != NULL)
            free(cfg->email_notify);
        cfg->email_notify = strdup(value);
    }

    return NULL;
}

static const char *
get_system_command(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    if (value != NULL && value[0] != 0) {
        if (cfg->system_command != NULL)
            free(cfg->system_command);
        cfg->system_command = strdup(value);
    }

    return NULL;
}

static const char *
get_http_reply(__attribute__((unused)) cmd_parms *cmd, void *dconfig, const char *value) {
    evasive_config *cfg = (evasive_config *) dconfig;
    char *endptr;
    long n;

    errno = 0;
    n = strtol(value, &endptr, 0);
    if (errno || *endptr != '\0' || ((n < 99 || n > 599) && n != OK && n != DECLINED)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, "Invalid DOSHTTPStatus value '%s', using default %d.",
                     value, HTTP_FORBIDDEN);
        cfg->http_reply = HTTP_FORBIDDEN;
    } else {
        cfg->http_reply = n;
    }

    return NULL;
}

/* END Configuration Functions */

static const command_rec access_cmds[] =
{
    AP_INIT_TAKE1("DOSEnabled", get_enabled, NULL, RSRC_CONF,
            "Enable mod_evasive (either globally or in the virtualhost where it is specified)"),

    AP_INIT_TAKE1("DOSHashTableSize", get_hash_tbl_size, NULL, RSRC_CONF,
            "Set size of hash table"),

    AP_INIT_TAKE1("DOSPageCount", get_page_count, NULL, RSRC_CONF,
            "Set maximum page hit count per interval"),

    AP_INIT_TAKE1("DOSSiteCount", get_site_count, NULL, RSRC_CONF,
            "Set maximum site hit count per interval"),

    AP_INIT_TAKE1("DOSPageInterval", get_page_interval, NULL, RSRC_CONF,
            "Set page interval"),

    AP_INIT_TAKE1("DOSSiteInterval", get_site_interval, NULL, RSRC_CONF,
            "Set site interval"),

    AP_INIT_TAKE1("DOSBlockingPeriod", get_blocking_period, NULL, RSRC_CONF,
            "Set blocking period for detected DoS IPs"),

    AP_INIT_TAKE1("DOSEmailNotify", get_email_notify, NULL, RSRC_CONF,
            "Set email notification"),

    AP_INIT_TAKE1("DOSLogDir", get_log_dir, NULL, RSRC_CONF,
            "Set log dir"),

    AP_INIT_TAKE1("DOSSystemCommand", get_system_command, NULL, RSRC_CONF,
            "Set system command on DoS"),

    AP_INIT_ITERATE("DOSWhitelist", whitelist_ip, NULL, RSRC_CONF,
            "IP-addresses wildcards to whitelist"),

    AP_INIT_ITERATE("DOSWhitelistUri", whitelist_uri, NULL, RSRC_CONF,
            "Files/paths regexes to whitelist"),

    AP_INIT_ITERATE("DOSTargetlistUri", target_uri, NULL, RSRC_CONF,
            "Files/paths regexes to target"),

    AP_INIT_ITERATE("DOSBlocklistUri", blocklist_uri, NULL, RSRC_CONF,
            "Files/paths regexes to blocklist"),

    AP_INIT_ITERATE("DOSHTTPStatus", get_http_reply, NULL, RSRC_CONF,
            "HTTP reply code"),

    { NULL }
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_FIRST-5);
    apr_pool_cleanup_register(p, NULL, apr_pool_cleanup_null, destroy_config);
};

module AP_MODULE_DECLARE_DATA evasive_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_conf,
    NULL,
    NULL,
    NULL,
    access_cmds,
    register_hooks,
    AP_MODULE_FLAG_NONE
};
