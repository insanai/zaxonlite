/*
 * zaxonlite: an embeddable SQLite service replicated by Multi-Paxos.
 *
 * One handle owns one node data directory (journal, payload store,
 * snapshots, and the materialized SQLite image). Handles are independent;
 * use each handle from one thread at a time, or under your own lock.
 *
 * Return codes:
 *   0  ok
 *   1  SQL or session error (see zaxonlite_last_error)
 *   2  misuse (null argument, write statement on the read path)
 *   3  integrity failure
 *   4  unavailable (directory locked, corrupt state, or I/O failure)
 */

#ifndef ZAXONLITE_H
#define ZAXONLITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void zaxonlite;
typedef void zaxonlite_transaction;
typedef void zaxonlite_cluster;

typedef enum zaxonlite_node_role {
    ZAXONLITE_DATA_VOTER = 0,
    ZAXONLITE_WITNESS = 1,
    ZAXONLITE_STANDBY = 2,
    ZAXONLITE_READ_REPLICA = 3,
    ZAXONLITE_GATEWAY = 4
} zaxonlite_node_role;

typedef struct zaxonlite_member {
    uint32_t id;
    const char *address;
    zaxonlite_node_role role;
} zaxonlite_member;

typedef struct zaxonlite_cluster_options {
    const char *directory;
    uint32_t node_id;
    const zaxonlite_member *members;
    size_t member_count;
    const char *cluster_id;
    const void *auth_secret;
    size_t auth_secret_length;
    uint64_t startup_timeout_ms;
} zaxonlite_cluster_options;

typedef enum zaxonlite_value_type {
    ZAXONLITE_NULL = 0,
    ZAXONLITE_INTEGER = 1,
    ZAXONLITE_REAL = 2,
    ZAXONLITE_TEXT = 3,
    ZAXONLITE_BLOB = 4
} zaxonlite_value_type;

/* TEXT and BLOB borrow `bytes` for the duration of the call. */
typedef struct zaxonlite_value {
    zaxonlite_value_type type;
    int64_t integer;
    double real;
    const void *bytes;
    size_t length;
} zaxonlite_value;

/* Library version string ("unreleased" until the release owner assigns it). */
const char *zaxonlite_version(void);

/* Opens (or creates) a node data directory. */
int zaxonlite_open(const char *directory, zaxonlite **out_handle);

/* Closes the node and releases the handle. */
void zaxonlite_close(zaxonlite *handle);

/*
 * Opens a transport-owning cluster member. The registry may contain any
 * number of learners; at most nine entries may be voting roles. Addresses
 * use host:port syntax and all pointed-to data is copied before return.
 */
int zaxonlite_cluster_open(const zaxonlite_cluster_options *options,
                           zaxonlite_cluster **out_handle);
void zaxonlite_cluster_close(zaxonlite_cluster *handle);
int zaxonlite_cluster_exec(zaxonlite_cluster *handle, const char *sql,
                           int64_t *changes_out);
int zaxonlite_cluster_query_json(zaxonlite_cluster *handle, const char *sql,
                                 char **json_out);
int zaxonlite_cluster_call_json(zaxonlite_cluster *handle,
                                const char *request_json,
                                bool require_leader, char **json_out);
const char *zaxonlite_cluster_last_error(zaxonlite_cluster *handle);

/* Executes one replicated write transaction (any SQL statement batch). */
int zaxonlite_exec(zaxonlite *handle, const char *sql, int64_t *changes_out);

/* Executes one prepared statement as a replicated transaction. */
int zaxonlite_exec_prepared(zaxonlite *handle, const char *sql,
                            const zaxonlite_value *values, size_t value_count,
                            int64_t *changes_out);

/*
 * Explicit transactions collect copied statements across calls, then execute
 * and replicate them atomically at commit. A transaction is single-use.
 */
int zaxonlite_transaction_begin(zaxonlite *handle,
                                zaxonlite_transaction **out_transaction);
int zaxonlite_transaction_exec(zaxonlite_transaction *transaction,
                               const char *sql,
                               const zaxonlite_value *values,
                               size_t value_count);
int zaxonlite_transaction_commit(zaxonlite_transaction *transaction,
                                 int64_t *changes_out);
void zaxonlite_transaction_close(zaxonlite_transaction *transaction);

/* Opens a replicated client session for idempotent retry. */
int zaxonlite_session_open(zaxonlite *handle, uint64_t *session_out);

/*
 * Executes `sequence` for `session` exactly once. Retrying the last
 * sequence sets *replayed_out and returns the recorded change count;
 * gaps and expired sequences fail with code 1 without executing SQL.
 */
int zaxonlite_exec_idempotent(zaxonlite *handle, uint64_t session,
                              uint64_t sequence, const char *sql,
                              int64_t *changes_out, bool *replayed_out);

/*
 * Runs a read-only query; on success *json_out receives one JSON object
 * {"columns":[...],"rows":[[...]]} to be released with zaxonlite_free.
 */
int zaxonlite_query_json(zaxonlite *handle, const char *sql, char **json_out);

int zaxonlite_query_prepared_json(zaxonlite *handle, const char *sql,
                                  const zaxonlite_value *values,
                                  size_t value_count, char **json_out);

/* Releases a buffer returned by zaxonlite_query_json. */
void zaxonlite_free(char *pointer);

/* Takes an online snapshot and seals the current journal epoch. */
int zaxonlite_snapshot(zaxonlite *handle);

/* Streams a consistent logical backup to `path`. */
int zaxonlite_backup(zaxonlite *handle, const char *path);

/* Verifies the image, descriptor chain, and payload availability. */
int zaxonlite_integrity_check(zaxonlite *handle);

/* Deletes sessions idle for more than `retain` recent session writes. */
int zaxonlite_expire_sessions(zaxonlite *handle, uint64_t retain,
                              int64_t *expired_out);

/* The most recent error message for this handle. */
const char *zaxonlite_last_error(zaxonlite *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZAXONLITE_H */
