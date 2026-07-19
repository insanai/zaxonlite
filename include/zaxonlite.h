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
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void zaxonlite;

/* Library version string, e.g. "0.1.0". */
const char *zaxonlite_version(void);

/* Opens (or creates) a node data directory. */
int zaxonlite_open(const char *directory, zaxonlite **out_handle);

/* Closes the node and releases the handle. */
void zaxonlite_close(zaxonlite *handle);

/* Executes one replicated write transaction (any SQL statement batch). */
int zaxonlite_exec(zaxonlite *handle, const char *sql, int64_t *changes_out);

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
