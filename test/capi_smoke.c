/* C ABI smoke test: exercises every exported function against a scratch
 * directory passed as argv[1]. Exits non-zero on the first failure. */

#include "zaxonlite.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(name, condition)                                                \
    do {                                                                      \
        if (condition) {                                                      \
            printf("ok   %s\n", name);                                        \
        } else {                                                              \
            printf("FAIL %s\n", name);                                        \
            failures++;                                                       \
        }                                                                     \
    } while (0)

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: capi_smoke <data-dir>\n");
        return 2;
    }
    /* The pid alone is not unique across CI runs: fresh runners assign
     * near-identical pids and the cache preserves old data directories,
     * which the journal then faithfully replays. */
    char dir[1024];
    snprintf(dir, sizeof dir, "%s-%d-%ld", argv[1], (int)getpid(),
             (long)time(NULL));

    CHECK("version string", strlen(zaxonlite_version()) >= 5);

    zaxonlite *db = NULL;
    CHECK("open", zaxonlite_open(dir, &db) == 0 && db != NULL);
    if (db == NULL) return 1;

    /* A second open of the same directory must report unavailable. */
    zaxonlite *locked = NULL;
    CHECK("locking", zaxonlite_open(dir, &locked) == 4 && locked == NULL);

    int64_t changes = -1;
    CHECK("create table",
          zaxonlite_exec(db, "create table c(a integer primary key, b text)",
                         &changes) == 0);
    CHECK("insert",
          zaxonlite_exec(db, "insert into c(b) values ('x'), ('y')",
                         &changes) == 0 &&
              changes == 2);

    const char prepared_text[] = "prepared";
    zaxonlite_value prepared_values[] = {
        {.type = ZAXONLITE_TEXT,
         .bytes = prepared_text,
         .length = strlen(prepared_text)}};
    CHECK("prepared insert",
          zaxonlite_exec_prepared(db, "insert into c(b) values (?1)",
                                  prepared_values, 1, &changes) == 0 &&
              changes == 1);

    zaxonlite_transaction *transaction = NULL;
    CHECK("transaction begin",
          zaxonlite_transaction_begin(db, &transaction) == 0 &&
              transaction != NULL);
    zaxonlite_value tx_one[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "tx-one", .length = 6}};
    zaxonlite_value tx_two[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "tx-two", .length = 6}};
    CHECK("transaction first statement",
          zaxonlite_transaction_exec(transaction,
                                     "insert into c(b) values (?1)", tx_one,
                                     1) == 0);
    CHECK("transaction second statement",
          zaxonlite_transaction_exec(transaction,
                                     "insert into c(b) values (?1)", tx_two,
                                     1) == 0);
    CHECK("transaction commit",
          zaxonlite_transaction_commit(transaction, &changes) == 0 &&
              changes == 2);
    zaxonlite_transaction_close(transaction);

    zaxonlite_value query_value[] = {
        {.type = ZAXONLITE_TEXT, .bytes = "prepared", .length = 8}};
    char *prepared_json = NULL;
    CHECK("prepared query",
          zaxonlite_query_prepared_json(
              db, "select count(*) from c where b = ?1", query_value, 1,
              &prepared_json) == 0 &&
              prepared_json != NULL && strstr(prepared_json, "[[\"1\"]]") != NULL);
    zaxonlite_free(prepared_json);
    CHECK("sql error surfaces",
          zaxonlite_exec(db, "insert into missing values (1)", &changes) == 1 &&
              strstr(zaxonlite_last_error(db), "no such table") != NULL);

    char *json = NULL;
    CHECK("query json",
          zaxonlite_query_json(db, "select * from c order by a", &json) == 0 &&
              json != NULL &&
              strcmp(json, "{\"columns\":[\"a\",\"b\"],"
                           "\"rows\":[[\"1\",\"x\"],[\"2\",\"y\"],"
                           "[\"3\",\"prepared\"],[\"4\",\"tx-one\"],"
                           "[\"5\",\"tx-two\"]]}") == 0);
    zaxonlite_free(json);
    CHECK("write via query is misuse",
          zaxonlite_query_json(db, "delete from c", &json) == 2);

    uint64_t session = 0;
    CHECK("session open", zaxonlite_session_open(db, &session) == 0 && session > 0);
    bool replayed = true;
    CHECK("idempotent exec",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              changes == 1 && !replayed);
    CHECK("idempotent replay",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              changes == 1 && replayed);
    CHECK("sequence gap",
          zaxonlite_exec_idempotent(db, session, 5,
                                    "insert into c(b) values ('g')", &changes,
                                    &replayed) == 1);

    CHECK("snapshot", zaxonlite_snapshot(db) == 0);
    CHECK("integrity", zaxonlite_integrity_check(db) == 0);

    int64_t expired = -1;
    CHECK("expire sessions",
          zaxonlite_expire_sessions(db, 1000, &expired) == 0 && expired == 0);

    char backup_path[1024];
    snprintf(backup_path, sizeof backup_path, "%s.backup.db", dir);
    CHECK("backup", zaxonlite_backup(db, backup_path) == 0);

    zaxonlite_close(db);

    /* Reopen: state survives, the session replays. */
    CHECK("reopen", zaxonlite_open(dir, &db) == 0 && db != NULL);
    CHECK("replay after reopen",
          zaxonlite_exec_idempotent(db, session, 1,
                                    "insert into c(b) values ('z')", &changes,
                                    &replayed) == 0 &&
              replayed);
    zaxonlite_close(db);

    /* The transport-owning facade is a separate C surface. */
    char cluster_dir[1024];
    char gateway_dir[1024];
    char cluster_address[64];
    char gateway_address[64];
    snprintf(cluster_dir, sizeof cluster_dir, "%s.cluster", dir);
    snprintf(gateway_dir, sizeof gateway_dir, "%s.gateway", dir);
    const int cluster_port = 30000 + ((int)getpid() % 20000);
    snprintf(cluster_address, sizeof cluster_address, "127.0.0.1:%d",
             cluster_port);
    snprintf(gateway_address, sizeof gateway_address, "127.0.0.1:%d",
             cluster_port + 1);
    zaxonlite_member cluster_members[] = {
        {.id = 1,
         .address = cluster_address,
         .role = ZAXONLITE_DATA_VOTER},
        {.id = 99, .address = gateway_address, .role = ZAXONLITE_GATEWAY},
    };
    zaxonlite_cluster_options cluster_options = {
        .directory = cluster_dir,
        .node_id = 1,
        .members = cluster_members,
        .member_count = 2,
        .cluster_id = "c-api-smoke",
        .startup_timeout_ms = 5000,
        .allow_insecure_test_tcp = true,
    };
    zaxonlite_cluster *cluster = NULL;
    CHECK("cluster facade open",
          zaxonlite_cluster_open(&cluster_options, &cluster) == 0 &&
              cluster != NULL);
    if (cluster != NULL) {
        CHECK("cluster facade exec",
              zaxonlite_cluster_exec(
                  cluster, "create table facade(value text)", &changes) == 0);
        CHECK("cluster facade insert",
              zaxonlite_cluster_exec(
                  cluster, "insert into facade values ('paxos')", &changes) == 0);
        char *cluster_json = NULL;
        CHECK("cluster facade query",
              zaxonlite_cluster_query_json(
                  cluster, "select value from facade", &cluster_json) == 0 &&
                  cluster_json != NULL && strstr(cluster_json, "paxos") != NULL);
        zaxonlite_free(cluster_json);
        char *status_json = NULL;
        CHECK("cluster facade generic RPC",
              zaxonlite_cluster_call_json(cluster, "{\"op\":\"status\"}",
                                          false, &status_json) == 0 &&
                  status_json != NULL &&
                  strstr(status_json, "data-voter") != NULL);
        zaxonlite_free(status_json);

        zaxonlite_member gateway_members[] = {
            {.id = 99,
             .address = gateway_address,
             .role = ZAXONLITE_GATEWAY},
            {.id = 1,
             .address = cluster_address,
             .role = ZAXONLITE_DATA_VOTER},
        };
        zaxonlite_cluster_options gateway_options = {
            .directory = gateway_dir,
            .node_id = 99,
            .members = gateway_members,
            .member_count = 2,
            .cluster_id = "c-api-smoke",
            .startup_timeout_ms = 5000,
            .allow_insecure_test_tcp = true,
        };
        zaxonlite_cluster *gateway = NULL;
        CHECK("gateway C facade open",
              zaxonlite_cluster_open(&gateway_options, &gateway) == 0 &&
                  gateway != NULL);
        if (gateway != NULL) {
            char *gateway_json = NULL;
            CHECK("gateway C facade query",
                  zaxonlite_cluster_query_json(
                      gateway, "select value from facade", &gateway_json) == 0 &&
                      gateway_json != NULL &&
                      strstr(gateway_json, "paxos") != NULL);
            zaxonlite_free(gateway_json);
            zaxonlite_cluster_close(gateway);
        }
        zaxonlite_cluster_close(cluster);
    }

    if (failures == 0) {
        printf("capi smoke: all checks passed\n");
        return 0;
    }
    printf("capi smoke: %d failure(s)\n", failures);
    return 1;
}
