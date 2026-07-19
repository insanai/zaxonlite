/* C ABI smoke test: exercises every exported function against a scratch
 * directory passed as argv[1]. Exits non-zero on the first failure. */

#include "zaxonlite.h"

#include <stdio.h>
#include <string.h>
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
    char dir[1024];
    snprintf(dir, sizeof dir, "%s-%d", argv[1], (int)getpid());

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
    CHECK("sql error surfaces",
          zaxonlite_exec(db, "insert into missing values (1)", &changes) == 1 &&
              strstr(zaxonlite_last_error(db), "no such table") != NULL);

    char *json = NULL;
    CHECK("query json",
          zaxonlite_query_json(db, "select * from c order by a", &json) == 0 &&
              json != NULL &&
              strcmp(json, "{\"columns\":[\"a\",\"b\"],"
                           "\"rows\":[[\"1\",\"x\"],[\"2\",\"y\"]]}") == 0);
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

    if (failures == 0) {
        printf("capi smoke: all checks passed\n");
        return 0;
    }
    printf("capi smoke: %d failure(s)\n", failures);
    return 1;
}
