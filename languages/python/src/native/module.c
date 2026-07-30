/*
 * zxlite._zxlite: thin CPython binding over the zaxonlite C ABI.
 *
 * The extension is a functional layer: it converts Python values to
 * zaxonlite_value arrays, calls the C ABI with the GIL released, and
 * converts typed results back to plain Python tuples.  All policy
 * (write lane, exception hierarchy, DB-API semantics) lives in the
 * Python package.  The Python layer guarantees single-threaded access
 * to each handle, so no mutex is taken here.
 *
 * Errors are raised as zxlite._zxlite._ZxError with attributes
 * `code` (native return code), `category` (stable native category),
 * and `message`; the Python layer re-maps them onto the DB-API
 * hierarchy.
 */

#define Py_LIMITED_API 0x030C0000
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zaxonlite.h"

/* Categories mirrored from the native ABI for locally raised errors. */
#define ZX_CATEGORY_MISUSE 4
#define ZX_CATEGORY_SQL_OTHER 9

#define ZX_CODE_SQL 1
#define ZX_CODE_MISUSE 2

static PyObject *ZxError; /* set during module exec */

/* Owned wrappers behind capsules: the pointer inside a capsule cannot
 * be reset to NULL, so close() clears the inner handle instead. */
typedef struct {
    zaxonlite *handle;
} ConnectionBox;

typedef struct {
    zaxonlite_transaction *transaction;
    zaxonlite *owner; /* borrowed: error text lives on the connection */
} TransactionBox;

typedef struct {
    zaxonlite_cluster *handle;
} ClusterBox;

typedef struct {
    zaxonlite_remote *handle;
} RemoteBox;

static const char connection_capsule_name[] = "zxlite.connection";
static const char transaction_capsule_name[] = "zxlite.transaction";
static const char cluster_capsule_name[] = "zxlite.cluster";
static const char remote_capsule_name[] = "zxlite.remote";

static void
raise_zx_error(int code, int category, const char *message)
{
    PyObject *exc = PyObject_CallFunction(ZxError, "s", message);
    if (exc == NULL) {
        return;
    }
    PyObject *code_obj = PyLong_FromLong(code);
    PyObject *category_obj = PyLong_FromLong(category);
    PyObject *message_obj = PyUnicode_FromString(message);
    if (code_obj == NULL || category_obj == NULL || message_obj == NULL ||
        PyObject_SetAttrString(exc, "code", code_obj) < 0 ||
        PyObject_SetAttrString(exc, "category", category_obj) < 0 ||
        PyObject_SetAttrString(exc, "message", message_obj) < 0) {
        Py_XDECREF(code_obj);
        Py_XDECREF(category_obj);
        Py_XDECREF(message_obj);
        Py_DECREF(exc);
        return;
    }
    Py_DECREF(code_obj);
    Py_DECREF(category_obj);
    Py_DECREF(message_obj);
    PyErr_SetObject(ZxError, exc);
    Py_DECREF(exc);
}

static void
raise_native_error(zaxonlite *handle, int code)
{
    const char *message = zaxonlite_last_error(handle);
    int category = zaxonlite_last_error_category(handle);
    raise_zx_error(code, category,
                   (message != NULL && message[0] != '\0')
                       ? message
                       : "zaxonlite call failed");
}

static ConnectionBox *
connection_from_capsule(PyObject *capsule)
{
    ConnectionBox *box =
        PyCapsule_GetPointer(capsule, connection_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    if (box->handle == NULL) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "connection handle is closed");
        return NULL;
    }
    return box;
}

static TransactionBox *
transaction_from_capsule(PyObject *capsule)
{
    TransactionBox *box =
        PyCapsule_GetPointer(capsule, transaction_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    if (box->transaction == NULL) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "transaction handle is closed");
        return NULL;
    }
    return box;
}

static void
connection_capsule_destructor(PyObject *capsule)
{
    ConnectionBox *box =
        PyCapsule_GetPointer(capsule, connection_capsule_name);
    if (box == NULL) {
        PyErr_Clear();
        return;
    }
    if (box->handle != NULL) {
        zaxonlite_close(box->handle);
        box->handle = NULL;
    }
    PyMem_Free(box);
}

static RemoteBox *
remote_from_capsule(PyObject *capsule)
{
    RemoteBox *box = PyCapsule_GetPointer(capsule, remote_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    if (box->handle == NULL) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "remote handle is closed");
        return NULL;
    }
    return box;
}

static void
raise_remote_error(zaxonlite_remote *remote, int rc)
{
    const char *message = zaxonlite_remote_last_error(remote);
    int category = zaxonlite_remote_last_error_category(remote);
    raise_zx_error(rc, category,
                   (message != NULL && message[0] != '\0')
                       ? message
                       : "zaxonlite remote call failed");
}

/* Maps a native return code to a category when no handle exists to ask. */
static int
handleless_category(int rc)
{
    switch (rc) {
    case 2:
        return ZX_CATEGORY_MISUSE;
    case 3:
        return 6; /* integrity */
    case 4:
        return 7; /* availability */
    default:
        return ZX_CATEGORY_SQL_OTHER;
    }
}

static void
cluster_capsule_destructor(PyObject *capsule)
{
    ClusterBox *box = PyCapsule_GetPointer(capsule, cluster_capsule_name);
    if (box == NULL) {
        PyErr_Clear();
        return;
    }
    if (box->handle != NULL) {
        zaxonlite_cluster_close(box->handle);
        box->handle = NULL;
    }
    PyMem_Free(box);
}

static void
remote_capsule_destructor(PyObject *capsule)
{
    RemoteBox *box = PyCapsule_GetPointer(capsule, remote_capsule_name);
    if (box == NULL) {
        PyErr_Clear();
        return;
    }
    if (box->handle != NULL) {
        zaxonlite_remote_close(box->handle);
        box->handle = NULL;
    }
    PyMem_Free(box);
}

static void
transaction_capsule_destructor(PyObject *capsule)
{
    TransactionBox *box =
        PyCapsule_GetPointer(capsule, transaction_capsule_name);
    if (box == NULL) {
        PyErr_Clear();
        return;
    }
    if (box->transaction != NULL) {
        zaxonlite_transaction_close(box->transaction);
        box->transaction = NULL;
    }
    PyMem_Free(box);
}

/*
 * Parameter binding.
 *
 * BoundParams pins every borrowed buffer (str storage via the tuple
 * reference, bytes-likes via Py_buffer) for the duration of one native
 * call.  bound_params_clear releases the pins.
 */
typedef struct {
    zaxonlite_value *values;
    Py_buffer *buffers;
    size_t buffer_count;
    size_t count;
} BoundParams;

static void
bound_params_clear(BoundParams *params)
{
    for (size_t i = 0; i < params->buffer_count; i++) {
        PyBuffer_Release(&params->buffers[i]);
    }
    PyMem_Free(params->values);
    PyMem_Free(params->buffers);
    params->values = NULL;
    params->buffers = NULL;
    params->buffer_count = 0;
    params->count = 0;
}

/* Binds one Python value into *value; may register a pinned buffer. */
static int
bind_one(PyObject *item, zaxonlite_value *value, BoundParams *params)
{
    memset(value, 0, sizeof(*value));
    if (item == Py_None) {
        value->type = ZAXONLITE_NULL;
        return 0;
    }
    if (PyBool_Check(item)) {
        value->type = ZAXONLITE_INTEGER;
        value->integer = (item == Py_True) ? 1 : 0;
        return 0;
    }
    if (PyLong_Check(item)) {
        int64_t integer = PyLong_AsLongLong(item);
        if (integer == -1 && PyErr_Occurred()) {
            return -1; /* OverflowError for out-of-range values */
        }
        value->type = ZAXONLITE_INTEGER;
        value->integer = integer;
        return 0;
    }
    if (PyFloat_Check(item)) {
        double real = PyFloat_AsDouble(item);
        if (real == -1.0 && PyErr_Occurred()) {
            return -1;
        }
        value->type = ZAXONLITE_REAL;
        value->real = real;
        return 0;
    }
    if (PyUnicode_Check(item)) {
        Py_ssize_t length = 0;
        const char *bytes = PyUnicode_AsUTF8AndSize(item, &length);
        if (bytes == NULL) {
            return -1;
        }
        value->type = ZAXONLITE_TEXT;
        value->bytes = bytes;
        value->length = (size_t)length;
        return 0;
    }
    if (PyBytes_Check(item) || PyByteArray_Check(item) ||
        PyMemoryView_Check(item)) {
        Py_buffer *view = &params->buffers[params->buffer_count];
        if (PyObject_GetBuffer(item, view, PyBUF_SIMPLE) < 0) {
            return -1; /* non-contiguous memoryview raises BufferError */
        }
        params->buffer_count++;
        value->type = ZAXONLITE_BLOB;
        value->bytes = view->buf;
        value->length = (size_t)view->len;
        return 0;
    }
    raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                   "unsupported parameter type; supported types are None, "
                   "bool, int, float, str, bytes, bytearray, and "
                   "contiguous memoryview");
    return -1;
}

/* Binds a parameter tuple; params must later be cleared exactly once. */
static int
bind_params(PyObject *tuple, BoundParams *params)
{
    memset(params, 0, sizeof(*params));
    if (!PyTuple_Check(tuple)) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "parameters must be passed as a tuple");
        return -1;
    }
    Py_ssize_t count = PyTuple_Size(tuple);
    if (count < 0) {
        return -1;
    }
    params->count = (size_t)count;
    if (count == 0) {
        return 0;
    }
    params->values = PyMem_Calloc((size_t)count, sizeof(zaxonlite_value));
    params->buffers = PyMem_Calloc((size_t)count, sizeof(Py_buffer));
    if (params->values == NULL || params->buffers == NULL) {
        bound_params_clear(params);
        PyErr_NoMemory();
        return -1;
    }
    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *item = PyTuple_GetItem(tuple, i); /* borrowed */
        if (item == NULL || bind_one(item, &params->values[i], params) < 0) {
            bound_params_clear(params);
            return -1;
        }
    }
    return 0;
}

/*
 * Result conversion: fully materializes a zaxonlite_result into
 * (columns, rows) with native Python objects, then the caller closes
 * the result.  NULL -> None, INTEGER -> int, REAL -> float,
 * TEXT -> str (strict UTF-8), BLOB -> bytes.
 */
static PyObject *
convert_result(zaxonlite *handle, zaxonlite_result *result)
{
    (void)handle;
    size_t column_count = zaxonlite_result_column_count(result);
    size_t row_count = zaxonlite_result_row_count(result);

    PyObject *columns = PyTuple_New((Py_ssize_t)column_count);
    if (columns == NULL) {
        return NULL;
    }
    for (size_t c = 0; c < column_count; c++) {
        const char *name = zaxonlite_result_column_name(result, c);
        PyObject *name_obj =
            PyUnicode_FromString(name != NULL ? name : "");
        if (name_obj == NULL ||
            PyTuple_SetItem(columns, (Py_ssize_t)c, name_obj) < 0) {
            Py_DECREF(columns);
            return NULL;
        }
    }

    PyObject *rows = PyTuple_New((Py_ssize_t)row_count);
    if (rows == NULL) {
        Py_DECREF(columns);
        return NULL;
    }
    for (size_t r = 0; r < row_count; r++) {
        PyObject *row = PyTuple_New((Py_ssize_t)column_count);
        if (row == NULL) {
            goto fail;
        }
        if (PyTuple_SetItem(rows, (Py_ssize_t)r, row) < 0) {
            Py_DECREF(row);
            goto fail;
        }
        for (size_t c = 0; c < column_count; c++) {
            zaxonlite_value cell;
            if (zaxonlite_result_value(result, r, c, &cell) != 0) {
                raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                               "result cell index out of bounds");
                goto fail;
            }
            PyObject *converted = NULL;
            switch (cell.type) {
            case ZAXONLITE_NULL:
                converted = Py_None;
                Py_INCREF(converted);
                break;
            case ZAXONLITE_INTEGER:
                converted = PyLong_FromLongLong(cell.integer);
                break;
            case ZAXONLITE_REAL:
                converted = PyFloat_FromDouble(cell.real);
                break;
            case ZAXONLITE_TEXT:
                converted = PyUnicode_DecodeUTF8(
                    (const char *)cell.bytes, (Py_ssize_t)cell.length,
                    NULL);
                if (converted == NULL) {
                    PyErr_Clear();
                    raise_zx_error(ZX_CODE_SQL, ZX_CATEGORY_SQL_OTHER,
                                   "TEXT result is not valid UTF-8");
                }
                break;
            case ZAXONLITE_BLOB:
                converted = PyBytes_FromStringAndSize(
                    (const char *)cell.bytes, (Py_ssize_t)cell.length);
                break;
            default:
                raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                               "unknown result value type");
                break;
            }
            if (converted == NULL ||
                PyTuple_SetItem(row, (Py_ssize_t)c, converted) < 0) {
                Py_XDECREF(converted);
                goto fail;
            }
        }
    }
    PyObject *pair = PyTuple_Pack(2, columns, rows);
    Py_DECREF(columns);
    Py_DECREF(rows);
    return pair;

fail:
    Py_DECREF(columns);
    Py_DECREF(rows);
    return NULL;
}

/* --- module functions ------------------------------------------------- */

static PyObject *
zx_open(PyObject *self, PyObject *args)
{
    (void)self;
    const char *path;
    if (!PyArg_ParseTuple(args, "s:open", &path)) {
        return NULL;
    }
    ConnectionBox *box = PyMem_Malloc(sizeof(ConnectionBox));
    if (box == NULL) {
        return PyErr_NoMemory();
    }
    box->handle = NULL;
    int rc;
    zaxonlite *handle = NULL;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_open(path, &handle);
    Py_END_ALLOW_THREADS
    if (rc != 0 || handle == NULL) {
        PyMem_Free(box);
        raise_zx_error(rc, rc == 4 ? 7 : ZX_CATEGORY_MISUSE,
                       "cannot open zaxonlite data directory (it may be "
                       "locked by another process)");
        return NULL;
    }
    box->handle = handle;
    PyObject *capsule = PyCapsule_New(box, connection_capsule_name,
                                      connection_capsule_destructor);
    if (capsule == NULL) {
        zaxonlite_close(handle);
        PyMem_Free(box);
        return NULL;
    }
    return capsule;
}

static PyObject *
zx_close(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:close", &capsule)) {
        return NULL;
    }
    ConnectionBox *box =
        PyCapsule_GetPointer(capsule, connection_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite *handle = box->handle;
    box->handle = NULL;
    if (handle != NULL) {
        Py_BEGIN_ALLOW_THREADS
        zaxonlite_close(handle);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_version(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    return PyUnicode_FromString(zaxonlite_version());
}

static PyObject *
zx_describe(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    if (!PyArg_ParseTuple(args, "Os:describe", &capsule, &sql)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite_statement_info info;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_statement_describe(box->handle, sql, &info);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return Py_BuildValue("(IIOO)", (unsigned int)info.parameter_count,
                         (unsigned int)info.column_count,
                         info.read_only ? Py_True : Py_False,
                         info.has_tail ? Py_True : Py_False);
}

static PyObject *
zx_query(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    if (!PyArg_ParseTuple(args, "OsO:query", &capsule, &sql,
                          &param_tuple)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    zaxonlite_result *result = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_query_prepared_result(box->handle, sql, params.values,
                                         params.count, &result);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    PyObject *pair = convert_result(box->handle, result);
    zaxonlite_result_close(result);
    return pair;
}

static PyObject *
zx_exec(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    if (!PyArg_ParseTuple(args, "OsO:exec", &capsule, &sql, &param_tuple)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    zaxonlite_exec_result exec_result;
    zaxonlite_result *returning = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_exec_prepared_result(box->handle, sql, params.values,
                                        params.count, &exec_result,
                                        &returning);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    PyObject *returning_obj = NULL;
    if (returning != NULL) {
        returning_obj = convert_result(box->handle, returning);
        zaxonlite_result_close(returning);
        if (returning_obj == NULL) {
            return NULL;
        }
    }
    else {
        returning_obj = Py_None;
        Py_INCREF(returning_obj);
    }
    PyObject *rowid_obj;
    if (exec_result.has_last_insert_rowid) {
        rowid_obj = PyLong_FromLongLong(exec_result.last_insert_rowid);
    }
    else {
        rowid_obj = Py_None;
        Py_INCREF(rowid_obj);
    }
    if (rowid_obj == NULL) {
        Py_DECREF(returning_obj);
        return NULL;
    }
    PyObject *out = Py_BuildValue(
        "(LOOO)", (long long)exec_result.changes, rowid_obj,
        exec_result.replayed ? Py_True : Py_False, returning_obj);
    Py_DECREF(rowid_obj);
    Py_DECREF(returning_obj);
    return out;
}

static PyObject *
zx_exec_script(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    if (!PyArg_ParseTuple(args, "Os:exec_script", &capsule, &sql)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int64_t changes = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_exec(box->handle, sql, &changes);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return PyLong_FromLongLong(changes);
}

static PyObject *
zx_begin(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:begin", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    TransactionBox *tx_box = PyMem_Malloc(sizeof(TransactionBox));
    if (tx_box == NULL) {
        return PyErr_NoMemory();
    }
    tx_box->transaction = NULL;
    tx_box->owner = box->handle;
    zaxonlite_transaction *transaction = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_transaction_begin(box->handle, &transaction);
    Py_END_ALLOW_THREADS
    if (rc != 0 || transaction == NULL) {
        PyMem_Free(tx_box);
        raise_native_error(box->handle, rc);
        return NULL;
    }
    tx_box->transaction = transaction;
    PyObject *tx_capsule = PyCapsule_New(
        tx_box, transaction_capsule_name, transaction_capsule_destructor);
    if (tx_capsule == NULL) {
        zaxonlite_transaction_close(transaction);
        PyMem_Free(tx_box);
        return NULL;
    }
    return tx_capsule;
}

static PyObject *
zx_tx_exec(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    if (!PyArg_ParseTuple(args, "OsO:tx_exec", &capsule, &sql,
                          &param_tuple)) {
        return NULL;
    }
    TransactionBox *box = transaction_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_transaction_exec(box->transaction, sql, params.values,
                                    params.count);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_native_error(box->owner, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_tx_commit(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:tx_commit", &capsule)) {
        return NULL;
    }
    TransactionBox *box = transaction_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int64_t changes = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_transaction_commit(box->transaction, &changes);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->owner, rc);
        return NULL;
    }
    return PyLong_FromLongLong(changes);
}

static PyObject *
zx_tx_close(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:tx_close", &capsule)) {
        return NULL;
    }
    TransactionBox *box =
        PyCapsule_GetPointer(capsule, transaction_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite_transaction *transaction = box->transaction;
    box->transaction = NULL;
    if (transaction != NULL) {
        Py_BEGIN_ALLOW_THREADS
        zaxonlite_transaction_close(transaction);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_session_open(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:session_open", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    uint64_t session = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_session_open(box->handle, &session);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return PyLong_FromUnsignedLongLong(session);
}

static PyObject *
zx_exec_idempotent(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    unsigned long long session;
    unsigned long long sequence;
    const char *sql;
    if (!PyArg_ParseTuple(args, "OKKs:exec_idempotent", &capsule, &session,
                          &sequence, &sql)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int64_t changes = 0;
    bool replayed = false;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_exec_idempotent(box->handle, session, sequence, sql,
                                   &changes, &replayed);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return Py_BuildValue("(LO)", (long long)changes,
                         replayed ? Py_True : Py_False);
}

static PyObject *
zx_snapshot(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:snapshot", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_snapshot(box->handle);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_backup(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *path;
    if (!PyArg_ParseTuple(args, "Os:backup", &capsule, &path)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_backup(box->handle, path);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_integrity_check(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:integrity_check", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_integrity_check(box->handle);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_expire_sessions(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    unsigned long long retain;
    if (!PyArg_ParseTuple(args, "OK:expire_sessions", &capsule, &retain)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int64_t expired = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_expire_sessions(box->handle, retain, &expired);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return PyLong_FromLongLong(expired);
}

static PyObject *
zx_search_impl(PyObject *self, PyObject *args, PyObject *kwargs,
               int remote)
{
    (void)self;
    static char *keywords[] = {
        "capsule",        "fts_table",       "vec_table",
        "text",           "embedding",       "k",
        "candidate_count", "fusion",         "text_weight",
        "vector_weight",  "metadata_table",  "metadata_id_column",
        "metadata_columns", "level",          "freshness_ms",
        NULL,
    };
    PyObject *capsule;
    const char *fts_table = NULL;
    const char *vec_table = NULL;
    const char *text = NULL;
    Py_ssize_t text_length = 0;
    PyObject *embedding_obj = Py_None;
    unsigned int k = 10;
    PyObject *candidate_obj = Py_None;
    int fusion = 0;
    double text_weight = 1.0;
    double vector_weight = 1.0;
    const char *metadata_table = NULL;
    const char *metadata_id_column = NULL;
    PyObject *metadata_columns_obj = Py_None;
    int level = 2;
    unsigned long long freshness_ms = 0;
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "O|zzz#OIOiddzzOiK:search", keywords, &capsule,
            &fts_table, &vec_table, &text, &text_length, &embedding_obj,
            &k, &candidate_obj, &fusion, &text_weight, &vector_weight,
            &metadata_table, &metadata_id_column, &metadata_columns_obj,
            &level, &freshness_ms)) {
        return NULL;
    }
    ConnectionBox *connection = NULL;
    RemoteBox *remote_box = NULL;
    if (remote) {
        remote_box = remote_from_capsule(capsule);
        if (remote_box == NULL) {
            return NULL;
        }
    }
    else {
        connection = connection_from_capsule(capsule);
        if (connection == NULL) {
            return NULL;
        }
    }

    zaxonlite_search_options options;
    memset(&options, 0, sizeof(options));
    options.fts_table = fts_table;
    options.vec_table = vec_table;
    options.text = text;
    options.text_length = (text != NULL) ? (size_t)text_length : 0;
    options.k = k;
    options.fusion = (fusion == 1) ? ZAXONLITE_SEARCH_DBSF
                                   : ZAXONLITE_SEARCH_RRF;
    options.text_weight = text_weight;
    options.vector_weight = vector_weight;
    options.metadata_table = metadata_table;
    options.metadata_id_column = metadata_id_column;

    if (candidate_obj != Py_None) {
        unsigned long candidate = PyLong_AsUnsignedLong(candidate_obj);
        if (candidate == (unsigned long)-1 && PyErr_Occurred()) {
            return NULL;
        }
        options.candidate_count = (uint32_t)candidate;
        options.has_candidate_count = true;
    }

    Py_buffer embedding_view;
    int have_embedding_view = 0;
    if (embedding_obj != Py_None) {
        if (PyObject_GetBuffer(embedding_obj, &embedding_view,
                               PyBUF_SIMPLE) < 0) {
            return NULL;
        }
        have_embedding_view = 1;
        options.embedding = embedding_view.buf;
        options.embedding_length = (size_t)embedding_view.len;
    }

    const char **metadata_columns = NULL;
    PyObject *columns_seq = NULL;
    if (metadata_columns_obj != Py_None) {
        columns_seq = PySequence_Tuple(metadata_columns_obj);
        if (columns_seq == NULL) {
            goto fail;
        }
        Py_ssize_t column_count = PyTuple_Size(columns_seq);
        if (column_count < 0) {
            goto fail;
        }
        if (column_count > 0) {
            metadata_columns =
                PyMem_Calloc((size_t)column_count, sizeof(char *));
            if (metadata_columns == NULL) {
                PyErr_NoMemory();
                goto fail;
            }
            for (Py_ssize_t i = 0; i < column_count; i++) {
                /* borrowed; columns_seq keeps items alive for the call */
                PyObject *item = PyTuple_GetItem(columns_seq, i);
                if (item == NULL) {
                    goto fail;
                }
                const char *column =
                    PyUnicode_AsUTF8AndSize(item, NULL);
                if (column == NULL) {
                    goto fail;
                }
                metadata_columns[i] = column;
            }
            options.metadata_columns = metadata_columns;
            options.metadata_column_count = (size_t)column_count;
        }
    }

    zaxonlite_result *result = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    if (remote) {
        rc = zaxonlite_remote_search(remote_box->handle, &options, level,
                                     freshness_ms, &result);
    }
    else {
        rc = zaxonlite_search(connection->handle, &options, &result);
    }
    Py_END_ALLOW_THREADS
    if (have_embedding_view) {
        PyBuffer_Release(&embedding_view);
        have_embedding_view = 0;
    }
    PyMem_Free(metadata_columns);
    metadata_columns = NULL;
    Py_XDECREF(columns_seq);
    columns_seq = NULL;
    if (rc != 0) {
        if (remote) {
            raise_remote_error(remote_box->handle, rc);
        }
        else {
            raise_native_error(connection->handle, rc);
        }
        return NULL;
    }
    PyObject *pair =
        convert_result(remote ? NULL : connection->handle, result);
    zaxonlite_result_close(result);
    return pair;

fail:
    if (have_embedding_view) {
        PyBuffer_Release(&embedding_view);
    }
    PyMem_Free(metadata_columns);
    Py_XDECREF(columns_seq);
    return NULL;
}

static PyObject *
zx_search(PyObject *self, PyObject *args, PyObject *kwargs)
{
    return zx_search_impl(self, args, kwargs, 0);
}

static PyObject *
zx_remote_search(PyObject *self, PyObject *args, PyObject *kwargs)
{
    return zx_search_impl(self, args, kwargs, 1);
}

/* --- hosted server (cluster facade) ---------------------------------- */

static PyObject *
zx_cluster_open(PyObject *self, PyObject *args)
{
    (void)self;
    const char *directory;
    unsigned int node_id;
    PyObject *members_obj;
    const char *cluster_id = NULL;
    const char *auth_file = NULL;
    const char *tls_cert = NULL;
    const char *tls_key = NULL;
    const char *tls_ca = NULL;
    unsigned long long startup_timeout_ms;
    int allow_psk;
    if (!PyArg_ParseTuple(args, "sIOzzzzzKp:cluster_open", &directory,
                          &node_id, &members_obj, &cluster_id, &auth_file,
                          &tls_cert, &tls_key, &tls_ca, &startup_timeout_ms,
                          &allow_psk)) {
        return NULL;
    }
    if (!PyTuple_Check(members_obj)) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "members must be a tuple of (id, address, role)");
        return NULL;
    }
    Py_ssize_t member_count = PyTuple_Size(members_obj);
    if (member_count < 0) {
        return NULL;
    }
    zaxonlite_member *members =
        PyMem_Calloc((size_t)(member_count > 0 ? member_count : 1),
                     sizeof(zaxonlite_member));
    if (members == NULL) {
        return PyErr_NoMemory();
    }
    for (Py_ssize_t i = 0; i < member_count; i++) {
        PyObject *entry = PyTuple_GetItem(members_obj, i); /* borrowed */
        unsigned int member_id;
        const char *address;
        int role;
        if (entry == NULL ||
            !PyArg_ParseTuple(entry, "Isi", &member_id, &address, &role)) {
            PyMem_Free(members);
            return NULL;
        }
        members[i].id = member_id;
        members[i].address = address; /* borrowed from members_obj */
        members[i].role = (zaxonlite_node_role)role;
    }

    zaxonlite_cluster_options_v2 options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.directory = directory;
    options.node_id = node_id;
    options.members = members;
    options.member_count = (size_t)member_count;
    options.cluster_id = cluster_id;
    options.auth_file_path = auth_file;
    options.tls_cert_path = tls_cert;
    options.tls_key_path = tls_key;
    options.tls_ca_path = tls_ca;
    options.startup_timeout_ms = startup_timeout_ms;
    options.allow_psk_only_loopback = (allow_psk != 0);

    ClusterBox *box = PyMem_Malloc(sizeof(ClusterBox));
    if (box == NULL) {
        PyMem_Free(members);
        return PyErr_NoMemory();
    }
    box->handle = NULL;
    zaxonlite_cluster *handle = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_cluster_open_v2(&options, &handle);
    Py_END_ALLOW_THREADS
    PyMem_Free(members);
    if (rc != 0 || handle == NULL) {
        PyMem_Free(box);
        raise_zx_error(rc, handleless_category(rc),
                       "cluster member failed to start (bad options, "
                       "locked directory, or startup timeout)");
        return NULL;
    }
    box->handle = handle;
    PyObject *capsule = PyCapsule_New(box, cluster_capsule_name,
                                      cluster_capsule_destructor);
    if (capsule == NULL) {
        zaxonlite_cluster_close(handle);
        PyMem_Free(box);
        return NULL;
    }
    return capsule;
}

static PyObject *
zx_cluster_close(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:cluster_close", &capsule)) {
        return NULL;
    }
    ClusterBox *box = PyCapsule_GetPointer(capsule, cluster_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite_cluster *handle = box->handle;
    box->handle = NULL;
    if (handle != NULL) {
        Py_BEGIN_ALLOW_THREADS
        zaxonlite_cluster_close(handle);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

/* --- external remote client ------------------------------------------ */

static PyObject *
zx_remote_open(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *seeds_obj;
    const char *tls_ca = NULL;
    const char *tls_cert = NULL;
    const char *tls_key = NULL;
    const char *auth_file = NULL;
    int allow_psk;
    Py_ssize_t pool_size;
    unsigned long long connect_timeout_ms;
    unsigned long long operation_timeout_ms;
    PyObject *expected_obj = Py_None;
    unsigned long long write_admission_timeout_ms;
    if (!PyArg_ParseTuple(args, "OzzzzpnKKOK:remote_open", &seeds_obj,
                          &tls_ca, &tls_cert, &tls_key, &auth_file,
                          &allow_psk, &pool_size, &connect_timeout_ms,
                          &operation_timeout_ms, &expected_obj,
                          &write_admission_timeout_ms)) {
        return NULL;
    }
    if (!PyTuple_Check(seeds_obj) || PyTuple_Size(seeds_obj) == 0) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "seeds must be a non-empty tuple of strings");
        return NULL;
    }
    Py_ssize_t seed_count = PyTuple_Size(seeds_obj);
    const char **seeds =
        PyMem_Calloc((size_t)seed_count, sizeof(char *));
    if (seeds == NULL) {
        return PyErr_NoMemory();
    }
    for (Py_ssize_t i = 0; i < seed_count; i++) {
        PyObject *item = PyTuple_GetItem(seeds_obj, i); /* borrowed */
        if (item == NULL) {
            PyMem_Free(seeds);
            return NULL;
        }
        seeds[i] = PyUnicode_AsUTF8AndSize(item, NULL);
        if (seeds[i] == NULL) {
            PyMem_Free(seeds);
            return NULL;
        }
    }

    zaxonlite_remote_options options;
    memset(&options, 0, sizeof(options));
    options.seeds = seeds;
    options.seed_count = (size_t)seed_count;
    options.tls_ca_path = tls_ca;
    options.tls_cert_path = tls_cert;
    options.tls_key_path = tls_key;
    options.auth_file_path = auth_file;
    options.allow_psk_only_loopback = (allow_psk != 0);
    options.pool_size = (pool_size > 0) ? (size_t)pool_size : 0;
    options.connect_timeout_ms = connect_timeout_ms;
    options.operation_timeout_ms = operation_timeout_ms;
    options.write_admission_timeout_ms = write_admission_timeout_ms;
    if (expected_obj != Py_None) {
        char *identity = NULL;
        Py_ssize_t identity_length = 0;
        if (PyBytes_AsStringAndSize(expected_obj, &identity,
                                    &identity_length) < 0) {
            PyMem_Free(seeds);
            return NULL;
        }
        if (identity_length != 16) {
            PyMem_Free(seeds);
            raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                           "expected_database_id must be exactly 16 bytes");
            return NULL;
        }
        memcpy(options.expected_database_id, identity, 16);
        options.has_expected_database_id = true;
    }

    RemoteBox *box = PyMem_Malloc(sizeof(RemoteBox));
    if (box == NULL) {
        PyMem_Free(seeds);
        return PyErr_NoMemory();
    }
    box->handle = NULL;
    zaxonlite_remote *handle = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_open(&options, &handle);
    Py_END_ALLOW_THREADS
    PyMem_Free(seeds);
    if (rc != 0 || handle == NULL) {
        PyMem_Free(box);
        raise_zx_error(rc, handleless_category(rc),
                       "remote open failed (invalid options, "
                       "unreachable seeds, authentication failure, or "
                       "database identity mismatch)");
        return NULL;
    }
    box->handle = handle;
    PyObject *capsule = PyCapsule_New(box, remote_capsule_name,
                                      remote_capsule_destructor);
    if (capsule == NULL) {
        zaxonlite_remote_close(handle);
        PyMem_Free(box);
        return NULL;
    }
    return capsule;
}

static PyObject *
zx_remote_close(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:remote_close", &capsule)) {
        return NULL;
    }
    RemoteBox *box = PyCapsule_GetPointer(capsule, remote_capsule_name);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite_remote *handle = box->handle;
    box->handle = NULL;
    if (handle != NULL) {
        Py_BEGIN_ALLOW_THREADS
        zaxonlite_remote_close(handle);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_remote_exec(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    if (!PyArg_ParseTuple(args, "OsO:remote_exec", &capsule, &sql,
                          &param_tuple)) {
        return NULL;
    }
    RemoteBox *box = remote_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    zaxonlite_exec_result exec_result;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_exec(box->handle, sql, params.values,
                               params.count, &exec_result);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_remote_error(box->handle, rc);
        return NULL;
    }
    PyObject *rowid_obj;
    if (exec_result.has_last_insert_rowid) {
        rowid_obj = PyLong_FromLongLong(exec_result.last_insert_rowid);
    }
    else {
        rowid_obj = Py_None;
        Py_INCREF(rowid_obj);
    }
    if (rowid_obj == NULL) {
        return NULL;
    }
    PyObject *out = Py_BuildValue(
        "(LOO)", (long long)exec_result.changes, rowid_obj,
        exec_result.replayed ? Py_True : Py_False);
    Py_DECREF(rowid_obj);
    return out;
}

static PyObject *
zx_remote_exec_batch(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *rows_obj;
    if (!PyArg_ParseTuple(args, "OsO:remote_exec_batch", &capsule, &sql,
                          &rows_obj)) {
        return NULL;
    }
    RemoteBox *box = remote_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    if (!PyTuple_Check(rows_obj) || PyTuple_Size(rows_obj) == 0) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "batch rows must be a non-empty tuple of tuples");
        return NULL;
    }
    Py_ssize_t row_count = PyTuple_Size(rows_obj);
    PyObject *first_row = PyTuple_GetItem(rows_obj, 0); /* borrowed */
    if (first_row == NULL || !PyTuple_Check(first_row)) {
        raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                       "batch rows must be a non-empty tuple of tuples");
        return NULL;
    }
    Py_ssize_t per_row = PyTuple_Size(first_row);
    Py_ssize_t total = row_count * per_row;

    /* One flat uniform-row value array; every buffer stays pinned for
     * the duration of the native call. */
    BoundParams params;
    memset(&params, 0, sizeof(params));
    params.count = (size_t)total;
    if (total > 0) {
        params.values =
            PyMem_Calloc((size_t)total, sizeof(zaxonlite_value));
        params.buffers = PyMem_Calloc((size_t)total, sizeof(Py_buffer));
        if (params.values == NULL || params.buffers == NULL) {
            bound_params_clear(&params);
            return PyErr_NoMemory();
        }
    }
    for (Py_ssize_t r = 0; r < row_count; r++) {
        PyObject *row = PyTuple_GetItem(rows_obj, r); /* borrowed */
        if (row == NULL || !PyTuple_Check(row) ||
            PyTuple_Size(row) != per_row) {
            bound_params_clear(&params);
            raise_zx_error(ZX_CODE_MISUSE, ZX_CATEGORY_MISUSE,
                           "batch rows must all have the same length");
            return NULL;
        }
        for (Py_ssize_t c = 0; c < per_row; c++) {
            PyObject *item = PyTuple_GetItem(row, c); /* borrowed */
            if (item == NULL ||
                bind_one(item, &params.values[r * per_row + c],
                         &params) < 0) {
                bound_params_clear(&params);
                return NULL;
            }
        }
    }

    zaxonlite_exec_result exec_result;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_exec_batch(box->handle, sql, params.values,
                                     (size_t)per_row, (size_t)row_count,
                                     &exec_result);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_remote_error(box->handle, rc);
        return NULL;
    }
    PyObject *rowid_obj;
    if (exec_result.has_last_insert_rowid) {
        rowid_obj = PyLong_FromLongLong(exec_result.last_insert_rowid);
    }
    else {
        rowid_obj = Py_None;
        Py_INCREF(rowid_obj);
    }
    if (rowid_obj == NULL) {
        return NULL;
    }
    PyObject *out = Py_BuildValue(
        "(LOO)", (long long)exec_result.changes, rowid_obj,
        exec_result.replayed ? Py_True : Py_False);
    Py_DECREF(rowid_obj);
    return out;
}

static PyObject *
zx_remote_query(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    int level;
    unsigned long long freshness_ms;
    if (!PyArg_ParseTuple(args, "OsOiK:remote_query", &capsule, &sql,
                          &param_tuple, &level, &freshness_ms)) {
        return NULL;
    }
    RemoteBox *box = remote_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    zaxonlite_result *result = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_query(box->handle, sql, params.values,
                                params.count, level, freshness_ms,
                                &result);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_remote_error(box->handle, rc);
        return NULL;
    }
    PyObject *pair = convert_result(NULL, result);
    zaxonlite_result_close(result);
    return pair;
}

static PyObject *
zx_remote_resolve_pending(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:remote_resolve_pending", &capsule)) {
        return NULL;
    }
    RemoteBox *box = remote_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    zaxonlite_exec_result exec_result;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_resolve_pending(box->handle, &exec_result);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_remote_error(box->handle, rc);
        return NULL;
    }
    return Py_BuildValue("(LO)", (long long)exec_result.changes,
                         exec_result.replayed ? Py_True : Py_False);
}

static PyObject *
zx_remote_status_json(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:remote_status_json", &capsule)) {
        return NULL;
    }
    RemoteBox *box = remote_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    char *json = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_remote_status_json(box->handle, &json);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_remote_error(box->handle, rc);
        return NULL;
    }
    PyObject *out = PyUnicode_FromString(json != NULL ? json : "");
    zaxonlite_free(json);
    return out;
}

/* --- Gate C live transactions (local handle) -------------------------- */

static PyObject *
zx_live_begin(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:live_begin", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_begin(box->handle);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_live_exec(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    PyObject *param_tuple;
    if (!PyArg_ParseTuple(args, "OsO:live_exec", &capsule, &sql,
                          &param_tuple)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    BoundParams params;
    if (bind_params(param_tuple, &params) < 0) {
        return NULL;
    }
    zaxonlite_exec_result exec_result;
    zaxonlite_result *returning = NULL;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_exec(box->handle, sql, params.values, params.count,
                             &exec_result, &returning);
    Py_END_ALLOW_THREADS
    bound_params_clear(&params);
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    PyObject *returning_obj = NULL;
    if (returning != NULL) {
        returning_obj = convert_result(box->handle, returning);
        zaxonlite_result_close(returning);
        if (returning_obj == NULL) {
            return NULL;
        }
    }
    else {
        returning_obj = Py_None;
        Py_INCREF(returning_obj);
    }
    PyObject *rowid_obj;
    if (exec_result.has_last_insert_rowid) {
        rowid_obj = PyLong_FromLongLong(exec_result.last_insert_rowid);
    }
    else {
        rowid_obj = Py_None;
        Py_INCREF(rowid_obj);
    }
    if (rowid_obj == NULL) {
        Py_DECREF(returning_obj);
        return NULL;
    }
    PyObject *out = Py_BuildValue(
        "(LOOO)", (long long)exec_result.changes, rowid_obj,
        exec_result.replayed ? Py_True : Py_False, returning_obj);
    Py_DECREF(rowid_obj);
    Py_DECREF(returning_obj);
    return out;
}

static PyObject *
zx_live_savepoint(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    unsigned int index;
    if (!PyArg_ParseTuple(args, "OI:live_savepoint", &capsule, &index)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_savepoint(box->handle, index);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_live_release_savepoint(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    unsigned int index;
    if (!PyArg_ParseTuple(args, "OI:live_release_savepoint", &capsule,
                          &index)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_release_savepoint(box->handle, index);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_live_rollback_to_savepoint(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    unsigned int index;
    if (!PyArg_ParseTuple(args, "OI:live_rollback_to_savepoint", &capsule,
                          &index)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_rollback_to_savepoint(box->handle, index);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_live_commit(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:live_commit", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int64_t changes = 0;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_commit(box->handle, &changes);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return PyLong_FromLongLong(changes);
}

static PyObject *
zx_live_rollback(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:live_rollback", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_live_rollback(box->handle);
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
zx_live_active(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    if (!PyArg_ParseTuple(args, "O:live_active", &capsule)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    bool active;
    Py_BEGIN_ALLOW_THREADS
    active = zaxonlite_live_active(box->handle);
    Py_END_ALLOW_THREADS
    if (active) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
zx_statement_parameter_name(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *capsule;
    const char *sql;
    unsigned int index;
    if (!PyArg_ParseTuple(args, "OsI:statement_parameter_name", &capsule,
                          &sql, &index)) {
        return NULL;
    }
    ConnectionBox *box = connection_from_capsule(capsule);
    if (box == NULL) {
        return NULL;
    }
    char buffer[512];
    buffer[0] = '\0';
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = zaxonlite_statement_parameter_name(box->handle, sql, index,
                                            buffer, sizeof(buffer));
    Py_END_ALLOW_THREADS
    if (rc != 0) {
        raise_native_error(box->handle, rc);
        return NULL;
    }
    return PyUnicode_FromString(buffer);
}

static PyMethodDef zx_methods[] = {
    {"open", zx_open, METH_VARARGS,
     "open(path) -> capsule\n\nOpen or create a zaxonlite data directory."},
    {"close", zx_close, METH_VARARGS,
     "close(capsule)\n\nClose the native handle; idempotent."},
    {"version", zx_version, METH_NOARGS,
     "version() -> str\n\nReturn the native zaxonlite version string."},
    {"describe", zx_describe, METH_VARARGS,
     "describe(capsule, sql) -> (parameter_count, column_count, read_only,"
     " has_tail)"},
    {"query", zx_query, METH_VARARGS,
     "query(capsule, sql, params) -> (columns, rows)"},
    {"exec", zx_exec, METH_VARARGS,
     "exec(capsule, sql, params) -> (changes, lastrowid, replayed,"
     " returning)"},
    {"exec_script", zx_exec_script, METH_VARARGS,
     "exec_script(capsule, sql) -> changes"},
    {"begin", zx_begin, METH_VARARGS,
     "begin(capsule) -> transaction capsule"},
    {"tx_exec", zx_tx_exec, METH_VARARGS,
     "tx_exec(txcapsule, sql, params)\n\nQueue one statement."},
    {"tx_commit", zx_tx_commit, METH_VARARGS,
     "tx_commit(txcapsule) -> changes\n\nCommit the batch atomically."},
    {"tx_close", zx_tx_close, METH_VARARGS,
     "tx_close(txcapsule)\n\nRelease the transaction; idempotent."},
    {"session_open", zx_session_open, METH_VARARGS,
     "session_open(capsule) -> session id"},
    {"exec_idempotent", zx_exec_idempotent, METH_VARARGS,
     "exec_idempotent(capsule, session, sequence, sql) -> (changes,"
     " replayed)"},
    {"snapshot", zx_snapshot, METH_VARARGS, "snapshot(capsule)"},
    {"backup", zx_backup, METH_VARARGS, "backup(capsule, path)"},
    {"integrity_check", zx_integrity_check, METH_VARARGS,
     "integrity_check(capsule)"},
    {"expire_sessions", zx_expire_sessions, METH_VARARGS,
     "expire_sessions(capsule, retain) -> expired count"},
    {"search", (PyCFunction)(void (*)(void))zx_search,
     METH_VARARGS | METH_KEYWORDS,
     "search(capsule, **options) -> (columns, rows)"},
    {"cluster_open", zx_cluster_open, METH_VARARGS,
     "cluster_open(directory, node_id, members, cluster_id, auth_file,"
     " tls_cert, tls_key, tls_ca, startup_timeout_ms, allow_psk)"
     " -> cluster capsule"},
    {"cluster_close", zx_cluster_close, METH_VARARGS,
     "cluster_close(capsule)\n\nStop the member and join its thread."},
    {"remote_open", zx_remote_open, METH_VARARGS,
     "remote_open(seeds, tls_ca, tls_cert, tls_key, auth_file, allow_psk,"
     " pool_size, connect_timeout_ms, operation_timeout_ms,"
     " expected_database_id) -> remote capsule"},
    {"remote_close", zx_remote_close, METH_VARARGS,
     "remote_close(capsule)\n\nClose the pool; idempotent."},
    {"remote_exec", zx_remote_exec, METH_VARARGS,
     "remote_exec(capsule, sql, params) -> (changes, lastrowid,"
     " replayed)"},
    {"remote_exec_batch", zx_remote_exec_batch, METH_VARARGS,
     "remote_exec_batch(capsule, sql, rows) -> (changes, lastrowid,"
     " replayed)\n\nOne atomic replicated batch; uniform row shape."},
    {"remote_query", zx_remote_query, METH_VARARGS,
     "remote_query(capsule, sql, params, level, freshness_ms) ->"
     " (columns, rows)"},
    {"remote_search", (PyCFunction)(void (*)(void))zx_remote_search,
     METH_VARARGS | METH_KEYWORDS,
     "remote_search(capsule, **options) -> (columns, rows)"},
    {"remote_resolve_pending", zx_remote_resolve_pending, METH_VARARGS,
     "remote_resolve_pending(capsule) -> (changes, replayed)"},
    {"remote_status_json", zx_remote_status_json, METH_VARARGS,
     "remote_status_json(capsule) -> str"},
    {"live_begin", zx_live_begin, METH_VARARGS, "live_begin(capsule)"},
    {"live_exec", zx_live_exec, METH_VARARGS,
     "live_exec(capsule, sql, params) -> (changes, lastrowid, replayed,"
     " returning)"},
    {"live_savepoint", zx_live_savepoint, METH_VARARGS,
     "live_savepoint(capsule, index)"},
    {"live_release_savepoint", zx_live_release_savepoint, METH_VARARGS,
     "live_release_savepoint(capsule, index)"},
    {"live_rollback_to_savepoint", zx_live_rollback_to_savepoint,
     METH_VARARGS, "live_rollback_to_savepoint(capsule, index)"},
    {"live_commit", zx_live_commit, METH_VARARGS,
     "live_commit(capsule) -> changes"},
    {"live_rollback", zx_live_rollback, METH_VARARGS,
     "live_rollback(capsule)"},
    {"live_active", zx_live_active, METH_VARARGS,
     "live_active(capsule) -> bool"},
    {"statement_parameter_name", zx_statement_parameter_name, METH_VARARGS,
     "statement_parameter_name(capsule, sql, index) -> str"},
    {NULL, NULL, 0, NULL},
};

static int
zx_module_exec(PyObject *module)
{
    ZxError = PyErr_NewExceptionWithDoc(
        "zxlite._zxlite._ZxError",
        "Native zaxonlite error carrying code, category, and message.",
        NULL, NULL);
    if (ZxError == NULL) {
        return -1;
    }
    if (PyModule_AddObjectRef(module, "_ZxError", ZxError) < 0) {
        return -1;
    }
    return 0;
}

static PyModuleDef_Slot zx_slots[] = {
    {Py_mod_exec, zx_module_exec},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL},
};

static struct PyModuleDef zx_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "zxlite._zxlite",
    .m_doc = "Thin native binding over the zaxonlite C ABI.",
    .m_size = 0,
    .m_methods = zx_methods,
    .m_slots = zx_slots,
};

PyMODINIT_FUNC
PyInit__zxlite(void)
{
    return PyModuleDef_Init(&zx_module);
}
