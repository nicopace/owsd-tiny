#include <stdbool.h>

typedef struct DBusMessage DBusMessage;
struct blob_buf;

bool check_reply_and_make_error(DBusMessage *reply, const char *expected_signature, struct blob_buf *errordata);
