// C interface of the Mailbox engine (libmailcore.a), used by the macOS helper app.
#ifndef MAILCORE_H
#define MAILCORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Called on an engine thread for every event, with a JSON object (see docs/API.md).
typedef void (*mailcore_event_cb)(void *ctx, const char *json);

/// Opens the store in `data_dir`, starts the local API (preferring `port`, 0 = default) and
/// all account workers. Returns the API port, or -1 (see mailcore_last_error).
int32_t mailcore_start(const char *data_dir, uint16_t port, mailcore_event_cb cb, void *ctx);

/// Stops workers and the API. Blocks for at most a few seconds.
void mailcore_stop(void);

/// API token of the running engine (free with mailcore_free_string), or NULL.
char *mailcore_token(void);

/// Last error message (free with mailcore_free_string), or NULL.
char *mailcore_last_error(void);

void mailcore_free_string(char *s);

/// Static version string.
const char *mailcore_version(void);

#ifdef __cplusplus
}
#endif

#endif
