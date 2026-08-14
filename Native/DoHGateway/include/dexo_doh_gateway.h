#ifndef DEXO_DOH_GATEWAY_H
#define DEXO_DOH_GATEWAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Starts (or restarts) the loopback HTTP gateway.
///
/// `doh_url` must be a NUL-terminated HTTPS DoH endpoint such as
/// `https://cloudflare-dns.com/dns-query`. `preferred_port` of 0 binds an
/// ephemeral port on 127.0.0.1.
///
/// Returns the bound TCP port on success. Negative values are errors:
/// -1 invalid DoH URL, -2 bind/listen failed, -3 internal error.
int32_t dexo_doh_gateway_start(const char *doh_url, uint16_t preferred_port);

/// Stops the gateway if it is running. Safe to call when already stopped.
void dexo_doh_gateway_stop(void);

/// Bound loopback port, or 0 when the gateway is not running.
int32_t dexo_doh_gateway_port(void);

/// 1 when the accept loop is running, otherwise 0.
int32_t dexo_doh_gateway_is_running(void);

/// NUL-terminated last start failure, or an empty string. Valid until the
/// next `dexo_doh_gateway_start` call.
const char *dexo_doh_gateway_last_error(void);

/// 1 when this static library was built with Encrypted Client Hello
/// (`--features ech` / aws-lc-rs). 0 means visible SNI only.
int32_t dexo_doh_gateway_ech_compiled(void);

#ifdef __cplusplus
}
#endif

#endif
