/**
 * Malleable - Windows HTTP Transport
 * 
 * WinHTTP-based HTTP/HTTPS client for Windows platforms.
 * This module provides actual network connectivity for malleable C2 callbacks.
 */

#ifndef MALLEABLE_HTTP_WIN_H
#define MALLEABLE_HTTP_WIN_H

#include "openmalleable.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send an HTTP request and receive response using WinHTTP
 * 
 * @param host Target host (domain or IP address)
 * @param port Target port (default: 80 for HTTP, 443 for HTTPS)
 * @param use_https Use HTTPS/TLS if true, plain HTTP if false
 * @param request Request structure to send
 * @param response Output response structure (caller must free with malleable_http_response_free)
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_http_send(
    const char* host,
    int port,
    int use_https,
    const malleable_http_request_t* request,
    malleable_http_response_t** response
);

#ifdef __cplusplus
}
#endif

#endif /* MALLEABLE_HTTP_WIN_H */
