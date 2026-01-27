/**
 * Malleable - Open Source Malleable C2 Profile Implementation
 * 
 * Framework-agnostic HTTP transformation library implementing Cobalt Strike's
 * Malleable C2 profile format for security research and testing.
 */

#ifndef OPENMALLEABLE_H
#define OPENMALLEABLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/*                            DATA STRUCTURES                            */
/* ===================================================================== */

/**
 * Transform types supported in malleable profiles
 */
typedef enum {
    MALLEABLE_TRANSFORM_BASE64,
    MALLEABLE_TRANSFORM_BASE64URL,
    MALLEABLE_TRANSFORM_NETBIOS,
    MALLEABLE_TRANSFORM_NETBIOSU,
    MALLEABLE_TRANSFORM_MASK,
    MALLEABLE_TRANSFORM_PREPEND,
    MALLEABLE_TRANSFORM_APPEND
} malleable_transform_type_t;

/**
 * Termination statement types
 */
typedef enum {
    MALLEABLE_TERM_HEADER,
    MALLEABLE_TERM_PARAMETER,
    MALLEABLE_TERM_PRINT,
    MALLEABLE_TERM_URI_APPEND
} malleable_termination_type_t;

/**
 * HTTP methods
 */
typedef enum {
    MALLEABLE_HTTP_GET,
    MALLEABLE_HTTP_POST
} malleable_http_method_t;

/**
 * A single transform step in a data transformation chain
 */
typedef struct {
    malleable_transform_type_t type;
    char* argument;  // For prepend/append transforms (NULL otherwise)
} malleable_transform_t;

/**
 * A termination statement (where transformed data goes)
 */
typedef struct {
    malleable_termination_type_t type;
    char* target;  // Header name, parameter key, etc.
} malleable_termination_t;

/**
 * A complete data transformation pipeline
 */
typedef struct {
    malleable_transform_t* transforms;
    size_t num_transforms;
    malleable_termination_t termination;
} malleable_transform_chain_t;

/**
 * HTTP transaction configuration (client or server side)
 */
typedef struct {
    char** headers;              // Array of header strings (NULL-terminated)
    size_t num_headers;
    char** parameters;           // Array of "key=value" strings (NULL-terminated)
    size_t num_parameters;
    malleable_transform_chain_t* metadata;   // For GET client metadata
    malleable_transform_chain_t* id;         // For POST client id
    malleable_transform_chain_t* output;     // For GET server output or POST client output
} malleable_http_config_t;

/**
 * A complete HTTP transaction definition
 */
typedef struct {
    char* variant;               // "default", "variant_1", etc.
    malleable_http_method_t method;     // GET or POST
    char** uris;                 // Array of possible URIs
    size_t num_uris;
    malleable_http_config_t client;
    malleable_http_config_t server;
} malleable_http_transaction_t;

/**
 * Complete malleable profile
 */
typedef struct {
    char* profile_name;
    char* useragent;
    char** headers_remove;
    size_t num_headers_remove;
    
    malleable_http_transaction_t* http_get_transactions;
    size_t num_http_get;
    
    malleable_http_transaction_t* http_post_transactions;
    size_t num_http_post;
} malleable_profile_t;

/**
 * HTTP request structure
 */
typedef struct {
    char* method;       // "GET", "POST", etc.
    char* uri;          // Full URI with query parameters
    char** headers;     // NULL-terminated array of "Name: Value"
    size_t num_headers;
    uint8_t* body;
    size_t body_len;
} malleable_http_request_t;

/**
 * HTTP response structure
 */
typedef struct {
    int status_code;
    char** headers;
    size_t num_headers;
    uint8_t* body;
    size_t body_len;
} malleable_http_response_t;

/**
 * Error codes
 */
typedef enum {
    MALLEABLE_SUCCESS = 0,
    MALLEABLE_ERROR_INVALID_PROFILE = -1,
    MALLEABLE_ERROR_PARSE_FAILED = -2,
    MALLEABLE_ERROR_INVALID_VARIANT = -3,
    MALLEABLE_ERROR_TRANSFORM_FAILED = -4,
    MALLEABLE_ERROR_MEMORY = -5,
    MALLEABLE_ERROR_NOT_FOUND = -6
} malleable_error_t;

/* ===================================================================== */
/*                            PROFILE PARSING                            */
/* ===================================================================== */

/**
 * Parse a malleable profile from memory (string buffer)
 * This is the primary way to load profiles. If you need to load from a file,
 * read the file into a string first and pass it to this function.
 * 
 * @param profile_str Profile content as null-terminated string
 * @return Profile structure or NULL on error
 * 
 * @example Loading from embedded string:
 *   const char* profile = "set sample_name \"test\"; ...";
 *   malleable_profile_t* p = malleable_profile_parse(profile);
 * 
 * @example Loading from file (user-managed):
 *   char* content = read_file("config.profile");
 *   malleable_profile_t* p = malleable_profile_parse(content);
 *   free(content);
 */
malleable_profile_t* malleable_profile_parse(const char* profile_str);

/**
 * Free a profile structure
 * @param profile Profile to free
 */
void malleable_profile_free(malleable_profile_t* profile);

/* ===================================================================== */
/*                         TRANSFORMATION ENGINE                         */
/* ===================================================================== */

/**
 * Apply a transformation chain to data (forward transform - client side)
 * @param chain Transform chain to apply
 * @param input Input data
 * @param input_len Input data length
 * @param output Output buffer (allocated by function, caller must free)
 * @param output_len Output data length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_transform_apply(
    const malleable_transform_chain_t* chain,
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
);

/**
 * Reverse a transformation chain (server side extraction)
 * @param chain Transform chain to reverse
 * @param input Transformed data
 * @param input_len Transformed data length
 * @param output Original data (allocated by function, caller must free)
 * @param output_len Original data length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_transform_reverse(
    const malleable_transform_chain_t* chain,
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
);

/* ===================================================================== */
/*                         HTTP REQUEST BUILDING                         */
/* ===================================================================== */

/**
 * Build an HTTP GET request (beacon metadata check-in)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param metadata Raw metadata to send
 * @param metadata_len Metadata length
 * @param request Output request structure (caller must free with malleable_http_request_free)
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_build_get_request(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* metadata,
    size_t metadata_len,
    malleable_http_request_t** request
);

/**
 * Build an HTTP POST request (beacon output submission)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param session_id Session identifier
 * @param id_len Session ID length
 * @param output Response data to send
 * @param output_len Output data length
 * @param request Output request structure (caller must free with malleable_http_request_free)
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_build_post_request(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* session_id,
    size_t id_len,
    const uint8_t* output,
    size_t output_len,
    malleable_http_request_t** request
);

/**
 * Parse server response from GET request (extract tasks)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param response HTTP response
 * @param data_out Extracted data (caller must free)
 * @param data_len_out Extracted data length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_parse_get_response(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_response_t* response,
    uint8_t** data_out,
    size_t* data_len_out
);

/**
 * Extract metadata from HTTP GET request (server side)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param request HTTP request
 * @param metadata_out Extracted metadata (caller must free)
 * @param metadata_len_out Extracted metadata length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_extract_metadata(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** metadata_out,
    size_t* metadata_len_out
);

/**
 * Extract session ID from HTTP POST request (server side)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param request HTTP request
 * @param id_out Extracted session ID (caller must free)
 * @param id_len_out Extracted ID length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_extract_session_id(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** id_out,
    size_t* id_len_out
);

/**
 * Extract output from HTTP POST request (server side)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param request HTTP request
 * @param output_out Extracted output (caller must free)
 * @param output_len_out Extracted output length
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_extract_output(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** output_out,
    size_t* output_len_out
);

/**
 * Build HTTP response with tasks (server response to GET)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param data Task data to send
 * @param data_len Task data length
 * @param response Output response structure (caller must free with malleable_http_response_free)
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_build_get_response(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* data,
    size_t data_len,
    malleable_http_response_t** response
);

/**
 * Build HTTP response for POST (server response to POST)
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param data Optional response data
 * @param data_len Response data length
 * @param response Output response structure (caller must free with malleable_http_response_free)
 * @return MALLEABLE_SUCCESS or error code
 */
malleable_error_t malleable_build_post_response(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* data,
    size_t data_len,
    malleable_http_response_t** response
);

/* ===================================================================== */
/*                            MEMORY MANAGEMENT                          */
/* ===================================================================== */

/**
 * Free an HTTP request structure
 * @param request Request to free
 */
void malleable_http_request_free(malleable_http_request_t* request);

/**
 * Free an HTTP response structure
 * @param response Response to free
 */
void malleable_http_response_free(malleable_http_response_t* response);

/* ===================================================================== */
/*                            UTILITY FUNCTIONS                          */
/* ===================================================================== */

/**
 * Get error message for error code
 * @param error Error code
 * @return Error message string
 */
const char* malleable_error_string(malleable_error_t error);

/**
 * Find transaction by variant name
 * @param transactions Array of transactions
 * @param num_transactions Number of transactions
 * @param variant Variant name (NULL for "default")
 * @return Pointer to transaction or NULL if not found
 */
malleable_http_transaction_t* malleable_find_transaction(
    malleable_http_transaction_t* transactions,
    size_t num_transactions,
    const char* variant
);

/* ===================================================================== */
/*                         TRANSPARENT CALLBACK API                      */
/* ===================================================================== */

/**
 * Perform a complete GET callback (check-in with metadata, receive tasks)
 * 
 * This is a high-level function that:
 * 1. Builds an HTTP GET request with transformed metadata
 * 2. Sends the request to the server
 * 3. Receives and parses the response
 * 4. Extracts and returns the server's task data
 * 
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param host Target host (domain or IP)
 * @param port Target port (0 for default: 80 for HTTP, 443 for HTTPS)
 * @param use_https Use HTTPS/TLS if non-zero
 * @param metadata Raw metadata to send
 * @param metadata_len Metadata length
 * @param tasks_out Extracted task data (caller must free)
 * @param tasks_len_out Task data length
 * @return MALLEABLE_SUCCESS or error code
 * 
 * Note: Requires WinHTTP on Windows. Link with malleable_http_win.c
 */
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
);

/**
 * Perform a complete POST callback (submit output data)
 * 
 * This is a high-level function that:
 * 1. Builds an HTTP POST request with transformed session ID and output
 * 2. Sends the request to the server
 * 3. Receives and parses the response
 * 4. Optionally extracts server response data
 * 
 * @param profile Malleable profile
 * @param variant Transaction variant (NULL for "default")
 * @param host Target host (domain or IP)
 * @param port Target port (0 for default: 80 for HTTP, 443 for HTTPS)
 * @param use_https Use HTTPS/TLS if non-zero
 * @param session_id Session identifier
 * @param id_len Session ID length
 * @param output Output data to send
 * @param output_len Output data length
 * @param response_out Optional server response data (caller must free, can be NULL)
 * @param response_len_out Optional server response length (can be NULL)
 * @return MALLEABLE_SUCCESS or error code
 * 
 * Note: Requires WinHTTP on Windows. Link with malleable_http_win.c
 */
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
);

#ifdef __cplusplus
}
#endif

#endif /* OPENMALLEABLE_H */
