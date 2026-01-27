/**
 * Malleable - Windows HTTP Transport Implementation
 */

#include "malleable_http_win.h"
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

/* Helper to convert ASCII to wide string */
static LPWSTR ascii_to_wide(const char* str) {
    if (!str) return NULL;
    
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;
    
    LPWSTR wstr = (LPWSTR)malloc(len * sizeof(WCHAR));
    if (!wstr) return NULL;
    
    MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
    return wstr;
}

/* Helper to convert wide string to ASCII */
static char* wide_to_ascii(LPCWSTR wstr) {
    if (!wstr) return NULL;
    
    int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len == 0) return NULL;
    
    char* str = (char*)malloc(len);
    if (!str) return NULL;
    
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);
    return str;
}

malleable_error_t malleable_http_send(
    const char* host,
    int port,
    int use_https,
    const malleable_http_request_t* request,
    malleable_http_response_t** response
) {
    if (!host || !request || !response) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    malleable_error_t result = MALLEABLE_ERROR_TRANSFORM_FAILED;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    LPWSTR whost = NULL;
    LPWSTR wuri = NULL;
    LPWSTR wmethod = NULL;
    LPWSTR wheaders = NULL;
    
    // Initialize WinHTTP
    whost = ascii_to_wide(host);
    wuri = ascii_to_wide(request->uri);
    wmethod = ascii_to_wide(request->method);
    
    if (!whost || !wuri || !wmethod) {
        result = MALLEABLE_ERROR_MEMORY;
        goto cleanup;
    }
    
    // Create session
    hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (!hSession) {
        goto cleanup;
    }
    
    // Set timeouts (30 seconds)
    WinHttpSetTimeouts(hSession, 30000, 30000, 30000, 30000);
    
    // Connect to server
    hConnect = WinHttpConnect(
        hSession,
        whost,
        (INTERNET_PORT)port,
        0
    );
    
    if (!hConnect) {
        goto cleanup;
    }
    
    // Open request
    DWORD dwFlags = (use_https ? WINHTTP_FLAG_SECURE : 0);
    
    hRequest = WinHttpOpenRequest(
        hConnect,
        wmethod,
        wuri,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags
    );
    
    if (!hRequest) {
        goto cleanup;
    }
    
    // Disable SSL certificate validation for testing (REMOVE IN PRODUCTION!)
    if (use_https) {
        DWORD dwSecurityFlags = 
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        
        WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &dwSecurityFlags,
            sizeof(dwSecurityFlags)
        );
    }
    
    // Build headers string
    size_t headers_len = 0;
    for (size_t i = 0; i < request->num_headers; i++) {
        headers_len += strlen(request->headers[i]) + 2; // +2 for \r\n
    }
    
    char* headers_str = NULL;
    if (headers_len > 0) {
        headers_str = (char*)malloc(headers_len + 1);
        if (!headers_str) {
            result = MALLEABLE_ERROR_MEMORY;
            goto cleanup;
        }
        
        headers_str[0] = '\0';
        for (size_t i = 0; i < request->num_headers; i++) {
            strcat_s(headers_str, headers_len + 1, request->headers[i]);
            strcat_s(headers_str, headers_len + 1, "\r\n");
        }
        
        wheaders = ascii_to_wide(headers_str);
        free(headers_str);
        
        if (!wheaders) {
            result = MALLEABLE_ERROR_MEMORY;
            goto cleanup;
        }
    }
    
    // Send request
    BOOL bResult = WinHttpSendRequest(
        hRequest,
        wheaders ? wheaders : WINHTTP_NO_ADDITIONAL_HEADERS,
        wheaders ? -1L : 0,
        (LPVOID)request->body,
        (DWORD)request->body_len,
        (DWORD)request->body_len,
        0
    );
    
    if (!bResult) {
        goto cleanup;
    }
    
    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult) {
        goto cleanup;
    }
    
    // Allocate response structure
    malleable_http_response_t* resp = (malleable_http_response_t*)calloc(1, sizeof(malleable_http_response_t));
    if (!resp) {
        result = MALLEABLE_ERROR_MEMORY;
        goto cleanup;
    }
    
    // Get status code
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(DWORD);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &dwStatusCode,
        &dwSize,
        NULL
    );
    resp->status_code = (int)dwStatusCode;
    
    // Get response headers
    dwSize = 0;
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        NULL,
        NULL,
        &dwSize,
        NULL
    );
    
    if (dwSize > 0) {
        LPWSTR wresponse_headers = (LPWSTR)malloc(dwSize);
        if (wresponse_headers) {
            if (WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                NULL,
                wresponse_headers,
                &dwSize,
                NULL
            )) {
                char* response_headers = wide_to_ascii(wresponse_headers);
                if (response_headers) {
                    // Parse headers into array
                    char* context = NULL;
                    char* line = strtok_s(response_headers, "\r\n", &context);
                    while (line) {
                        if (strlen(line) > 0 && strchr(line, ':')) {
                            resp->num_headers++;
                            resp->headers = (char**)realloc(resp->headers, resp->num_headers * sizeof(char*));
                            if (resp->headers) {
                                resp->headers[resp->num_headers - 1] = _strdup(line);
                            }
                        }
                        line = strtok_s(NULL, "\r\n", &context);
                    }
                    free(response_headers);
                }
            }
            free(wresponse_headers);
        }
    }
    
    // Read response body
    DWORD dwTotalSize = 0;
    DWORD dwDownloaded = 0;
    BYTE* pBuffer = NULL;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            break;
        }
        
        if (dwSize == 0) {
            break;
        }
        
        pBuffer = (BYTE*)realloc(resp->body, dwTotalSize + dwSize);
        if (!pBuffer) {
            result = MALLEABLE_ERROR_MEMORY;
            malleable_http_response_free(resp);
            goto cleanup;
        }
        resp->body = pBuffer;
        
        if (!WinHttpReadData(hRequest, resp->body + dwTotalSize, dwSize, &dwDownloaded)) {
            break;
        }
        
        dwTotalSize += dwDownloaded;
        
    } while (dwSize > 0);
    
    resp->body_len = dwTotalSize;
    
    *response = resp;
    result = MALLEABLE_SUCCESS;
    
cleanup:
    if (wheaders) free(wheaders);
    if (wmethod) free(wmethod);
    if (wuri) free(wuri);
    if (whost) free(whost);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return result;
}
