/**
 * Malleable - Implementation
 */

#include "openmalleable.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* Avoid unused parameter warnings in stub functions */
#define MALLEABLE_UNUSED(x) (void)(x)

/* ===================================================================== */
/*                         INTERNAL UTILITIES                            */
/* ===================================================================== */

static void* malleable_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr && size > 0) {
        fprintf(stderr, "Malleable: Memory allocation failed\n");
    }
    return ptr;
}

static void* malleable_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        fprintf(stderr, "Malleable: Memory reallocation failed\n");
    }
    return new_ptr;
}

static char* malleable_strdup(const char* str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char* dup = (char*)malleable_malloc(len + 1);
    if (dup) {
        memcpy(dup, str, len + 1);
    }
    return dup;
}

static int malleable_strncasecmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca == '\0' || cb == '\0') {
            return tolower(ca) - tolower(cb);
        }
        int diff = tolower(ca) - tolower(cb);
        if (diff != 0) return diff;
    }
    return 0;
}

static char* trim_in_place(char* s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char* end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    *end = '\0';
    return s;
}

/* ===================================================================== */
/*                      BASE64 ENCODING/DECODING                         */
/* ===================================================================== */

static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char base64url_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int base64_decode_char(char c) {
    // Handle both standard base64 and URL-safe base64
    if (c == '=') return -1;  // Padding
    
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    
    // Standard base64: + and /
    if (c == '+') return 62;
    if (c == '/') return 63;
    
    // URL-safe base64: - and _
    if (c == '-') return 62;
    if (c == '_') return 63;
    
    return -2;  // Invalid character
}

static malleable_error_t base64_encode_impl(
    const uint8_t* input, 
    size_t input_len,
    uint8_t** output,
    size_t* output_len,
    const char* table,
    int padding
) {
    if (input_len == 0) {
        *output = (uint8_t*)malleable_malloc(1);
        if (!*output) return MALLEABLE_ERROR_MEMORY;
        (*output)[0] = '\0';
        *output_len = 0;
        return MALLEABLE_SUCCESS;
    }
    
    size_t encoded_len = ((input_len + 2) / 3) * 4;
    *output = (uint8_t*)malleable_malloc(encoded_len + 1);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    size_t j = 0;
    
    for (size_t i = 0; i < input_len; i += 3) {
        uint32_t octet_a = input[i];
        uint32_t octet_b = (i + 1 < input_len) ? input[i + 1] : 0;
        uint32_t octet_c = (i + 2 < input_len) ? input[i + 2] : 0;
        
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        // First two characters are always output
        (*output)[j++] = table[(triple >> 18) & 0x3F];
        (*output)[j++] = table[(triple >> 12) & 0x3F];
        
        // Third character: output if we had at least 2 input bytes, or padding
        if (i + 1 < input_len) {
            (*output)[j++] = table[(triple >> 6) & 0x3F];
        } else if (padding) {
            (*output)[j++] = '=';
        }
        
        // Fourth character: output if we had all 3 input bytes, or padding
        if (i + 2 < input_len) {
            (*output)[j++] = table[triple & 0x3F];
        } else if (padding) {
            (*output)[j++] = '=';
        }
    }
    
    (*output)[j] = '\0';
    *output_len = j;
    return MALLEABLE_SUCCESS;
}

static malleable_error_t base64_decode_impl(
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
) {
    if (input_len == 0) {
        *output = (uint8_t*)malleable_malloc(1);
        if (!*output) return MALLEABLE_ERROR_MEMORY;
        (*output)[0] = '\0';
        *output_len = 0;
        return MALLEABLE_SUCCESS;
    }
    
    // Calculate max decoded length (may be less due to padding)
    size_t decoded_len = ((input_len + 3) / 4) * 3;
    *output = (uint8_t*)malleable_malloc(decoded_len + 1);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    size_t j = 0;
    size_t i = 0;
    
    while (i < input_len) {
        uint32_t sextet[4] = {0, 0, 0, 0};
        int valid_count = 0;
        
        // Read up to 4 base64 characters
        for (int k = 0; k < 4 && i < input_len; k++) {
            char c = (char)input[i++];
            
            // Skip whitespace
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                k--;
                continue;
            }
            
            int val = base64_decode_char(c);
            
            if (val == -1) {
                // Padding character '=', stop collecting
                continue;
            }
            
            if (val == -2) {
                // Invalid character, skip it
                k--;
                continue;
            }
            
            sextet[valid_count++] = (uint32_t)val;
        }
        
        // Decode based on how many valid characters we got
        if (valid_count >= 2) {
            uint32_t triple = (sextet[0] << 18) | (sextet[1] << 12) | (sextet[2] << 6) | sextet[3];
            
            (*output)[j++] = (triple >> 16) & 0xFF;
            
            if (valid_count >= 3) {
                (*output)[j++] = (triple >> 8) & 0xFF;
            }
            
            if (valid_count >= 4) {
                (*output)[j++] = triple & 0xFF;
            }
        }
    }
    
    (*output)[j] = '\0';
    *output_len = j;
    return MALLEABLE_SUCCESS;
}

/* ===================================================================== */
/*                      NETBIOS ENCODING/DECODING                        */
/* ===================================================================== */

static malleable_error_t netbios_encode(
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len,
    char base_char
) {
    *output_len = input_len * 2;
    *output = (uint8_t*)malleable_malloc(*output_len + 1);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    for (size_t i = 0; i < input_len; i++) {
        (*output)[i * 2] = base_char + (input[i] >> 4);
        (*output)[i * 2 + 1] = base_char + (input[i] & 0x0F);
    }
    (*output)[*output_len] = '\0';
    
    return MALLEABLE_SUCCESS;
}

static malleable_error_t netbios_decode(
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len,
    char base_char
) {
    if (input_len % 2 != 0) {
        return MALLEABLE_ERROR_TRANSFORM_FAILED;
    }
    
    *output_len = input_len / 2;
    *output = (uint8_t*)malleable_malloc(*output_len + 1);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    for (size_t i = 0; i < *output_len; i++) {
        uint8_t high = input[i * 2] - base_char;
        uint8_t low = input[i * 2 + 1] - base_char;
        (*output)[i] = (high << 4) | low;
    }
    (*output)[*output_len] = '\0';
    
    return MALLEABLE_SUCCESS;
}

/* ===================================================================== */
/*                         MASK (XOR) TRANSFORM                          */
/* ===================================================================== */

static malleable_error_t mask_encode(
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
) {
    // Generate random 4-byte key
    uint8_t key[4];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 4; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
    
    // Output is key + masked data
    *output_len = 4 + input_len;
    *output = (uint8_t*)malleable_malloc(*output_len);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    // Prepend key
    memcpy(*output, key, 4);
    
    // XOR data with key
    for (size_t i = 0; i < input_len; i++) {
        (*output)[4 + i] = input[i] ^ key[i % 4];
    }
    
    return MALLEABLE_SUCCESS;
}

static malleable_error_t mask_decode(
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
) {
    if (input_len < 4) {
        return MALLEABLE_ERROR_TRANSFORM_FAILED;
    }
    
    // Extract key from first 4 bytes
    const uint8_t* key = input;
    const uint8_t* data = input + 4;
    *output_len = input_len - 4;
    
    *output = (uint8_t*)malleable_malloc(*output_len);
    if (!*output) return MALLEABLE_ERROR_MEMORY;
    
    // XOR data with key
    for (size_t i = 0; i < *output_len; i++) {
        (*output)[i] = data[i] ^ key[i % 4];
    }
    
    return MALLEABLE_SUCCESS;
}

/* ===================================================================== */
/*                      TRANSFORMATION ENGINE                            */
/* ===================================================================== */

malleable_error_t malleable_transform_apply(
    const malleable_transform_chain_t* chain,
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
) {
    if (!chain || !input || !output || !output_len) {
        return MALLEABLE_ERROR_TRANSFORM_FAILED;
    }
    
    // Start with a copy of input
    uint8_t* current = (uint8_t*)malleable_malloc(input_len);
    if (!current) return MALLEABLE_ERROR_MEMORY;
    memcpy(current, input, input_len);
    size_t current_len = input_len;
    
    // Apply each transform in sequence
    for (size_t i = 0; i < chain->num_transforms; i++) {
        malleable_transform_t* t = &chain->transforms[i];
        uint8_t* next = NULL;
        size_t next_len = 0;
        malleable_error_t err = MALLEABLE_SUCCESS;
        
        switch (t->type) {
            case MALLEABLE_TRANSFORM_BASE64:
                err = base64_encode_impl(current, current_len, &next, &next_len, 
                                        base64_table, 1);
                break;
                
            case MALLEABLE_TRANSFORM_BASE64URL:
                err = base64_encode_impl(current, current_len, &next, &next_len,
                                        base64url_table, 0);
                break;
                
            case MALLEABLE_TRANSFORM_NETBIOS:
                err = netbios_encode(current, current_len, &next, &next_len, 'a');
                break;
                
            case MALLEABLE_TRANSFORM_NETBIOSU:
                err = netbios_encode(current, current_len, &next, &next_len, 'A');
                break;
                
            case MALLEABLE_TRANSFORM_MASK:
                err = mask_encode(current, current_len, &next, &next_len);
                break;
                
            case MALLEABLE_TRANSFORM_PREPEND:
                if (t->argument) {
                    size_t arg_len = strlen(t->argument);
                    next_len = arg_len + current_len;
                    next = (uint8_t*)malleable_malloc(next_len);
                    if (!next) err = MALLEABLE_ERROR_MEMORY;
                    else {
                        memcpy(next, t->argument, arg_len);
                        memcpy(next + arg_len, current, current_len);
                    }
                }
                break;
                
            case MALLEABLE_TRANSFORM_APPEND:
                if (t->argument) {
                    size_t arg_len = strlen(t->argument);
                    next_len = current_len + arg_len;
                    next = (uint8_t*)malleable_malloc(next_len);
                    if (!next) err = MALLEABLE_ERROR_MEMORY;
                    else {
                        memcpy(next, current, current_len);
                        memcpy(next + current_len, t->argument, arg_len);
                    }
                }
                break;
        }
        
        free(current);
        
        if (err != MALLEABLE_SUCCESS) {
            if (next) free(next);
            return err;
        }
        
        current = next;
        current_len = next_len;
    }
    
    *output = current;
    *output_len = current_len;
    return MALLEABLE_SUCCESS;
}

malleable_error_t malleable_transform_reverse(
    const malleable_transform_chain_t* chain,
    const uint8_t* input,
    size_t input_len,
    uint8_t** output,
    size_t* output_len
) {
    if (!chain || !input || !output || !output_len) {
        return MALLEABLE_ERROR_TRANSFORM_FAILED;
    }
    
    // Start with a copy of input
    uint8_t* current = (uint8_t*)malleable_malloc(input_len + 1);
    if (!current) return MALLEABLE_ERROR_MEMORY;
    memcpy(current, input, input_len);
    current[input_len] = '\0';
    size_t current_len = input_len;
    
    // Apply transforms in REVERSE order
    for (int i = (int)chain->num_transforms - 1; i >= 0; i--) {
        malleable_transform_t* t = &chain->transforms[i];
        uint8_t* next = NULL;
        size_t next_len = 0;
        malleable_error_t err = MALLEABLE_SUCCESS;
        
        switch (t->type) {
            case MALLEABLE_TRANSFORM_BASE64:
                err = base64_decode_impl(current, current_len, &next, &next_len);
                break;
                
            case MALLEABLE_TRANSFORM_BASE64URL:
                err = base64_decode_impl(current, current_len, &next, &next_len);
                break;
                
            case MALLEABLE_TRANSFORM_NETBIOS:
                err = netbios_decode(current, current_len, &next, &next_len, 'a');
                break;
                
            case MALLEABLE_TRANSFORM_NETBIOSU:
                err = netbios_decode(current, current_len, &next, &next_len, 'A');
                break;
                
            case MALLEABLE_TRANSFORM_MASK:
                err = mask_decode(current, current_len, &next, &next_len);
                break;
                
            case MALLEABLE_TRANSFORM_PREPEND:
                // Reverse: remove first N characters
                if (t->argument) {
                    size_t arg_len = strlen(t->argument);
                    if (current_len < arg_len) {
                        err = MALLEABLE_ERROR_TRANSFORM_FAILED;
                    } else {
                        next_len = current_len - arg_len;
                        next = (uint8_t*)malleable_malloc(next_len);
                        if (!next) err = MALLEABLE_ERROR_MEMORY;
                        else memcpy(next, current + arg_len, next_len);
                    }
                }
                break;
                
            case MALLEABLE_TRANSFORM_APPEND:
                // Reverse: remove last N characters
                if (t->argument) {
                    size_t arg_len = strlen(t->argument);
                    if (current_len < arg_len) {
                        err = MALLEABLE_ERROR_TRANSFORM_FAILED;
                    } else {
                        next_len = current_len - arg_len;
                        next = (uint8_t*)malleable_malloc(next_len);
                        if (!next) err = MALLEABLE_ERROR_MEMORY;
                        else memcpy(next, current, next_len);
                    }
                }
                break;
        }
        
        free(current);
        
        if (err != MALLEABLE_SUCCESS) {
            if (next) free(next);
            return err;
        }
        
        current = next;
        current_len = next_len;
    }
    
    *output = current;
    *output_len = current_len;
    return MALLEABLE_SUCCESS;
}

/* ===================================================================== */
/*                            PROFILE PARSER                             */
/* ===================================================================== */

typedef struct {
    const char* input;
    size_t pos;
    size_t len;
} malleable_parser_t;

static void skip_whitespace(malleable_parser_t* p) {
    while (p->pos < p->len && isspace((unsigned char)p->input[p->pos])) {
        p->pos++;
    }
}

static void skip_comments(malleable_parser_t* p) {
    while (p->pos < p->len) {
        skip_whitespace(p);
        if (p->pos < p->len && p->input[p->pos] == '#') {
            // Skip until end of line
            while (p->pos < p->len && p->input[p->pos] != '\n') {
                p->pos++;
            }
        } else {
            break;
        }
    }
}

static int peek_char(malleable_parser_t* p) {
    skip_comments(p);
    return (p->pos < p->len) ? p->input[p->pos] : EOF;
}

static int next_char(malleable_parser_t* p) {
    skip_comments(p);
    return (p->pos < p->len) ? p->input[p->pos++] : EOF;
}

static int match_keyword(malleable_parser_t* p, const char* keyword) {
    skip_comments(p);
    size_t kw_len = strlen(keyword);
    if (p->pos + kw_len <= p->len && 
        strncmp(p->input + p->pos, keyword, kw_len) == 0) {
        // Check that it's followed by whitespace or delimiter
        if (p->pos + kw_len == p->len || 
            isspace((unsigned char)p->input[p->pos + kw_len]) ||
            p->input[p->pos + kw_len] == '{' ||
            p->input[p->pos + kw_len] == ';') {
            p->pos += kw_len;
            return 1;
        }
    }
    return 0;
}

static char* parse_string(malleable_parser_t* p) {
    skip_comments(p);
    
    if (peek_char(p) != '"') return NULL;
    next_char(p);  // Skip opening quote
    
    size_t capacity = 64;
    size_t len = 0;
    char* str = (char*)malleable_malloc(capacity);
    if (!str) return NULL;
    
    while (p->pos < p->len && p->input[p->pos] != '"') {
        char c = p->input[p->pos++];
        
        // Handle escape sequences
        if (c == '\\' && p->pos < p->len) {
            char next = p->input[p->pos++];
            switch (next) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case '\\': c = '\\'; break;
                case '"': c = '"'; break;
                case 'x': {
                    // Hex byte \xNN
                    if (p->pos + 1 < p->len) {
                        char hex[3] = {p->input[p->pos], p->input[p->pos + 1], 0};
                        c = (char)strtol(hex, NULL, 16);
                        p->pos += 2;
                    }
                    break;
                }
                case 'u': {
                    // Unicode \u#### (encode as UTF-8)
                    if (p->pos + 3 < p->len) {
                        char hex[5] = {
                            p->input[p->pos],
                            p->input[p->pos + 1],
                            p->input[p->pos + 2],
                            p->input[p->pos + 3],
                            0
                        };
                        unsigned int codepoint = (unsigned int)strtoul(hex, NULL, 16);
                        p->pos += 4;

                        // Encode codepoint as UTF-8
                        if (codepoint <= 0x7F) {
                            c = (char)codepoint;
                        } else {
                            char utf8[4] = {0};
                            int utf8_len = 0;

                            if (codepoint <= 0x7FF) {
                                utf8[0] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
                                utf8[1] = (char)(0x80 | (codepoint & 0x3F));
                                utf8_len = 2;
                            } else {
                                utf8[0] = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
                                utf8[1] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                                utf8[2] = (char)(0x80 | (codepoint & 0x3F));
                                utf8_len = 3;
                            }

                            if (len + utf8_len >= capacity) {
                                while (len + utf8_len >= capacity) {
                                    capacity *= 2;
                                }
                                str = (char*)malleable_realloc(str, capacity);
                                if (!str) return NULL;
                            }

                            memcpy(str + len, utf8, utf8_len);
                            len += utf8_len;
                            continue;
                        }
                    }
                    break;
                }
                default: c = next; break;
            }
        }
        
        if (len + 1 >= capacity) {
            capacity *= 2;
            str = (char*)malleable_realloc(str, capacity);
            if (!str) return NULL;
        }
        str[len++] = c;
    }
    
    if (p->pos < p->len && p->input[p->pos] == '"') {
        p->pos++;  // Skip closing quote
    }
    
    str[len] = '\0';
    return str;
}

static malleable_transform_type_t parse_transform_type(const char* name) {
    if (strcmp(name, "base64") == 0) return MALLEABLE_TRANSFORM_BASE64;
    if (strcmp(name, "base64url") == 0) return MALLEABLE_TRANSFORM_BASE64URL;
    if (strcmp(name, "netbios") == 0) return MALLEABLE_TRANSFORM_NETBIOS;
    if (strcmp(name, "netbiosu") == 0) return MALLEABLE_TRANSFORM_NETBIOSU;
    if (strcmp(name, "mask") == 0) return MALLEABLE_TRANSFORM_MASK;
    if (strcmp(name, "prepend") == 0) return MALLEABLE_TRANSFORM_PREPEND;
    if (strcmp(name, "append") == 0) return MALLEABLE_TRANSFORM_APPEND;
    return -1;
}

static malleable_termination_type_t parse_termination_type(const char* name) {
    if (strcmp(name, "header") == 0) return MALLEABLE_TERM_HEADER;
    if (strcmp(name, "parameter") == 0) return MALLEABLE_TERM_PARAMETER;
    if (strcmp(name, "print") == 0) return MALLEABLE_TERM_PRINT;
    if (strcmp(name, "uri-append") == 0) return MALLEABLE_TERM_URI_APPEND;
    return -1;
}

static malleable_transform_chain_t* parse_transform_chain(malleable_parser_t* p) {
    malleable_transform_chain_t* chain = (malleable_transform_chain_t*)malleable_malloc(sizeof(malleable_transform_chain_t));
    if (!chain) return NULL;
    
    memset(chain, 0, sizeof(malleable_transform_chain_t));
    
    size_t capacity = 8;
    chain->transforms = (malleable_transform_t*)malleable_malloc(sizeof(malleable_transform_t) * capacity);
    if (!chain->transforms) {
        free(chain);
        return NULL;
    }
    
    while (peek_char(p) != '}' && peek_char(p) != EOF) {
        // Try to match known transform keywords
        malleable_transform_t transform = {0};
        char* keyword = NULL;
        
        // Read identifier
        skip_comments(p);
        size_t start = p->pos;
        while (p->pos < p->len && (isalnum((unsigned char)p->input[p->pos]) || 
               p->input[p->pos] == '_' || p->input[p->pos] == '-')) {
            p->pos++;
        }
        
        if (p->pos > start) {
            size_t kw_len = p->pos - start;
            keyword = (char*)malleable_malloc(kw_len + 1);
            if (keyword) {
                memcpy(keyword, p->input + start, kw_len);
                keyword[kw_len] = '\0';
            }
        }
        
        if (!keyword) break;
        
        // Check if it's a transform
        int transform_type = parse_transform_type(keyword);
        if (transform_type >= 0) {
            transform.type = transform_type;
            
            // Some transforms take arguments
            if (transform.type == MALLEABLE_TRANSFORM_PREPEND || 
                transform.type == MALLEABLE_TRANSFORM_APPEND) {
                transform.argument = parse_string(p);
            }
            
            // Expect semicolon
            skip_comments(p);
            if (peek_char(p) == ';') next_char(p);
            
            // Add to chain
            if (chain->num_transforms >= capacity) {
                capacity *= 2;
                chain->transforms = (malleable_transform_t*)malleable_realloc(
                    chain->transforms, sizeof(malleable_transform_t) * capacity);
            }
            chain->transforms[chain->num_transforms++] = transform;
            free(keyword);
            continue;
        }
        
        // Check if it's a termination statement
        int term_type = parse_termination_type(keyword);
        if (term_type >= 0) {
            chain->termination.type = term_type;
            chain->termination.target = parse_string(p);
            
            // Expect semicolon
            skip_comments(p);
            if (peek_char(p) == ';') next_char(p);
            
            free(keyword);
            break;  // Termination ends the chain
        }
        
        free(keyword);
        break;
    }
    
    return chain;
}

static int parse_http_config_block(malleable_parser_t* p, malleable_http_config_t* config, const char* block_name) {
    if (!match_keyword(p, block_name)) return 0;
    
    skip_comments(p);
    if (peek_char(p) != '{') return 0;
    next_char(p);
    
    while (peek_char(p) != '}' && peek_char(p) != EOF) {
        if (match_keyword(p, "header")) {
            char* name = parse_string(p);
            char* value = parse_string(p);
            if (name && value) {
                // Store as "Name: Value"
                size_t len = strlen(name) + strlen(value) + 3;
                char* header = (char*)malleable_malloc(len);
                if (header) {
                    snprintf(header, len, "%s: %s", name, value);
                    config->headers = (char**)malleable_realloc(config->headers, 
                                        sizeof(char*) * (config->num_headers + 1));
                    config->headers[config->num_headers++] = header;
                }
                free(name);
                free(value);
            }
            skip_comments(p);
            if (peek_char(p) == ';') next_char(p);
        }
        else if (match_keyword(p, "parameter")) {
            char* key = parse_string(p);
            char* value = parse_string(p);
            if (key && value) {
                size_t len = strlen(key) + strlen(value) + 2;
                char* param = (char*)malleable_malloc(len);
                if (param) {
                    snprintf(param, len, "%s=%s", key, value);
                    config->parameters = (char**)malleable_realloc(config->parameters,
                                          sizeof(char*) * (config->num_parameters + 1));
                    config->parameters[config->num_parameters++] = param;
                }
                free(key);
                free(value);
            }
            skip_comments(p);
            if (peek_char(p) == ';') next_char(p);
        }
        else if (match_keyword(p, "metadata")) {
            skip_comments(p);
            if (peek_char(p) == '{') {
                next_char(p);
                config->metadata = parse_transform_chain(p);
                skip_comments(p);
                if (peek_char(p) == '}') next_char(p);
            }
        }
        else if (match_keyword(p, "id")) {
            skip_comments(p);
            if (peek_char(p) == '{') {
                next_char(p);
                config->id = parse_transform_chain(p);
                skip_comments(p);
                if (peek_char(p) == '}') next_char(p);
            }
        }
        else if (match_keyword(p, "output")) {
            skip_comments(p);
            if (peek_char(p) == '{') {
                next_char(p);
                config->output = parse_transform_chain(p);
                skip_comments(p);
                if (peek_char(p) == '}') next_char(p);
            }
        }
        else {
            // Skip unknown statement
            while (peek_char(p) != ';' && peek_char(p) != '}' && peek_char(p) != EOF) {
                next_char(p);
            }
            if (peek_char(p) == ';') next_char(p);
        }
    }
    
    if (peek_char(p) == '}') next_char(p);
    return 1;
}

static malleable_http_transaction_t* parse_http_transaction(malleable_parser_t* p, const char* transaction_type) {
    if (!match_keyword(p, transaction_type)) return NULL;
    
    malleable_http_transaction_t* trans = (malleable_http_transaction_t*)malleable_malloc(sizeof(malleable_http_transaction_t));
    if (!trans) return NULL;
    memset(trans, 0, sizeof(malleable_http_transaction_t));
    
    // Parse optional variant name
    skip_comments(p);
    if (peek_char(p) == '"') {
        trans->variant = parse_string(p);
    } else {
        trans->variant = malleable_strdup("default");
    }
    
    // Set method
    if (strcmp(transaction_type, "http-get") == 0) {
        trans->method = MALLEABLE_HTTP_GET;
    } else if (strcmp(transaction_type, "http-post") == 0) {
        trans->method = MALLEABLE_HTTP_POST;
    }
    
    skip_comments(p);
    if (peek_char(p) != '{') {
        free(trans);
        return NULL;
    }
    next_char(p);
    
    // Parse transaction body
    while (peek_char(p) != '}' && peek_char(p) != EOF) {
        if (match_keyword(p, "set")) {
            if (match_keyword(p, "uri")) {
                char* uri_str = parse_string(p);
                if (uri_str) {
                    // Split space-separated URIs without strtok (MSVC warning)
                    char* cursor = uri_str;
                    while (*cursor) {
                        while (*cursor && isspace((unsigned char)*cursor)) cursor++;
                        if (!*cursor) break;
                        char* start = cursor;
                        while (*cursor && !isspace((unsigned char)*cursor)) cursor++;
                        size_t token_len = (size_t)(cursor - start);
                        if (token_len > 0) {
                            char* token = (char*)malleable_malloc(token_len + 1);
                            if (token) {
                                memcpy(token, start, token_len);
                                token[token_len] = '\0';
                                trans->uris = (char**)malleable_realloc(trans->uris,
                                               sizeof(char*) * (trans->num_uris + 1));
                                trans->uris[trans->num_uris++] = token;
                            }
                        }
                    }
                    free(uri_str);
                }
                skip_comments(p);
                if (peek_char(p) == ';') next_char(p);
            } else {
                if (match_keyword(p, "verb")) {
                    char* verb_str = parse_string(p);
                    if (verb_str) {
                        if (malleable_strncasecmp(verb_str, "GET", 3) == 0 && strlen(verb_str) == 3) {
                            trans->method = MALLEABLE_HTTP_GET;
                        } else if (malleable_strncasecmp(verb_str, "POST", 4) == 0 && strlen(verb_str) == 4) {
                            trans->method = MALLEABLE_HTTP_POST;
                        }
                        free(verb_str);
                    }
                    skip_comments(p);
                    if (peek_char(p) == ';') next_char(p);
                } else {
                // Skip unknown set statement
                while (peek_char(p) != ';' && peek_char(p) != EOF) next_char(p);
                if (peek_char(p) == ';') next_char(p);
                }
            }
        }
        else if (parse_http_config_block(p, &trans->client, "client")) {
            // Parsed client block
        }
        else if (parse_http_config_block(p, &trans->server, "server")) {
            // Parsed server block
        }
        else {
            // Skip unknown
            next_char(p);
        }
    }
    
    if (peek_char(p) == '}') next_char(p);
    
    return trans;
}

malleable_profile_t* malleable_profile_parse(const char* profile_str) {
    if (!profile_str) return NULL;
    
    malleable_profile_t* profile = (malleable_profile_t*)malleable_malloc(sizeof(malleable_profile_t));
    if (!profile) return NULL;
    memset(profile, 0, sizeof(malleable_profile_t));
    
    malleable_parser_t parser = {
        .input = profile_str,
        .pos = 0,
        .len = strlen(profile_str)
    };
    
    // Parse profile
    while (parser.pos < parser.len) {
        if (match_keyword(&parser, "set")) {
            if (match_keyword(&parser, "useragent")) {
                profile->useragent = parse_string(&parser);
                skip_comments(&parser);
                if (peek_char(&parser) == ';') next_char(&parser);
            } else if (match_keyword(&parser, "sample_name")) {
                profile->profile_name = parse_string(&parser);
                skip_comments(&parser);
                if (peek_char(&parser) == ';') next_char(&parser);
            } else if (match_keyword(&parser, "headers_remove")) {
                char* list = parse_string(&parser);
                if (list) {
                    char* cursor = list;
                    while (*cursor) {
                        char* token = cursor;
                        char* comma = strchr(cursor, ',');
                        if (comma) {
                            *comma = '\0';
                            cursor = comma + 1;
                        } else {
                            cursor = token + strlen(token);
                        }
                        token = trim_in_place(token);
                        if (*token) {
                            profile->headers_remove = (char**)malleable_realloc(
                                profile->headers_remove,
                                sizeof(char*) * (profile->num_headers_remove + 1)
                            );
                            if (profile->headers_remove) {
                                profile->headers_remove[profile->num_headers_remove++] = malleable_strdup(token);
                            }
                        }
                    }
                    free(list);
                }
                skip_comments(&parser);
                if (peek_char(&parser) == ';') next_char(&parser);
            } else {
                // Skip other set statements
                while (peek_char(&parser) != ';' && peek_char(&parser) != EOF) {
                    next_char(&parser);
                }
                if (peek_char(&parser) == ';') next_char(&parser);
            }
        }
        else {
            malleable_http_transaction_t* trans = parse_http_transaction(&parser, "http-get");
            if (trans) {
                profile->http_get_transactions = (malleable_http_transaction_t*)malleable_realloc(
                    profile->http_get_transactions,
                    sizeof(malleable_http_transaction_t) * (profile->num_http_get + 1));
                profile->http_get_transactions[profile->num_http_get++] = *trans;
                free(trans);
                continue;
            }
            
            trans = parse_http_transaction(&parser, "http-post");
            if (trans) {
                profile->http_post_transactions = (malleable_http_transaction_t*)malleable_realloc(
                    profile->http_post_transactions,
                    sizeof(malleable_http_transaction_t) * (profile->num_http_post + 1));
                profile->http_post_transactions[profile->num_http_post++] = *trans;
                free(trans);
                continue;
            }
            
            // Skip unknown blocks
            if (peek_char(&parser) != EOF) {
                next_char(&parser);
            } else {
                break;
            }
        }
    }
    return profile;
}

void malleable_profile_free(malleable_profile_t* profile) {
    if (!profile) return;

    free(profile->profile_name);
    free(profile->useragent);

    if (profile->headers_remove) {
        for (size_t i = 0; i < profile->num_headers_remove; i++) {
            free(profile->headers_remove[i]);
        }
        free(profile->headers_remove);
    }

    if (profile->http_get_transactions) {
        for (size_t i = 0; i < profile->num_http_get; i++) {
            malleable_http_transaction_t* txn = &profile->http_get_transactions[i];
            free(txn->variant);
            if (txn->uris) {
                for (size_t u = 0; u < txn->num_uris; u++) {
                    free(txn->uris[u]);
                }
                free(txn->uris);
            }
            if (txn->client.headers) {
                for (size_t h = 0; h < txn->client.num_headers; h++) {
                    free(txn->client.headers[h]);
                }
                free(txn->client.headers);
            }
            if (txn->client.parameters) {
                for (size_t p = 0; p < txn->client.num_parameters; p++) {
                    free(txn->client.parameters[p]);
                }
                free(txn->client.parameters);
            }
            if (txn->server.headers) {
                for (size_t h = 0; h < txn->server.num_headers; h++) {
                    free(txn->server.headers[h]);
                }
                free(txn->server.headers);
            }
            if (txn->server.parameters) {
                for (size_t p = 0; p < txn->server.num_parameters; p++) {
                    free(txn->server.parameters[p]);
                }
                free(txn->server.parameters);
            }
            if (txn->client.metadata) {
                for (size_t t = 0; t < txn->client.metadata->num_transforms; t++) {
                    free(txn->client.metadata->transforms[t].argument);
                }
                free(txn->client.metadata->transforms);
                free(txn->client.metadata->termination.target);
                free(txn->client.metadata);
            }
            if (txn->client.id) {
                for (size_t t = 0; t < txn->client.id->num_transforms; t++) {
                    free(txn->client.id->transforms[t].argument);
                }
                free(txn->client.id->transforms);
                free(txn->client.id->termination.target);
                free(txn->client.id);
            }
            if (txn->client.output) {
                for (size_t t = 0; t < txn->client.output->num_transforms; t++) {
                    free(txn->client.output->transforms[t].argument);
                }
                free(txn->client.output->transforms);
                free(txn->client.output->termination.target);
                free(txn->client.output);
            }
            if (txn->server.metadata) {
                for (size_t t = 0; t < txn->server.metadata->num_transforms; t++) {
                    free(txn->server.metadata->transforms[t].argument);
                }
                free(txn->server.metadata->transforms);
                free(txn->server.metadata->termination.target);
                free(txn->server.metadata);
            }
            if (txn->server.id) {
                for (size_t t = 0; t < txn->server.id->num_transforms; t++) {
                    free(txn->server.id->transforms[t].argument);
                }
                free(txn->server.id->transforms);
                free(txn->server.id->termination.target);
                free(txn->server.id);
            }
            if (txn->server.output) {
                for (size_t t = 0; t < txn->server.output->num_transforms; t++) {
                    free(txn->server.output->transforms[t].argument);
                }
                free(txn->server.output->transforms);
                free(txn->server.output->termination.target);
                free(txn->server.output);
            }
        }
        free(profile->http_get_transactions);
    }
    
    if (profile->http_post_transactions) {
        for (size_t i = 0; i < profile->num_http_post; i++) {
            malleable_http_transaction_t* txn = &profile->http_post_transactions[i];
            free(txn->variant);
            if (txn->uris) {
                for (size_t u = 0; u < txn->num_uris; u++) {
                    free(txn->uris[u]);
                }
                free(txn->uris);
            }
            if (txn->client.headers) {
                for (size_t h = 0; h < txn->client.num_headers; h++) {
                    free(txn->client.headers[h]);
                }
                free(txn->client.headers);
            }
            if (txn->client.parameters) {
                for (size_t p = 0; p < txn->client.num_parameters; p++) {
                    free(txn->client.parameters[p]);
                }
                free(txn->client.parameters);
            }
            if (txn->server.headers) {
                for (size_t h = 0; h < txn->server.num_headers; h++) {
                    free(txn->server.headers[h]);
                }
                free(txn->server.headers);
            }
            if (txn->server.parameters) {
                for (size_t p = 0; p < txn->server.num_parameters; p++) {
                    free(txn->server.parameters[p]);
                }
                free(txn->server.parameters);
            }
            if (txn->client.metadata) {
                for (size_t t = 0; t < txn->client.metadata->num_transforms; t++) {
                    free(txn->client.metadata->transforms[t].argument);
                }
                free(txn->client.metadata->transforms);
                free(txn->client.metadata->termination.target);
                free(txn->client.metadata);
            }
            if (txn->client.id) {
                for (size_t t = 0; t < txn->client.id->num_transforms; t++) {
                    free(txn->client.id->transforms[t].argument);
                }
                free(txn->client.id->transforms);
                free(txn->client.id->termination.target);
                free(txn->client.id);
            }
            if (txn->client.output) {
                for (size_t t = 0; t < txn->client.output->num_transforms; t++) {
                    free(txn->client.output->transforms[t].argument);
                }
                free(txn->client.output->transforms);
                free(txn->client.output->termination.target);
                free(txn->client.output);
            }
            if (txn->server.metadata) {
                for (size_t t = 0; t < txn->server.metadata->num_transforms; t++) {
                    free(txn->server.metadata->transforms[t].argument);
                }
                free(txn->server.metadata->transforms);
                free(txn->server.metadata->termination.target);
                free(txn->server.metadata);
            }
            if (txn->server.id) {
                for (size_t t = 0; t < txn->server.id->num_transforms; t++) {
                    free(txn->server.id->transforms[t].argument);
                }
                free(txn->server.id->transforms);
                free(txn->server.id->termination.target);
                free(txn->server.id);
            }
            if (txn->server.output) {
                for (size_t t = 0; t < txn->server.output->num_transforms; t++) {
                    free(txn->server.output->transforms[t].argument);
                }
                free(txn->server.output->transforms);
                free(txn->server.output->termination.target);
                free(txn->server.output);
            }
        }
        free(profile->http_post_transactions);
    }

    free(profile);
}

/* ===================================================================== */
/*                       HTTP REQUEST/RESPONSE FUNCTIONS                 */
/* ===================================================================== */

malleable_http_transaction_t* malleable_find_transaction(
    malleable_http_transaction_t* transactions,
    size_t num_transactions,
    const char* variant
) {
    const char* target = variant ? variant : "default";
    
    for (size_t i = 0; i < num_transactions; i++) {
        if (transactions[i].variant && strcmp(transactions[i].variant, target) == 0) {
            return &transactions[i];
        }
    }
    
    return NULL;
}

const char* malleable_error_string(malleable_error_t error) {
    switch (error) {
        case MALLEABLE_SUCCESS: return "Success";
        case MALLEABLE_ERROR_INVALID_PROFILE: return "Invalid profile";
        case MALLEABLE_ERROR_PARSE_FAILED: return "Parse failed";
        case MALLEABLE_ERROR_INVALID_VARIANT: return "Invalid variant";
        case MALLEABLE_ERROR_TRANSFORM_FAILED: return "Transform failed";
        case MALLEABLE_ERROR_MEMORY: return "Memory allocation failed";
        case MALLEABLE_ERROR_NOT_FOUND: return "Not found";
        default: return "Unknown error";
    }
}

void malleable_http_request_free(malleable_http_request_t* request) {
    if (!request) return;
    free(request->method);
    free(request->uri);
    if (request->headers) {
        for (size_t i = 0; i < request->num_headers; i++) {
            free(request->headers[i]);
        }
        free(request->headers);
    }
    free(request->body);
    free(request);
}

void malleable_http_response_free(malleable_http_response_t* response) {
    if (!response) return;
    if (response->headers) {
        for (size_t i = 0; i < response->num_headers; i++) {
            free(response->headers[i]);
        }
        free(response->headers);
    }
    free(response->body);
    free(response);
}

/* ===================================================================== */
/*                      REQUEST/RESPONSE HELPERS                         */
/* ===================================================================== */

// Helper: Add header to request
static malleable_error_t add_header(malleable_http_request_t* req, const char* name, const char* value) {
    size_t new_count = req->num_headers + 1;
    char** new_headers = (char**)malleable_realloc(req->headers, new_count * sizeof(char*));
    if (!new_headers) return MALLEABLE_ERROR_MEMORY;
    
    size_t header_len = strlen(name) + strlen(value) + 3; // ": " + null
    char* header = (char*)malleable_malloc(header_len);
    if (!header) {
        free(new_headers);
        return MALLEABLE_ERROR_MEMORY;
    }
    snprintf(header, header_len, "%s: %s", name, value);
    
    new_headers[new_count - 1] = header;
    req->headers = new_headers;
    req->num_headers = new_count;
    return MALLEABLE_SUCCESS;
}

static int header_name_matches(const char* header, const char* name) {
    const char* colon = strchr(header, ':');
    size_t header_len = colon ? (size_t)(colon - header) : strlen(header);
    size_t name_len = strlen(name);
    if (header_len != name_len) return 0;
    return malleable_strncasecmp(header, name, header_len) == 0;
}

static void remove_headers(malleable_http_request_t* req, const malleable_profile_t* profile) {
    if (!req || !profile || !profile->headers_remove || profile->num_headers_remove == 0) return;
    size_t i = 0;
    while (i < req->num_headers) {
        int remove = 0;
        for (size_t r = 0; r < profile->num_headers_remove; r++) {
            if (header_name_matches(req->headers[i], profile->headers_remove[r])) {
                remove = 1;
                break;
            }
        }
        if (remove) {
            free(req->headers[i]);
            for (size_t j = i + 1; j < req->num_headers; j++) {
                req->headers[j - 1] = req->headers[j];
            }
            req->num_headers--;
        } else {
            i++;
        }
    }
    if (req->num_headers == 0) {
        free(req->headers);
        req->headers = NULL;
    }
}

// Helper: Extract value from header
static const char* get_header_value(const malleable_http_request_t* req, const char* name) {
    size_t name_len = strlen(name);
    for (size_t i = 0; i < req->num_headers; i++) {
        if (strncmp(req->headers[i], name, name_len) == 0 && req->headers[i][name_len] == ':') {
            const char* value = req->headers[i] + name_len + 1;
            while (*value == ' ') value++;
            return value;
        }
    }
    return NULL;
}

// Helper: Extract parameter value from query string
static char* get_parameter_value(const char* query, const char* key) {
    if (!query || !key) return NULL;
    
    size_t key_len = strlen(key);
    const char* pos = query;
    
    while (pos && *pos) {
        if (strncmp(pos, key, key_len) == 0 && pos[key_len] == '=') {
            const char* value_start = pos + key_len + 1;
            const char* value_end = strchr(value_start, '&');
            size_t value_len = value_end ? (size_t)(value_end - value_start) : strlen(value_start);
            
            char* value = (char*)malleable_malloc(value_len + 1);
            if (value) {
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';
            }
            return value;
        }
        pos = strchr(pos, '&');
        if (pos) pos++; // Skip '&'
    }
    return NULL;
}

// Helper: Apply transform chain and place result per termination
static malleable_error_t apply_and_place(
    const malleable_transform_chain_t* chain,
    const uint8_t* data,
    size_t data_len,
    malleable_http_request_t* req,
    char** uri_suffix  // For URI-APPEND termination
) {
    if (!chain || !data || !req) return MALLEABLE_ERROR_TRANSFORM_FAILED;
    
    // Apply transformation chain
    uint8_t* transformed = NULL;
    size_t transformed_len = 0;
    malleable_error_t err = malleable_transform_apply(chain, data, data_len, &transformed, &transformed_len);
    if (err != MALLEABLE_SUCCESS) return err;
    
    // Null-terminate for string operations
    char* transformed_str = (char*)malleable_realloc(transformed, transformed_len + 1);
    if (!transformed_str) {
        free(transformed);
        return MALLEABLE_ERROR_MEMORY;
    }
    transformed_str[transformed_len] = '\0';
    
    // Place based on termination type
    switch (chain->termination.type) {
        case MALLEABLE_TERM_HEADER:
            err = add_header(req, chain->termination.target, transformed_str);
            free(transformed_str);
            return err;
            
        case MALLEABLE_TERM_PARAMETER: {
            // Add as query parameter to URI
            const char* prefix = strchr(req->uri, '?') ? "&" : "?";
            size_t new_uri_len = strlen(req->uri) + strlen(prefix) + 
                               strlen(chain->termination.target) + 1 + transformed_len + 1;
            char* new_uri = (char*)malleable_malloc(new_uri_len);
            if (!new_uri) {
                free(transformed_str);
                return MALLEABLE_ERROR_MEMORY;
            }
            snprintf(new_uri, new_uri_len, "%s%s%s=%s", req->uri, prefix, 
                    chain->termination.target, transformed_str);
            free(req->uri);
            req->uri = new_uri;
            free(transformed_str);
            return MALLEABLE_SUCCESS;
        }
        
        case MALLEABLE_TERM_PRINT:
            // Set as request body
            if (req->body) free(req->body);
            req->body = (uint8_t*)transformed_str;
            req->body_len = transformed_len;
            return MALLEABLE_SUCCESS;
            
        case MALLEABLE_TERM_URI_APPEND:
            // Append to URI
            if (uri_suffix) {
                *uri_suffix = transformed_str;
            } else {
                size_t new_uri_len = strlen(req->uri) + transformed_len + 1;
                char* new_uri = (char*)malleable_malloc(new_uri_len);
                if (!new_uri) {
                    free(transformed_str);
                    return MALLEABLE_ERROR_MEMORY;
                }
                snprintf(new_uri, new_uri_len, "%s%s", req->uri, transformed_str);
                free(req->uri);
                req->uri = new_uri;
                free(transformed_str);
            }
            return MALLEABLE_SUCCESS;
    }
    
    free(transformed_str);
    return MALLEABLE_ERROR_TRANSFORM_FAILED;
}

// Helper: Extract and reverse transform from request
static const char* find_uri_suffix(const malleable_http_transaction_t* txn, const char* uri) {
    if (!txn || !uri || txn->num_uris == 0) return NULL;
    for (size_t i = 0; i < txn->num_uris; i++) {
        const char* base = txn->uris[i];
        size_t base_len = strlen(base);
        if (strncmp(uri, base, base_len) == 0) {
            return uri + base_len;
        }
    }
    return NULL;
}

static malleable_error_t extract_and_reverse(
    const malleable_transform_chain_t* chain,
    const malleable_http_request_t* req,
    const malleable_http_transaction_t* txn,
    uint8_t** data_out,
    size_t* data_len_out
) {
    if (!chain || !req || !data_out || !data_len_out) {
        return MALLEABLE_ERROR_TRANSFORM_FAILED;
    }
    
    const char* extracted = NULL;
    char* extracted_copy = NULL;
    
    // Extract based on termination type
    switch (chain->termination.type) {
        case MALLEABLE_TERM_HEADER:
            extracted = get_header_value(req, chain->termination.target);
            if (extracted) {
                extracted_copy = malleable_strdup(extracted);
            }
            break;
            
        case MALLEABLE_TERM_PARAMETER: {
            const char* query = strchr(req->uri, '?');
            if (query) {
                extracted_copy = get_parameter_value(query + 1, chain->termination.target);
            }
            break;
        }
        
        case MALLEABLE_TERM_PRINT:
            if (req->body && req->body_len > 0) {
                extracted_copy = (char*)malleable_malloc(req->body_len + 1);
                if (extracted_copy) {
                    memcpy(extracted_copy, req->body, req->body_len);
                    extracted_copy[req->body_len] = '\0';
                }
            }
            break;
            
        case MALLEABLE_TERM_URI_APPEND: {
            const char* suffix = find_uri_suffix(txn, req->uri);
            if (suffix && *suffix) {
                extracted_copy = malleable_strdup(suffix);
            }
            break;
        }
    }
    
    if (!extracted_copy) {
        return MALLEABLE_ERROR_NOT_FOUND;
    }
    
    // Reverse transform
    size_t extracted_len = strlen(extracted_copy);
    malleable_error_t err = malleable_transform_reverse(chain, (uint8_t*)extracted_copy, 
                                                       extracted_len, data_out, data_len_out);
    free(extracted_copy);
    return err;
}

/* ===================================================================== */
/*                      REQUEST/RESPONSE BUILDING                        */
/* ===================================================================== */

malleable_error_t malleable_build_get_request(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* metadata,
    size_t metadata_len,
    malleable_http_request_t** request
) {
    if (!profile || !metadata || !request) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_get_transactions,
        profile->num_http_get,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    
    // Allocate request
    malleable_http_request_t* req = (malleable_http_request_t*)malleable_malloc(sizeof(malleable_http_request_t));
    if (!req) return MALLEABLE_ERROR_MEMORY;
    memset(req, 0, sizeof(malleable_http_request_t));
    
    // Set method
    req->method = malleable_strdup(txn->method == MALLEABLE_HTTP_POST ? "POST" : "GET");
    if (!req->method) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_MEMORY;
    }
    
    // Select random URI
    if (txn->num_uris == 0) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    size_t uri_idx = rand() % txn->num_uris;
    req->uri = malleable_strdup(txn->uris[uri_idx]);
    if (!req->uri) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_MEMORY;
    }
    
    // Add User-Agent header
    if (profile->useragent) {
        malleable_error_t err = add_header(req, "User-Agent", profile->useragent);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_request_free(req);
            return err;
        }
    }
    
    // Add fixed client headers
    for (size_t i = 0; i < txn->client.num_headers; i++) {
        // Parse "Name: Value" format
        char* header_copy = malleable_strdup(txn->client.headers[i]);
        if (!header_copy) {
            malleable_http_request_free(req);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        char* colon = strchr(header_copy, ':');
        if (colon) {
            *colon = '\0';
            char* value = colon + 1;
            while (*value == ' ') value++;
            
            malleable_error_t err = add_header(req, header_copy, value);
            free(header_copy);
            if (err != MALLEABLE_SUCCESS) {
                malleable_http_request_free(req);
                return err;
            }
        } else {
            free(header_copy);
        }
    }
    
    // Add fixed client parameters
    for (size_t i = 0; i < txn->client.num_parameters; i++) {
        const char* param = txn->client.parameters[i];
        const char* prefix = strchr(req->uri, '?') ? "&" : "?";
        size_t new_uri_len = strlen(req->uri) + strlen(prefix) + strlen(param) + 1;
        char* new_uri = (char*)malleable_malloc(new_uri_len);
        if (!new_uri) {
            malleable_http_request_free(req);
            return MALLEABLE_ERROR_MEMORY;
        }
        snprintf(new_uri, new_uri_len, "%s%s%s", req->uri, prefix, param);
        free(req->uri);
        req->uri = new_uri;
    }
    
    // Apply metadata transformation
    if (txn->client.metadata) {
        malleable_error_t err = apply_and_place(txn->client.metadata, metadata, metadata_len, req, NULL);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_request_free(req);
            return err;
        }
    }

    remove_headers(req, profile);
    
    *request = req;
    return MALLEABLE_SUCCESS;
}

malleable_error_t malleable_build_post_request(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* session_id,
    size_t id_len,
    const uint8_t* output,
    size_t output_len,
    malleable_http_request_t** request
) {
    if (!profile || !session_id || !output || !request) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_post_transactions,
        profile->num_http_post,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    
    // Allocate request
    malleable_http_request_t* req = (malleable_http_request_t*)malleable_malloc(sizeof(malleable_http_request_t));
    if (!req) return MALLEABLE_ERROR_MEMORY;
    memset(req, 0, sizeof(malleable_http_request_t));
    
    // Set method
    req->method = malleable_strdup(txn->method == MALLEABLE_HTTP_GET ? "GET" : "POST");
    if (!req->method) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_MEMORY;
    }
    
    // Select random URI
    if (txn->num_uris == 0) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    size_t uri_idx = rand() % txn->num_uris;
    req->uri = malleable_strdup(txn->uris[uri_idx]);
    if (!req->uri) {
        malleable_http_request_free(req);
        return MALLEABLE_ERROR_MEMORY;
    }
    
    // Add User-Agent header
    if (profile->useragent) {
        malleable_error_t err = add_header(req, "User-Agent", profile->useragent);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_request_free(req);
            return err;
        }
    }
    
    // Add fixed client headers
    for (size_t i = 0; i < txn->client.num_headers; i++) {
        char* header_copy = malleable_strdup(txn->client.headers[i]);
        if (!header_copy) {
            malleable_http_request_free(req);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        char* colon = strchr(header_copy, ':');
        if (colon) {
            *colon = '\0';
            char* value = colon + 1;
            while (*value == ' ') value++;
            
            malleable_error_t err = add_header(req, header_copy, value);
            free(header_copy);
            if (err != MALLEABLE_SUCCESS) {
                malleable_http_request_free(req);
                return err;
            }
        } else {
            free(header_copy);
        }
    }
    
    // Add fixed client parameters
    for (size_t i = 0; i < txn->client.num_parameters; i++) {
        const char* param = txn->client.parameters[i];
        const char* prefix = strchr(req->uri, '?') ? "&" : "?";
        size_t new_uri_len = strlen(req->uri) + strlen(prefix) + strlen(param) + 1;
        char* new_uri = (char*)malleable_malloc(new_uri_len);
        if (!new_uri) {
            malleable_http_request_free(req);
            return MALLEABLE_ERROR_MEMORY;
        }
        snprintf(new_uri, new_uri_len, "%s%s%s", req->uri, prefix, param);
        free(req->uri);
        req->uri = new_uri;
    }
    
    // Apply session ID transformation
    if (txn->client.id) {
        malleable_error_t err = apply_and_place(txn->client.id, session_id, id_len, req, NULL);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_request_free(req);
            return err;
        }
    }
    
    // Apply output transformation
    if (txn->client.output) {
        malleable_error_t err = apply_and_place(txn->client.output, output, output_len, req, NULL);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_request_free(req);
            return err;
        }
    }

    remove_headers(req, profile);
    
    *request = req;
    return MALLEABLE_SUCCESS;
}

malleable_error_t malleable_parse_get_response(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_response_t* response,
    uint8_t** data_out,
    size_t* data_len_out
) {
    if (!profile || !response || !data_out || !data_len_out) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_get_transactions,
        profile->num_http_get,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    if (!txn->server.output) return MALLEABLE_ERROR_NOT_FOUND;
    
    const char* extracted = NULL;
    char* extracted_copy = NULL;
    
    // Extract based on server output termination type
    switch (txn->server.output->termination.type) {
        case MALLEABLE_TERM_HEADER:
            // Find header in response
            for (size_t i = 0; i < response->num_headers; i++) {
                const char* header = response->headers[i];
                size_t name_len = strlen(txn->server.output->termination.target);
                if (strncmp(header, txn->server.output->termination.target, name_len) == 0 &&
                    header[name_len] == ':') {
                    extracted = header + name_len + 1;
                    while (*extracted == ' ') extracted++;
                    extracted_copy = malleable_strdup(extracted);
                    break;
                }
            }
            break;
            
        case MALLEABLE_TERM_PRINT:
            // Data is in response body
            if (response->body && response->body_len > 0) {
                extracted_copy = (char*)malleable_malloc(response->body_len + 1);
                if (extracted_copy) {
                    memcpy(extracted_copy, response->body, response->body_len);
                    extracted_copy[response->body_len] = '\0';
                }
            }
            break;
            
        case MALLEABLE_TERM_PARAMETER:
        case MALLEABLE_TERM_URI_APPEND:
            // These don't make sense for server responses
            return MALLEABLE_ERROR_NOT_FOUND;
    }
    
    if (!extracted_copy) {
        return MALLEABLE_ERROR_NOT_FOUND;
    }
    
    // Reverse transform
    size_t extracted_len = strlen(extracted_copy);
    malleable_error_t err = malleable_transform_reverse(txn->server.output, 
                                                       (uint8_t*)extracted_copy, 
                                                       extracted_len, 
                                                       data_out, 
                                                       data_len_out);
    free(extracted_copy);
    return err;
}

malleable_error_t malleable_extract_metadata(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** metadata_out,
    size_t* metadata_len_out
) {
    if (!profile || !request || !metadata_out || !metadata_len_out) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_get_transactions,
        profile->num_http_get,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    if (!txn->client.metadata) return MALLEABLE_ERROR_NOT_FOUND;
    
    return extract_and_reverse(txn->client.metadata, request, txn, metadata_out, metadata_len_out);
}

malleable_error_t malleable_extract_session_id(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** id_out,
    size_t* id_len_out
) {
    if (!profile || !request || !id_out || !id_len_out) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_post_transactions,
        profile->num_http_post,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    if (!txn->client.id) return MALLEABLE_ERROR_NOT_FOUND;
    
    return extract_and_reverse(txn->client.id, request, txn, id_out, id_len_out);
}

malleable_error_t malleable_extract_output(
    const malleable_profile_t* profile,
    const char* variant,
    const malleable_http_request_t* request,
    uint8_t** output_out,
    size_t* output_len_out
) {
    if (!profile || !request || !output_out || !output_len_out) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_post_transactions,
        profile->num_http_post,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    if (!txn->client.output) return MALLEABLE_ERROR_NOT_FOUND;
    
    return extract_and_reverse(txn->client.output, request, txn, output_out, output_len_out);
}

malleable_error_t malleable_build_get_response(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* data,
    size_t data_len,
    malleable_http_response_t** response
) {
    if (!profile || !data || !response) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_get_transactions,
        profile->num_http_get,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    
    // Allocate response
    malleable_http_response_t* resp = (malleable_http_response_t*)malleable_malloc(sizeof(malleable_http_response_t));
    if (!resp) return MALLEABLE_ERROR_MEMORY;
    memset(resp, 0, sizeof(malleable_http_response_t));
    
    resp->status_code = 200;
    
    // Add fixed server headers
    for (size_t i = 0; i < txn->server.num_headers; i++) {
        size_t new_count = resp->num_headers + 1;
        char** new_headers = (char**)malleable_realloc(resp->headers, new_count * sizeof(char*));
        if (!new_headers) {
            malleable_http_response_free(resp);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        new_headers[new_count - 1] = malleable_strdup(txn->server.headers[i]);
        if (!new_headers[new_count - 1]) {
            free(new_headers);
            malleable_http_response_free(resp);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        resp->headers = new_headers;
        resp->num_headers = new_count;
    }
    
    // Apply output transformation
    if (txn->server.output) {
        uint8_t* transformed = NULL;
        size_t transformed_len = 0;
        malleable_error_t err = malleable_transform_apply(txn->server.output, data, data_len, 
                                                         &transformed, &transformed_len);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_response_free(resp);
            return err;
        }
        
        // Place based on termination type
        switch (txn->server.output->termination.type) {
            case MALLEABLE_TERM_HEADER: {
                // Add as response header
                size_t new_count = resp->num_headers + 1;
                char** new_headers = (char**)malleable_realloc(resp->headers, new_count * sizeof(char*));
                if (!new_headers) {
                    free(transformed);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                
                // Null-terminate transformed data
                char* transformed_str = (char*)malleable_realloc(transformed, transformed_len + 1);
                if (!transformed_str) {
                    free(transformed);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                transformed_str[transformed_len] = '\0';
                
                size_t header_len = strlen(txn->server.output->termination.target) + 
                                   transformed_len + 3;
                char* header = (char*)malleable_malloc(header_len);
                if (!header) {
                    free(transformed_str);
                    free(new_headers);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                snprintf(header, header_len, "%s: %s", txn->server.output->termination.target, 
                        transformed_str);
                free(transformed_str);
                
                new_headers[new_count - 1] = header;
                resp->headers = new_headers;
                resp->num_headers = new_count;
                break;
            }
            
            case MALLEABLE_TERM_PRINT:
                // Set as response body
                resp->body = transformed;
                resp->body_len = transformed_len;
                break;
                
            case MALLEABLE_TERM_PARAMETER:
            case MALLEABLE_TERM_URI_APPEND:
                // These don't make sense for responses
                free(transformed);
                malleable_http_response_free(resp);
                return MALLEABLE_ERROR_TRANSFORM_FAILED;
        }
    }
    
    *response = resp;
    return MALLEABLE_SUCCESS;
}

malleable_error_t malleable_build_post_response(
    const malleable_profile_t* profile,
    const char* variant,
    const uint8_t* data,
    size_t data_len,
    malleable_http_response_t** response
) {
    if (!profile || !response) {
        return MALLEABLE_ERROR_INVALID_PROFILE;
    }
    
    // Find transaction
    malleable_http_transaction_t* txn = malleable_find_transaction(
        profile->http_post_transactions,
        profile->num_http_post,
        variant
    );
    if (!txn) return MALLEABLE_ERROR_INVALID_VARIANT;
    
    // Allocate response
    malleable_http_response_t* resp = (malleable_http_response_t*)malleable_malloc(sizeof(malleable_http_response_t));
    if (!resp) return MALLEABLE_ERROR_MEMORY;
    memset(resp, 0, sizeof(malleable_http_response_t));
    
    resp->status_code = 200;
    
    // Add fixed server headers
    for (size_t i = 0; i < txn->server.num_headers; i++) {
        size_t new_count = resp->num_headers + 1;
        char** new_headers = (char**)malleable_realloc(resp->headers, new_count * sizeof(char*));
        if (!new_headers) {
            malleable_http_response_free(resp);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        new_headers[new_count - 1] = malleable_strdup(txn->server.headers[i]);
        if (!new_headers[new_count - 1]) {
            free(new_headers);
            malleable_http_response_free(resp);
            return MALLEABLE_ERROR_MEMORY;
        }
        
        resp->headers = new_headers;
        resp->num_headers = new_count;
    }
    
    // Apply optional output transformation (POST responses often have no data)
    if (data && data_len > 0 && txn->server.output) {
        uint8_t* transformed = NULL;
        size_t transformed_len = 0;
        malleable_error_t err = malleable_transform_apply(txn->server.output, data, data_len, 
                                                         &transformed, &transformed_len);
        if (err != MALLEABLE_SUCCESS) {
            malleable_http_response_free(resp);
            return err;
        }
        
        // Place based on termination type
        switch (txn->server.output->termination.type) {
            case MALLEABLE_TERM_HEADER: {
                // Add as response header
                size_t new_count = resp->num_headers + 1;
                char** new_headers = (char**)malleable_realloc(resp->headers, new_count * sizeof(char*));
                if (!new_headers) {
                    free(transformed);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                
                char* transformed_str = (char*)malleable_realloc(transformed, transformed_len + 1);
                if (!transformed_str) {
                    free(transformed);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                transformed_str[transformed_len] = '\0';
                
                size_t header_len = strlen(txn->server.output->termination.target) + 
                                   transformed_len + 3;
                char* header = (char*)malleable_malloc(header_len);
                if (!header) {
                    free(transformed_str);
                    free(new_headers);
                    malleable_http_response_free(resp);
                    return MALLEABLE_ERROR_MEMORY;
                }
                snprintf(header, header_len, "%s: %s", txn->server.output->termination.target, 
                        transformed_str);
                free(transformed_str);
                
                new_headers[new_count - 1] = header;
                resp->headers = new_headers;
                resp->num_headers = new_count;
                break;
            }
            
            case MALLEABLE_TERM_PRINT:
                resp->body = transformed;
                resp->body_len = transformed_len;
                break;
                
            case MALLEABLE_TERM_PARAMETER:
            case MALLEABLE_TERM_URI_APPEND:
                free(transformed);
                malleable_http_response_free(resp);
                return MALLEABLE_ERROR_TRANSFORM_FAILED;
        }
    }
    
    *response = resp;
    return MALLEABLE_SUCCESS;
}

/*
 * Note: The high-level callback API (malleable_callback_get/post) is implemented
 * in malleable_callbacks.c. Link that file along with malleable_http_win.c to use
 * the transparent callback functionality.
 */
