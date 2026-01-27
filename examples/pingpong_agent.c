/**
 * Ping Pong PoC Agent
 *
 * Usage:
 *   pingpong_agent.exe <profile.profile>
 *
 * This agent performs:
 * 1) GET check-in (send metadata, receive tasks)
 * 2) Execute received command locally
 * 3) POST output (send task output back to server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "openmalleable.h"

static void print_banner(const char* title) {
    printf("============================================================\n");
    printf("%s\n", title);
    printf("============================================================\n");
}

static void print_bytes_ascii(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    if (data && len > 0) {
        printf("\"%.*s\"\n", (int)len, (const char*)data);
    } else {
        printf("(empty)\n");
    }
}

static void get_computer_info(char* buffer, size_t bufsize) {
    char hostname[256] = "UNKNOWN";
    
#ifdef _WIN32
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    char username[256] = "UNKNOWN";
    size = sizeof(username);
    GetUserNameA(username, &size);
    DWORD pid = GetCurrentProcessId();
    
    snprintf(buffer, bufsize, 
             "Computer=%s User=%s PID=%lu OS=Windows Arch=x64",
             hostname, username, pid);
#else
    gethostname(hostname, sizeof(hostname));
    snprintf(buffer, bufsize, 
             "Computer=%s User=%s PID=%d OS=Linux Arch=x64",
             hostname, getenv("USER") ? getenv("USER") : "unknown", getpid());
#endif
}

static void reverse_string(char* str) {
    if (!str) return;
    
    size_t len = strlen(str);
    for (size_t i = 0; i < len / 2; i++) {
        char temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
}

static void trim_whitespace(char* str) {
    if (!str) return;
    
    // Trim trailing whitespace
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' || 
                       str[len - 1] == '\r' || str[len - 1] == '\n')) {
        str[--len] = '\0';
    }
    
    // Trim leading whitespace
    char* start = str;
    while (*start && (*start == ' ' || *start == '\t' || 
                      *start == '\r' || *start == '\n')) {
        start++;
    }
    
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <profile.profile>\n", argv[0]);
        return 1;
    }

    const char* profile_path = argv[1];
    const char* host = "127.0.0.1";
    int port = 8080;
    int use_https = 0;

    srand((unsigned int)time(NULL));

    print_banner("Ping Pong PoC Agent");

    /* User handles file I/O - library only accepts strings */
    printf("[Agent] Reading profile file: %s\n", profile_path);
#ifdef _MSC_VER
    FILE* f = NULL;
    if (fopen_s(&f, profile_path, "r") != 0) {
        f = NULL;
    }
#else
    FILE* f = fopen(profile_path, "r");
#endif
    if (!f) {
        fprintf(stderr, "[Agent] Failed to open profile file\n");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* profile_content = (char*)malloc(file_size + 1);
    if (!profile_content) {
        fprintf(stderr, "[Agent] Memory allocation failed\n");
        fclose(f);
        return 1;
    }
    
    fread(profile_content, 1, file_size, f);
    profile_content[file_size] = '\0';
    fclose(f);
    
    printf("[Agent] Parsing profile from memory...\n");
    malleable_profile_t* profile = malleable_profile_parse(profile_content);
    free(profile_content);  /* Done with file content */
    
    if (!profile) {
        fprintf(stderr, "[Agent] Failed to parse profile\n");
        return 1;
    }
    printf("[Agent] Profile loaded: %s\n", profile->profile_name ? profile->profile_name : "unnamed");
    printf("[Agent] User-Agent: %s\n", profile->useragent ? profile->useragent : "(none)");
    printf("\n");

    /* Generate realistic beacon metadata */
    char metadata_buf[512];
    get_computer_info(metadata_buf, sizeof(metadata_buf));
    
    /* Add timestamp */
    time_t now = time(NULL);
    char final_metadata[1024];
    snprintf(final_metadata, sizeof(final_metadata), 
             "BEACON-CHECKIN: %s Timestamp=%ld", metadata_buf, (long)now);
    
    uint8_t* metadata = (uint8_t*)final_metadata;
    size_t metadata_len = strlen(final_metadata);

    printf("[Agent] ===== GET: Requesting tasks from server =====\n");
    print_bytes_ascii("[Agent] Metadata", metadata, metadata_len);

    uint8_t* tasks = NULL;
    size_t tasks_len = 0;
    malleable_error_t err = malleable_callback_get(
        profile,
        NULL,
        host,
        port,
        use_https,
        metadata,
        metadata_len,
        &tasks,
        &tasks_len
    );

    if (err != MALLEABLE_SUCCESS) {
        fprintf(stderr, "[Agent] GET callback failed: %s\n", malleable_error_string(err));
        malleable_profile_free(profile);
        return 1;
    }

    print_bytes_ascii("[Agent] Received task", tasks, tasks_len);

    /* Treat the task as the raw string to reverse */
    char task_str[1024];
    snprintf(task_str, sizeof(task_str), "%.*s", (int)tasks_len, (char*)tasks);
    trim_whitespace(task_str);
    printf("[Agent] Task string: \"%s\"\n", task_str);

    reverse_string(task_str);
    printf("[Agent] Reversed task: \"%s\"\n", task_str);

    /* Generate random session ID */
    int session_num = 10000 + (rand() % 90000);
    char session_id_buf[32];
    snprintf(session_id_buf, sizeof(session_id_buf), "%d", session_num);
    uint8_t* session_id = (uint8_t*)session_id_buf;
    size_t session_id_len = strlen(session_id_buf);

    /* Prepare output data with reversed string */
    char output_buf[8192];
    snprintf(output_buf, sizeof(output_buf), 
             "TASK-RESULT: ReversedOutput=%s", task_str);
    uint8_t* output = (uint8_t*)output_buf;
    size_t output_len = strlen(output_buf);

    printf("\n[Agent] ===== POST: Sending task results to server =====\n");
    print_bytes_ascii("[Agent] Session ID", session_id, session_id_len);
    print_bytes_ascii("[Agent] Task output", output, output_len);

    uint8_t* response = NULL;
    size_t response_len = 0;
    err = malleable_callback_post(
        profile,
        NULL,
        host,
        port,
        use_https,
        session_id,
        session_id_len,
        output,
        output_len,
        &response,
        &response_len
    );

    if (err != MALLEABLE_SUCCESS) {
        fprintf(stderr, "[Agent] POST callback failed: %s\n", malleable_error_string(err));
        free(tasks);
        malleable_profile_free(profile);
        return 1;
    }

    if (response && response_len > 0) {
        print_bytes_ascii("[Agent] Server confirmation", response, response_len);
        free(response);
    } else {
        printf("[Agent] No confirmation data (normal for POST responses)\n");
    }

    free(tasks);
    malleable_profile_free(profile);
    printf("\n[Agent] ===== Ping pong complete =====\n");
    printf("[Agent] Successfully executed server task and reported results!\n");
    return 0;
}
