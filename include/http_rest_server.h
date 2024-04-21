#ifndef HTTP_REST_SERVER_H
#define HTTP_REST_SERVER_H


#include <stdint.h>
#include "esp_event.h"
#include "esp_vfs.h" // ESP_VFS_PATH_MAX

#ifdef __cplusplus
extern "C" {
#endif

#define R_NONE 1
#define R_ARCHIVE_LIST 2
#define R_ARCHIVE_FILE 3
#define R_UPLOAD 4
#define R_FUPLOAD 5
#define R_CONFIG 6
#define R_CONFIGUPLOAD 7
#define R_UPDATE 8
#define R_FIRMWARE 9
#define R_SYSINFO 10
#define R_LOGIN 11
#define R_ELSE 12
#define R_END 13

#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 209)
#define SCRATCH_BUFSIZE (1024)

typedef struct rest_server_context {
    const char *base_path;
    uint8_t request_no;
    uint16_t _pad0;  // pad to 4bytes
} rest_server_context_t;

#define CHECK_FILE_EXTENSION(filename, flen, ext, elen) \
    (strcasecmp(filename + flen - elen, ext) == 0)

struct strbf_s;
int set_content_type_from_file(void *req, const char *filepath, size_t pathlen);
char *get_directory_json(const char *path, const char *match, struct strbf_s *buf);

int http_rest_init(const char *path);

esp_err_t http_stop_webserver();
esp_err_t http_start_webserver();

#ifdef __cplusplus
}
#endif
#endif