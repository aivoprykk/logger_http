#ifndef FC0AF177_160E_4294_8D44_3953BBB70C15
#define FC0AF177_160E_4294_8D44_3953BBB70C15

#ifdef __cplusplus
extern "C" {
#endif

#include "sdkconfig.h"

extern struct m_wifi_context wifi_context;
#if !defined(CONFIG_LOGGER_WIFI_ENABLED)
struct m_wifi_context {
    char hostname[32];
};
#endif

#include <esp_http_server.h>

typedef int (*httpd_req_handler_t)(httpd_req_t *req);

struct httpd_async_req_s {
    void *req;
    httpd_req_handler_t handler;
};

typedef struct httpd_async_req_s httpd_async_req_t;

int post_handler(httpd_req_t *req);
int get_handler(httpd_req_t *req);
int head_handler(httpd_req_t *req);
int api_handler(httpd_req_t *req);

#if defined(X1)
void start_async_req_workers(void);
void stop_async_req_workers(void);
#endif

#define API_BASE "/api/v1/"

#define FILE_EXTENSIONS(l) \
    l(html) \
    l(css) \
    l(txt) \
    l(jpg) \
    l(png) \
    l(ico) \
    l(svg) \
    l(json) \
    l(js) \
    l(sbp) \
    l(ubx) \
    l(gpx) \
    l(gpy) \
    l(gz) \
    l(zip) \
    l(eot) \
    l(ttf) \
    l(woff) \
    l(woff2)

#define FILE_TYPE_HANDLERS(l) \
    l(text/html) \
    l(text/css) \
    l(text/plain) \
    l(image/jpg) \
    l(image/png) \
    l(image/x-icon) \
    l(image/svg+xml) \
    l(application/json) \
    l(application/javascript) \
    l(application/octet-stream) \
    l(application/octet-stream) \
    l(application/octet-stream) \
    l(application/octet-stream) \
    l(application/gzip) \
    l(application/zip) \
    l(font/eot) \
    l(font/ttf) \
    l(font/woff) \
    l(font/woff2)

#define CHECK_FILE_EXTENSION(filename, flen, ext, elen) (*(filename + flen - elen -1 ) == '.' && strcasecmp(filename + flen - elen, ext) == 0)

#define FILE_ENUM(l) file_type_##l,
enum { FILE_EXTENSIONS(FILE_ENUM) };

#if (defined(CONFIG_LOGGER_USE_GLOBAL_LOG_LEVEL) && CONFIG_LOGGER_GLOBAL_LOG_LEVEL < CONFIG_LOGGER_HTTP_LOG_LEVEL)
#define C_LOG_LEVEL CONFIG_LOGGER_GLOBAL_LOG_LEVEL
#else
#define C_LOG_LEVEL CONFIG_LOGGER_HTTP_LOG_LEVEL
#endif
#include "common_log.h"

#ifdef __cplusplus
}
#endif

#endif /* FC0AF177_160E_4294_8D44_3953BBB70C15 */
