#ifndef HTTP_ASYNC_HANDLER_H
#define HTTP_ASYNC_HANDLER_H

#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*httpd_req_handler_t)(httpd_req_t *req);

struct httpd_async_req_s {
    void *req;
    httpd_req_handler_t handler;
};

typedef struct httpd_async_req_s httpd_async_req_t;

int post_async_handler(httpd_req_t *req);
int rest_async_get_handler(httpd_req_t *req);
void start_async_req_workers(void);
void stop_async_req_workers(void);


#ifdef __cplusplus
}
#endif
#endif