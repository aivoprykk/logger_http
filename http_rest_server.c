

#include <esp_http_server.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "sys/time.h"
#include <unistd.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "mdns.h"

#include "http_rest_server.h"
#include "http_async_handler.h"
#include "strbf.h"
#include "uri_common.h"
#include "context.h"

#define HTTP_QUERY_KEY_MAX_LEN (64)

extern struct context_s m_context;

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "http_server";

httpd_handle_t *server = 0;
uint8_t downloading_file = 0;
static char base_path[ESP_VFS_PATH_MAX + 1];

struct m_handler {
    int fctl;
    httpd_uri_t uri;
};

rest_server_context_t rest_server_context_1 = {.base_path = &(base_path[0]),
                                               .request_no = 1};
rest_server_context_t rest_server_context_3 = {.base_path = &(base_path[0]),
                                               .request_no = 3};
rest_server_context_t rest_server_context_4 = {.base_path = &(base_path[0]),
                                               .request_no = 4};
rest_server_context_t rest_server_context_5 = {.base_path = &(base_path[0]),
                                                .request_no = 5};
rest_server_context_t rest_server_context_6 = {.base_path = &(base_path[0]),
                                                .request_no = 6};
rest_server_context_t rest_server_context_12 = {.base_path = &(base_path[0]),
                                                .request_no = 12};
static const struct m_handler handlers[] = {
    {0},
    {1,
     {.uri = "/api/v1/*",
      .method = HTTP_DELETE,
      .handler = rest_async_get_handler,
      .user_ctx = (void *)&rest_server_context_1}},
    {3,
     {.uri = "/api/v1/*",
      .method = HTTP_POST,
      .handler = post_async_handler,
      .user_ctx = (void *)&rest_server_context_3}},
    {4,
     {.uri = "/api/v1/*",
      .method = HTTP_PATCH,
      .handler = post_async_handler,
      .user_ctx = (void *)&rest_server_context_4}},
    {5,
     {.uri = "/api/v1/*",
      .method = HTTP_OPTIONS,
      .handler = rest_async_get_handler,
      .user_ctx = (void *)&rest_server_context_5}},
    {6,
     {.uri = "/api/v1/*",
      .method = HTTP_HEAD,
      .handler = rest_async_get_handler,
      .user_ctx = (void *)&rest_server_context_6}},
    {12,
     {.uri = "/*",
      .method = HTTP_GET,
      .handler = rest_async_get_handler,
      .user_ctx = (void *)&rest_server_context_12}},
    {0}};

//-----------------------------------------------------------------------
const char *rangematch(const char *pattern, char test, int flags) {
    int negate, ok;
    char c, c2;

    /*
     * A bracket expression starting with an unquoted circumflex
     * character produces unspecified results (IEEE 1003.2-1992,
     * 3.13.2).  This implementation treats it like '!', for
     * consistency with the regular expression syntax.
     * J.T. Conklin (conklin@ngai.kaleida.com)
     */
    if ((negate = (*pattern == '!' || *pattern == '^')))
        ++pattern;

    if (flags & FNM_CASEFOLD)
        test = tolower((unsigned char)test);

    for (ok = 0; (c = *pattern++) != ']';) {
        if (c == '\\' && !(flags & FNM_NOESCAPE))
            c = *pattern++;
        if (c == EOS)
            return (NULL);

        if (flags & FNM_CASEFOLD)
            c = tolower((unsigned char)c);

        if (*pattern == '-' && (c2 = *(pattern + 1)) != EOS && c2 != ']') {
            pattern += 2;
            if (c2 == '\\' && !(flags & FNM_NOESCAPE))
                c2 = *pattern++;
            if (c2 == EOS)
                return (NULL);

            if (flags & FNM_CASEFOLD)
                c2 = tolower((unsigned char)c2);

            if ((unsigned char)c <= (unsigned char)test &&
                (unsigned char)test <= (unsigned char)c2)
                ok = 1;
        } else if (c == test)
            ok = 1;
    }
    return (ok == negate ? NULL : pattern);
}

//--------------------------------------------------------------------
int fnmatch(const char *pattern, const char *string, int flags) {
    const char *stringstart;
    char c, test;

    for (stringstart = string;;)
        switch (c = *pattern++) {
            case EOS:
                if ((flags & FNM_LEADING_DIR) && *string == '/')
                    return (0);
                return (*string == EOS ? 0 : FNM_NOMATCH);
            case '?':
                if (*string == EOS)
                    return (FNM_NOMATCH);
                if (*string == '/' && (flags & FNM_PATHNAME))
                    return (FNM_NOMATCH);
                if (*string == '.' && (flags & FNM_PERIOD) &&
                    (string == stringstart ||
                     ((flags & FNM_PATHNAME) && *(string - 1) == '/')))
                    return (FNM_NOMATCH);
                ++string;
                break;
            case '*':
                c = *pattern;
                // Collapse multiple stars.
                while (c == '*')
                    c = *++pattern;

                if (*string == '.' && (flags & FNM_PERIOD) &&
                    (string == stringstart ||
                     ((flags & FNM_PATHNAME) && *(string - 1) == '/')))
                    return (FNM_NOMATCH);

                // Optimize for pattern with * at end or before /.
                if (c == EOS)
                    if (flags & FNM_PATHNAME)
                        return ((flags & FNM_LEADING_DIR) ||
                                        strchr(string, '/') == NULL
                                    ? 0
                                    : FNM_NOMATCH);
                    else
                        return (0);
                else if ((c == '/') && (flags & FNM_PATHNAME)) {
                    if ((string = strchr(string, '/')) == NULL)
                        return (FNM_NOMATCH);
                    break;
                }

                // General case, use recursion.
                while ((test = *string) != EOS) {
                    if (!fnmatch(pattern, string, flags & ~FNM_PERIOD))
                        return (0);
                    if ((test == '/') && (flags & FNM_PATHNAME))
                        break;
                    ++string;
                }
                return (FNM_NOMATCH);
            case '[':
                if (*string == EOS)
                    return (FNM_NOMATCH);
                if ((*string == '/') && (flags & FNM_PATHNAME))
                    return (FNM_NOMATCH);
                if ((pattern = rangematch(pattern, *string, flags)) == NULL)
                    return (FNM_NOMATCH);
                ++string;
                break;
            case '\\':
                if (!(flags & FNM_NOESCAPE)) {
                    if ((c = *pattern++) == EOS) {
                        c = '\\';
                        --pattern;
                    }
                }
                break;
                // FALLTHROUGH
            default:
                if (c == *string) {
                } else if ((flags & FNM_CASEFOLD) &&
                           (tolower((unsigned char)c) ==
                            tolower((unsigned char)*string))) {
                } else if ((flags & FNM_PREFIX_DIRS) && *string == EOS &&
                           ((c == '/' && string != stringstart) ||
                            (string == stringstart + 1 && *stringstart == '/')))
                    return (0);
                else
                    return (FNM_NOMATCH);
                string++;
                break;
        }
    // NOTREACHED
    return 0;
}

// char *get_directory_json(const char *path, const char *match, strbf_t *buf) {
//     DIR *dir = NULL;
//     struct dirent *ent;
//     char type;
//     char size[16];
//     char tpath[FILE_PATH_MAX];
//     char tbuffer[92];
//     struct stat sb;
//     struct tm *tm_info;
//     char *lpath = NULL;
//     int statok;

//     printf("\nList of Directory [%s]\n", path);
//     printf("-----------------------------------\n");
//     // Open directory
//     dir = opendir(path);
//     if (!dir) {
//         printf("Error opening directory\n");
//         return 0;
//     }

//     // Read directory entries
//     uint64_t total = 0;
//     uint32_t nfiles = 0, nitems = 0;
//     strbf_t fbuf;
//     strbf_inits(&fbuf, tpath, FILE_PATH_MAX);
//     strbf_puts(&fbuf, path);
//     size_t len = fbuf.cur - fbuf.start;

//     printf("T  Size      Date/Time         Name\n");
//     printf("-----------------------------------\n");
//     int i = 0;
//     strbf_puts(buf, "[");
//     while ((ent = readdir(dir)) != NULL) {
//         strbf_shape(&fbuf, len);
//         strbf_put_path(&fbuf, ent->d_name);
//         tbuffer[0] = '\0';
//         if ((match == NULL) ||
//             (fnmatch(match, &(tpath[0]), (FNM_PERIOD)) == 0)) {
//             // Get file stat
//             statok = stat(&(tpath[0]), &sb);
//             strbf_puts(buf, nitems > 0 ? ",{" : "{");
//             if (statok == 0) {
//                 tm_info = localtime(&sb.st_mtime);
//                 strftime(tbuffer, 92, "%Y-%m-%d %R", tm_info);

//             } else {
//                 sprintf(tbuffer, "                ");
//             }

//             if (ent->d_type == DT_REG) {
//                 type = 'f';
//                 nfiles++;
//                 if (statok)
//                     strcpy(size, "       ?");
//                 else {
//                     total += sb.st_size;
//                     if (sb.st_size < (1024 * 1024))
//                         sprintf(size, "%8d", (int)sb.st_size);
//                     else if ((sb.st_size / 1024) < (1024 * 1024))
//                         sprintf(size, "%6dKB", (int)(sb.st_size / 1024));
//                     else
//                         sprintf(size, "%6dMB",
//                                 (int)(sb.st_size / (1024 * 1024)));
//                 }
//             } else {
//                 type = 'd';
//                 strcpy(size, "       -");
//             }
//             ++nitems;
//             strbf_puts(buf, "\"name\":\"");
//             strbf_puts(buf, ent->d_name);
//             strbf_puts(buf, "\",\"date\":\"");
//             if (!statok)
//                 strbf_puts(buf, tbuffer);
//             strbf_puts(buf, "\",\"size\":\"");
//             if (!statok && ent->d_type == DT_REG)
//                 strbf_putul(buf, (int)sb.st_size);
//             strbf_puts(buf, "\",\"type\":\"");
//             strbf_putc(buf, type);
//             strbf_puts(buf, "\",\"mode\":\"");
//             if (strstr(ent->d_name, "config")) {
//                 strbf_puts(buf, "r");
//             } else
//                 strbf_puts(buf, "rw");
//             strbf_puts(buf, "\"}");

//             printf("%c  %s  %s  %s\r\n", type, size, tbuffer, ent->d_name);
//         }
//     }
//     strbf_puts(buf, "]\n");
//     if (total) {
//         printf("-----------------------------------\n");
//         if (total < (1024 * 1024))
//             printf("   %8d", (int)total);
//         else if ((total / 1024) < (1024 * 1024))
//             printf("   %6dKB", (int)(total / 1024));
//         else
//             printf("   %6dMB", (int)(total / (1024 * 1024)));
//         printf(" in %" PRIu32 " file(s)\n", nfiles);
//     }
//     printf("-----------------------------------\n");

//     closedir(dir);

//     free(lpath);
//     return strbf_get(buf);
// }

// esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err) {
//     /* if (strcmp("/hello", req->uri) == 0) {
//       httpd_resp_send_err(req, HTTPD_404_NOT_FOUND,
//                           "/hello URI is not available");
//       // Return ESP_OK to keep underlying socket open
//       return ESP_OK;
//     } else if (strcmp("/echo", req->uri) == 0) {
//       httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not
//     available");
//       // Return ESP_FAIL to close underlying socket
//       return ESP_FAIL;
//     } */
//     /* For any other URI send 404 and close socket */
//     httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
//     return ESP_FAIL;
// }

static const char * http_rest_server_errors[] = {
    "Error starting server",
    "Failed to stop http server",
    "Failed to set up mDNS service",
};

httpd_handle_t start_webserver(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = CONFIG_WEB_SERVER_TASK_STACK_SIZE;
    config.lru_purge_enable = true;

    // Start the httpd server
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        const struct m_handler *handler;
        for (int i = 1, j = sizeof(handlers) / sizeof(struct m_handler); i < j; ++i) {
            handler = &handlers[i];
            if (handler->fctl > 0) {
                httpd_register_uri_handler(server, &(handler->uri));
            }
        }
#if CONFIG_HTTP_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        goto done;
    }

    ESP_LOGI(TAG, "%s", http_rest_server_errors[0]);
    done:
    return server;
}

#if !CONFIG_IDF_TARGET_LINUX
unsigned int stop_webserver(httpd_handle_t server) {
    // Stop the httpd server
    const struct m_handler *handler;
    unsigned int ret = 0;
    for (int i = 1, j = sizeof(handlers) / sizeof(struct m_handler); i < j; ++i) {
        handler = &handlers[i];
        if (handler->fctl > 0) {
            /* rest_server_context_t *rest_context =
                (rest_server_context_t *)handler->uri.user_ctx;
            if (rest_context && rest_context->request_no > 0) {
                int req = (int)rest_context->request_no;
                handler->uri.user_ctx = (void *)req;
                free(rest_context); */
            httpd_unregister_uri_handler(server, handler->uri.uri, handler->uri.method);
            //}
        }
    }

    ret = httpd_stop(server);
    return ret;
}

#define MDNS_INSTANCE "esp logger web server"

static esp_err_t initialise_mdns(void) {
    esp_err_t ret = mdns_init();
    if(ret) goto done;
    ret = mdns_hostname_set(CONFIG_MDNS_HOST_NAME);
    if(ret) goto done;
    ret = mdns_instance_name_set(MDNS_INSTANCE);
    if(ret) goto done;

    mdns_txt_item_t serviceTxtData[] = {{"board", "esp32"}, {"path", "/"}};
    ret = mdns_service_add("esp-logger", "_http", "_tcp", 80, serviceTxtData, sizeof(serviceTxtData) / sizeof(serviceTxtData[0]));
    done:
    if(ret)
        ESP_LOGE(TAG, "%s: %s", http_rest_server_errors[2], esp_err_to_name(ret));
    return ret;
}

static esp_err_t deinitialise_mdns(void) {
    esp_err_t ret = mdns_service_remove_all();
    mdns_free();
    return ret;
}

esp_err_t http_start_webserver() {
    //httpd_handle_t server = s;
    if (server == NULL) {
        start_async_req_workers();
        server = start_webserver();
        initialise_mdns();
    }
    task_memory_info("webServer");
    if(server) return ESP_OK;
    else return ESP_FAIL;
}

esp_err_t http_stop_webserver() {
    //httpd_handle_t server = s;
    esp_err_t ret = ESP_OK;
    if (server) {
        deinitialise_mdns();
        ret = stop_webserver(server);
        if(!ret) {
            server = NULL;
        } else {
            ESP_LOGE(TAG, "%s", http_rest_server_errors[1]);
        }
        stop_async_req_workers();
    }
    return ret;
}

void disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server) {
        deinitialise_mdns();
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "%s", http_rest_server_errors[1]);
        }
        stop_async_req_workers();
    }
}

void connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL) {
        start_async_req_workers();
        *server = start_webserver();
        initialise_mdns();
    }
}
#endif  // !CONFIG_IDF_TARGET_LINUX

// void http_rest_init() {
//     esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server);
//     esp_event_handler_register(IP_EVENT, IP_EVENT_STA_LOST_IP, &disconnect_handler, &server);
//     esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_START, &connect_handler, &server);
//     esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STOP, &disconnect_handler, &server);
//     /* Start the server for the first time */
//     //server = start_webserver();
// }

// void http_rest_uninit() {
//     esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler);
//     esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_LOST_IP, &disconnect_handler);
//     esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_AP_START,&connect_handler);
//     esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_AP_STOP,&disconnect_handler);
// }

static const char *http_server_events [] = {
    "HTTP_SERVER_EVENT_ERROR",
    "HTTP_SERVER_EVENT_START",
    "HTTP_SERVER_EVENT_ON_CONNECTED",
    "HTTP_SERVER_EVENT_ON_HEADER",
    "HTTP_SERVER_EVENT_HEADERS_SENT",
    "HTTP_SERVER_EVENT_ON_DATA",
    "HTTP_SERVER_EVENT_SENT_DATA",
    "HTTP_SERVER_EVENT_DISCONNECTED",
    "HTTP_SERVER_EVENT_STOP"
};

static void esp_http_server_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data) {
    if(base == ESP_HTTP_SERVER_EVENT) {
        esp_http_server_event_data *data = (esp_http_server_event_data *)event_data;
        switch(id) {
            case HTTP_SERVER_EVENT_ERROR: // 0
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            case HTTP_SERVER_EVENT_START: // 1
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            case HTTP_SERVER_EVENT_ON_CONNECTED: // 2
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            case HTTP_SERVER_EVENT_ON_HEADER: // 3
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            case HTTP_SERVER_EVENT_HEADERS_SENT: // 4
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            // case HTTP_SERVER_EVENT_ON_DATA: // 5
            //     ESP_LOGI(TAG, "[%s]  %d", __FUNCTION__, http_server_events[id], data ? data->data_len : 0);
            //     break;
            // case HTTP_SERVER_EVENT_SENT_DATA: // 6
            //     ESP_LOGI(TAG, "[%s] %s %d", __FUNCTION__, http_server_events[id], data ? data->data_len : 0);
            //     break;
            // case HTTP_SERVER_EVENT_DISCONNECTED: // 7
            //     ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
            //     break;
            case HTTP_SERVER_EVENT_STOP: // 8
                ESP_LOGI(TAG, "[%s] %s", __FUNCTION__, http_server_events[id]);
                break;
            default:
                // ESP_LOGI(TAG, "[%s] %s:%" PRId32, __FUNCTION__, base, id);
                break;
        }
    }
}
esp_err_t http_rest_init(const char *basepath) {
    esp_err_t ret = ESP_OK;
    if (!basepath){
        ret = ESP_FAIL;
        goto done;
    }
    ESP_ERROR_CHECK(esp_event_handler_register(ESP_HTTP_SERVER_EVENT, ESP_EVENT_ANY_ID, &esp_http_server_event_handler, NULL));
    strbf_t buf;
    strbf_inits(&buf, base_path, ESP_VFS_PATH_MAX);
    struct stat sb = {0};
    int statok, i = 0;
    while(i < 3) {
        strbf_reset(&buf);
        if(i++ == 0) {
            #if defined(CONFIG_USE_SPIFFS)
            strbf_puts(&buf, CONFIG_SPIFFS_MOUNT_POINT);
            #endif
        }
        else if (i++ == 1) {
            #if defined(CONFIG_USE_FATFS)
            strbf_puts(&buf, CONFIG_FATFS_MOUNT_POINT);
            #endif
        }
        else {
            strbf_puts(&buf, CONFIG_SD_MOUNT_POINT);
        }
        strbf_puts(&buf, basepath);
        statok = stat(buf.start, &sb);
        if(statok == 0) {
            break;
        }
    }
    strbf_finish(&buf);
    //http_rest_init();
    ret = ESP_OK;
done:
    return ret;
}
