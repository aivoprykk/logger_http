#include "logger_http_private.h"
#if defined(CONFIG_LOGGER_HTTP_ENABLED)
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "sys/time.h"
#include <unistd.h>

#include "esp_event.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "mdns.h"

#include "http_rest_server.h"
#include "http_async_handler.h"
#include "strbf.h"
#include "uri_common.h"
#include "context.h"
#include "logger_config.h"
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
#include "https_ota.h"
#endif
#if defined(CONFIG_LOGGER_WIFI_ENABLED)
#include "logger_wifi.h"
#else
struct m_wifi_context wifi_context = {.hostname = "esp32"};
#endif
#if defined(CONFIG_LOGGER_VFS_ENABLED)
#include "vfs.h"
#endif

#define HTTP_QUERY_KEY_MAX_LEN (64)

extern struct context_s m_context;
/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "http_server";

httpd_handle_t *server = 0;
uint8_t downloading_file = 0;
// char base_path[ESP_VFS_PATH_MAX + 1] = {0};

struct m_handler {
    int fctl;
    httpd_uri_t uri;
};

rest_server_context_t rest_server_context[] = {
    {.request_no = 3},
    {.request_no = 6},
    {.request_no = 11},
    {.request_no = 12}
};

static const char url_base[] = API_BASE"*";
static const struct m_handler handlers[] = {
    {0},
    {3,
     {.uri = &url_base[0],
      .method = HTTP_POST,
      .handler = post_handler,
      .user_ctx = (void *)&rest_server_context[0]}},
    {6,
     {.uri = "/*",
      .method = HTTP_HEAD,
      .handler = head_handler,
      .user_ctx = (void *)&rest_server_context[1]}},
      {12,
    {.uri = &url_base[0],
      .method = HTTP_GET,
      .handler = api_handler,
      .user_ctx = (void *)&rest_server_context[2]}},
    {12,
     {.uri = "/*",
      .method = HTTP_GET,
      .handler = get_handler,
      .user_ctx = (void *)&rest_server_context[2]}},
    {0}};


static const char * http_rest_server_errors[] = {
    "Error starting server",
    "Failed to stop http server",
    "Failed to set up mDNS service",
};

httpd_handle_t start_webserver(void) {
    ILOG(TAG, "[%s]", __func__);
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = CONFIG_WEB_SERVER_TASK_STACK_SIZE;
    config.lru_purge_enable = true;

    // Start the httpd server
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        DLOG(TAG, "[%s] Registering URI handlers", __func__);
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

    WLOG(TAG, "[%s] %s", __func__, http_rest_server_errors[0]);
    done:
    return server;
}

#if !CONFIG_IDF_TARGET_LINUX
unsigned int stop_webserver(httpd_handle_t server) {
    ILOG(TAG, "[%s]", __func__);
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
#include "esp_mac.h"

static esp_err_t initialise_mdns(void) {
    ILOG(TAG, "[%s]", __func__);
    esp_err_t ret = mdns_init();
    if(ret) goto done;
    size_t len = 0;
    char * hn = 0;
    hn = wifi_context.hostname;

    if(m_context.config->hostname[0] != '\0') {
        len = MIN(strlen(m_context.config->hostname), 32);
        memcpy(hn, m_context.config->hostname, len);
    } else {
        len = MIN(strlen(CONFIG_MDNS_HOST_NAME), 32);
        memcpy(hn, CONFIG_MDNS_HOST_NAME, len);
    }
#if defined(CONFIG_WEB_SERVER_APPEND_MAC_TO_HOSTNAME)
    if(!strcmp(hn,"esp")) {
        //wifi_context.hostname[len++] = '-';
        uint8_t mac[6];
        esp_read_mac(&mac[0], ESP_MAC_EFUSE_FACTORY);
        char mac_str[8]={0};
        mac_to_char(mac, hn+len, 4);
        str_tolower(hn+len);
    }
#endif
    ret = mdns_hostname_set(hn);
    if(ret) goto done;
    ret = mdns_instance_name_set(MDNS_INSTANCE);
    if(ret) goto done;

    mdns_txt_item_t serviceTxtData[] = {{"board", "esp32"}, {"path", "/"}};
    ret = mdns_service_add(hn, "_http", "_tcp", 80, serviceTxtData, sizeof(serviceTxtData) / sizeof(serviceTxtData[0]));
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
    ILOG(TAG, "[%s]", __func__);
    //httpd_handle_t server = s;
    if (server == NULL) {
        #if defined(X1)
        start_async_req_workers();
        #endif
        server = start_webserver();
        initialise_mdns();
    }
    if(server) return ESP_OK;
    else return ESP_FAIL;
}

esp_err_t http_stop_webserver() {
    ILOG(TAG, "[%s]", __func__);
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
        #if defined(X1)
        stop_async_req_workers();
        #endif
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
        #if defined(X1)
        stop_async_req_workers();
        #endif
    }
}

void connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL) {
        #if defined(X1)
        start_async_req_workers();
        #endif
        *server = start_webserver();
        initialise_mdns();
    }
}
#endif  // !CONFIG_IDF_TARGET_LINUX

#if (C_LOG_LEVEL < 2)
static const char * const _http_server_events [] = {
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
const char * http_server_events(int id) {
    return _http_server_events[id];
}
#else
const char * http_server_events(int id) {
    return "HTTP_SERVER_EVENT";
}
#endif

static void esp_http_server_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data) {
    if(base == ESP_HTTP_SERVER_EVENT) {
        esp_http_server_event_data *data = (esp_http_server_event_data *)event_data;
 #if (C_LOG_LEVEL < 2)
       switch(id) {
            case HTTP_SERVER_EVENT_ERROR: // 0
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_START: // 1
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_ON_CONNECTED: // 2
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_ON_HEADER: // 3
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_HEADERS_SENT: // 4
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_ON_DATA: // 5
                DLOG(TAG, "%s", ".");
                break;
            case HTTP_SERVER_EVENT_SENT_DATA: // 6
                ILOG(TAG, "[%s] -", __FUNCTION__);
                break;
            case HTTP_SERVER_EVENT_DISCONNECTED: // 7
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            case HTTP_SERVER_EVENT_STOP: // 8
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_server_events(id));
                break;
            default:
                // ILOG(TAG, "[%s] %s:%" PRId32, __FUNCTION__, base, id);
                break;
        }
#endif
    }
#if defined (CONFIG_LOGGER_WIFI_ENABLED)
    else if(base == WIFI_EVENT) {
        switch(id) {
            case WIFI_EVENT_AP_START:
#if (C_LOG_LEVEL < 2)
                ILOG(TAG, "[%s] %s", __FUNCTION__, wifi_event_strings(id));
#endif
                http_start_webserver();
                break;
            case WIFI_EVENT_AP_STOP:
#if (C_LOG_LEVEL < 2)
                ILOG(TAG, "[%s] %s", __FUNCTION__, wifi_event_strings(id));
#endif
                if (!wifi_context.s_sta_connection)
                    http_stop_webserver();
                break;
            case WIFI_EVENT_STA_STOP:
#if (C_LOG_LEVEL < 2)
                ILOG(TAG, "[%s] %s", __FUNCTION__, wifi_event_strings(id));
#endif
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
                if(m_context.config->fwupdate.update_enabled)
                    https_ota_stop();
#endif
                break;
            default:
                break;
        }
    }
    else if(base == IP_EVENT) {
        switch(id) {
            case IP_EVENT_STA_GOT_IP:
#if (C_LOG_LEVEL < 2)
                ILOG(TAG, "[%s] %s", __FUNCTION__, wifi_event_strings(id));
#endif
                http_start_webserver();
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
                if(m_context.config->fwupdate.update_enabled)
                    https_ota_start();
#endif
                break;
            case IP_EVENT_STA_LOST_IP:
#if (C_LOG_LEVEL < 2)
                ILOG(TAG, "[%s] %s", __FUNCTION__, wifi_event_strings(id));
#endif
                if (!wifi_context.s_ap_connection)
                    http_stop_webserver();
    #if defined(CONFIG_OTA_USE_AUTO_UPDATE)
                if(m_context.config->fwupdate.update_enabled)
                    https_ota_stop();
    #endif
                break;
            default:
                break;
        }
    }
#endif
}
esp_err_t http_rest_init(const char *basepath) {
    ILOG(TAG, "[%s]", __func__);
    esp_err_t ret = ESP_OK;
    if (!basepath){
        ret = ESP_FAIL;
        goto done;
    }
    if(esp_event_handler_register(ESP_EVENT_ANY_BASE, ESP_EVENT_ANY_ID, &esp_http_server_event_handler, NULL)) {
        ESP_LOGE(TAG, "[%s] Failed to register event handler", __func__);
        ret = ESP_FAIL;
        goto done;
    }
    //strbf_t buf;
    //strbf_inits(&buf, base_path, ESP_VFS_PATH_MAX+1);
    struct stat sb = {0};
    int statok, i = 0;
    //strbf_put_path(&buf, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
    //strbf_put_path(&buf, CONFIG_WEB_APP_PATH);

    //strbf_finish(&buf);
    ret = ESP_OK;
done:
    return ret;
}
#endif