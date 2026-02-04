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
#include "esp_netif.h"
#include "esp_system.h"
#include "mdns.h"

#include "http_rest_server.h"
#include "http_async_handler.h"
#include "strbf.h"
#include "uri_common.h"
// #include "context.h"
// #include "logger_config.h"
#include "unified_config.h"
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
#include "https_ota.h"
#endif
#if defined(CONFIG_LOGGER_WIFI_ENABLED)
#include "logger_wifi.h"
#else
struct m_wifi_context wifi_context = {.hostname = "esp32"};
#endif
#if defined(CONFIG_LOGGER_VFS_ENABLED)
// #include "vfs.h"
#endif

#define HTTP_QUERY_KEY_MAX_LEN (64)

extern struct context_s m_context;
/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "http_server";

httpd_handle_t *server = 0;
// Task handle and state management for deferred HTTP server operations
static TaskHandle_t http_server_task_handle = NULL;
static volatile bool http_server_desired_state = false; // false=stop, true=start
static volatile bool http_server_state_changed = false;

uint8_t downloading_file = 0;
bool http_rest_initialized = false;
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
      .handler = long_post_handler,
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
      .handler = long_get_handler,
      .user_ctx = (void *)&rest_server_context[2]}},
    {0}};


static const char * http_rest_server_errors[] = {
    "Error starting server",
    "Failed to stop http server",
    "Failed to set up mDNS service",
};

httpd_handle_t start_webserver(void) {
    FUNC_ENTRY(TAG);
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = CONFIG_WEB_SERVER_TASK_STACK_SIZE;
    config.lru_purge_enable = true;

    // Start the httpd server
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        FUNC_ENTRY_ARGSD(TAG, "Registering URI handlers");
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
    FUNC_ENTRY(TAG);
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
    FUNC_ENTRY(TAG);
    // Ensure at least one WiFi netif exists and is up before starting mDNS
    const TickType_t wait_ticks = pdMS_TO_TICKS(5000);
    TickType_t start = xTaskGetTickCount();
    esp_netif_t *netif_ap = NULL;
    esp_netif_t *netif_sta = NULL;
    while (true) {
        netif_ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        netif_sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        bool ap_up = netif_ap && esp_netif_is_netif_up(netif_ap);
        bool sta_up = netif_sta && esp_netif_is_netif_up(netif_sta);
        if (ap_up || sta_up) {
            break;
        }
        if ((xTaskGetTickCount() - start) >= wait_ticks) {
            WLOG(TAG, "[%s] Netif not ready for mDNS, skipping init", __func__);
            return ESP_ERR_INVALID_STATE;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    esp_err_t ret = mdns_init();
    if(ret) goto done;
    size_t len = 0;
    char * hn = 0;
    hn = wifi_context.hostname;

    if(g_rtc_config.advanced.hostname[0] != '\0') {
        len = MIN(strlen(g_rtc_config.advanced.hostname), 32);
        memcpy(hn, g_rtc_config.advanced.hostname, len);
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
    if(ret) {
        WLOG(TAG, "%s: %s", http_rest_server_errors[2], esp_err_to_name(ret));
    }
    else {
        ILOG(TAG, "mDNS initialized with hostname: %s", hn);
    }
    return ret;
}

static esp_err_t deinitialise_mdns(void) {
    esp_err_t ret = mdns_service_remove_all();
    mdns_free();
    return ret;
}

// Refresh mDNS bindings to currently active netifs (AP/STA)
static void refresh_mdns(void) {
    FUNC_ENTRY(TAG);
    // If HTTP server is running, safely re-init mDNS to include any new/up netifs
    deinitialise_mdns();
    initialise_mdns();
    ILOG(TAG, "mDNS refreshed for current netifs (AP/STA)");
}

// Unified task for HTTP server start/stop (prevents event loop blocking)
// Processes state changes in a loop until reaching stable desired state
// This handles rapid start→stop→start sequences without race conditions
static void http_server_task(void *arg) {
    FUNC_ENTRY(TAG);
    // Loop until current state matches desired state
    while (true) {
        bool current_running = (server != NULL);
        bool desired_running = http_server_desired_state;
        
        // Check if we've reached the desired state
        if (current_running == desired_running && !http_server_state_changed) {
            DLOG(TAG, "[http_server_task] Reached stable state (running=%d)", current_running);
            break;
        }
        
        http_server_state_changed = false;
        
        if (desired_running && !current_running) {
            // Need to start server
            ILOG(TAG, "[http_server_task] Starting HTTP server");
#if defined(CONFIG_WEB_SERVER_ASYNC_WORKER_ENABLED) && (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 0)
            start_async_req_workers();
#endif
            server = start_webserver();
            initialise_mdns();
            
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
            // Start OTA if STA is active and update is enabled
            if (wifi_is_sta_connecting() && g_rtc_config.fw_update.update_enabled) {
                ILOG(TAG, "[http_server_task] Starting OTA (STA active)");
                https_ota_start();
            }
#endif
        } else if (!desired_running && current_running) {
            // Need to stop server
            ILOG(TAG, "[http_server_task] Stopping HTTP server");
            
#if defined(CONFIG_OTA_USE_AUTO_UPDATE)
            // Stop OTA if update is enabled
            if (g_rtc_config.fw_update.update_enabled) {
                ILOG(TAG, "[http_server_task] Stopping OTA");
                https_ota_stop();
            }
#endif
            
            deinitialise_mdns();
            esp_err_t ret = stop_webserver(server);
            if (!ret) {
                server = NULL;
            } else {
                ELOG(TAG, "Failed to stop http server");
            }
#if defined(CONFIG_WEB_SERVER_ASYNC_WORKER_ENABLED) && (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 0)
            stop_async_req_workers();
#endif
        }
        
        // Small delay to allow state updates from events
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    // Task cleanup
    http_server_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t http_start_webserver() {
    FUNC_ENTRY(TAG);
    
    // Set desired state to running
    http_server_desired_state = true;
    http_server_state_changed = true;
    
    // If task already running, it will pick up the state change
    if (http_server_task_handle != NULL) {
        DLOG(TAG, "HTTP server task already running, updated desired state");
        return ESP_OK;
    }
    
    // If already running and no task, we're done
    if (server != NULL) {
        DLOG(TAG, "HTTP server already running");
        return ESP_OK;
    }
    
    // Create task to start server
    BaseType_t ret = xTaskCreate(http_server_task, "http_srv", 4096, NULL, 3, &http_server_task_handle);
    
    if (ret != pdPASS) {
        ELOG(TAG, "Failed to create HTTP server task");
        http_server_task_handle = NULL;
        return ESP_FAIL;
    }
    
    DLOG(TAG, "HTTP server start deferred to background task");
    return ESP_OK;
}

esp_err_t http_stop_webserver() {
    FUNC_ENTRY(TAG);
    
    // Set desired state to stopped
    http_server_desired_state = false;
    http_server_state_changed = true;
    
    // If task already running, it will pick up the state change
    if (http_server_task_handle != NULL) {
        DLOG(TAG, "HTTP server task already running, updated desired state");
        return ESP_OK;
    }
    
    // If already stopped and no task, we're done
    if (server == NULL) {
        DLOG(TAG, "HTTP server already stopped");
        return ESP_OK;
    }
    
    // Create task to stop server
    BaseType_t ret = xTaskCreate(http_server_task, "http_srv", 4096, NULL, 3, &http_server_task_handle);
    
    if (ret != pdPASS) {
        ELOG(TAG, "Failed to create HTTP server task");
        http_server_task_handle = NULL;
        return ESP_FAIL;
    }
    
    DLOG(TAG, "HTTP server stop deferred to background task");
    return ESP_OK;
}

#if defined(HTTP_CONN_HANDLERS)
void disconnect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server) {
        deinitialise_mdns();
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ELOG(TAG, "%s", http_rest_server_errors[1]);
        }
#if defined(CONFIG_WEB_SERVER_ASYNC_WORKER_ENABLED) && (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 0)
        stop_async_req_workers();
#endif
    }
}

void connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL) {
#if defined(CONFIG_WEB_SERVER_ASYNC_WORKER_ENABLED) && (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 0)
        start_async_req_workers();
#endif
        *server = start_webserver();
        initialise_mdns();
    }
}
#endif
#endif  // !CONFIG_IDF_TARGET_LINUX

#if (C_LOG_LEVEL <= LOG_INFO_NUM)
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
static const size_t _http_server_events_count = sizeof(_http_server_events) / sizeof(_http_server_events[0]);
const char * http_server_events(int id) {
    return id < (int)_http_server_events_count ? _http_server_events[id] : "HTTP_SERVER_EVENT";
}
#else
const char * http_server_events(int id) {return "HTTP_SERVER_EVENT";}
#endif

static void esp_http_server_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data) {
#if (C_LOG_LEVEL <= LOG_INFO_NUM)
    if(base == ESP_HTTP_SERVER_EVENT) {
        // esp_http_server_event_data *data = (esp_http_server_event_data *)event_data;
        if(id == HTTP_SERVER_EVENT_ON_DATA) printf(".");
        else if(id == HTTP_SERVER_EVENT_SENT_DATA) printf(",");
        else
            FUNC_ENTRY_ARGS(TAG, "%s", http_server_events(id));
    }
#endif
#if defined (CONFIG_LOGGER_WIFI_ENABLED)
#if (C_LOG_LEVEL <= LOG_INFO_NUM)
    else
#endif
    if(base == WIFI_EVENT) {
        switch(id) {
            case WIFI_EVENT_AP_START:
                // Start server if not running, else refresh mDNS to add AP
                if (server == NULL) {
                    http_start_webserver();
                } else {
                    refresh_mdns();
                }
                break;
            case WIFI_EVENT_AP_STOP:
                if (!wifi_is_sta_connecting()) {
                    http_stop_webserver();
                } else {
                    // Keep server for STA, refresh mDNS to drop AP
                    if (server != NULL) refresh_mdns();
                }
                break;
            default:
                break;
        }
    }
    else if(base == IP_EVENT) {
        switch(id) {
            case IP_EVENT_STA_GOT_IP:
                // Start server if not running, else refresh mDNS to add STA
                if (server == NULL) {
                    http_start_webserver();
                } else {
                    refresh_mdns();
                }
                break;
            case IP_EVENT_STA_LOST_IP:
                if (!wifi_is_ap_ready()) {
                    http_stop_webserver();
                } else {
                    // Keep server for AP, refresh mDNS to drop STA
                    if (server != NULL) refresh_mdns();
                }
                break;
            default:
                break;
        }
    }
#endif
}
esp_err_t http_rest_init(const char *basepath) {
    FUNC_ENTRY(TAG);
    if(http_rest_initialized) {
        WLOG(TAG, "[%s] already initialized", __func__);
        return ESP_OK;
    }
    esp_err_t ret = ESP_OK;
    // if (!basepath){
    //     ret = ESP_FAIL;
    //     goto done;
    // }
    if(esp_event_handler_register(ESP_EVENT_ANY_BASE, ESP_EVENT_ANY_ID, &esp_http_server_event_handler, NULL)) {
        ELOG(TAG, "[%s] Failed to register event handler", __func__);
        ret = ESP_FAIL;
        goto done;
    }
    //strbf_t buf;
    //strbf_inits(&buf, base_path, ESP_VFS_PATH_MAX+1);
    // struct stat sb = {0};
    // int statok, i = 0;
    //strbf_put_path(&buf, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
    //strbf_put_path(&buf, CONFIG_WEB_APP_PATH);

    //strbf_finish(&buf);
    http_rest_initialized = true;
    ret = ESP_OK;
done:
    return ret;
}
#endif