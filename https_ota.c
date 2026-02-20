#include "logger_http_private.h"
#if defined(CONFIG_LOGGER_HTTP_ENABLED)
#include "https_ota.h"
#include "ota_events.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "freertos/timers.h"

// #include "esp_mac.h"
// #include "esp_system.h"
// #include "esp_timer.h"
// #include "lwip/dns.h"
// #include "lwip/err.h"
// #include "lwip/netdb.h"
// #include "lwip/sockets.h"
// #include "lwip/sys.h"


#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"

#include "context.h"
// #include "logger_config.h"
#include "unified_config.h"
#include "numstr.h"

#ifndef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
#include "esp_tls.h"
#endif

ESP_EVENT_DEFINE_BASE(OTA_AUTO_EVENT);

#if (C_LOG_LEVEL <= LOG_INFO_NUM)
static const char * const _ota_auto_event_strings[] = { OTA_EVENT_LIST(STRINGIFY_) };
const char * ota_auto_event_strings(int id) {
    return id < lengthof(_ota_auto_event_strings) ? _ota_auto_event_strings[id] : "OTA_AUTO_EVENT_UNKNOWN";
}
#else
const char * ota_auto_event_strings(int id) {return "OTA_AUTO_EVENT";}
#endif

#if !defined(CONFIG_OTA_USE_AUTO_UPDATE)
void https_ota_start() {
}
void https_ota_stop() {
}
#else

static SemaphoreHandle_t xMutex = 0;
#ifndef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
extern const uint8_t server_cert_pem_start[] asm("_binary_majasa_ca_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_majasa_ca_pem_end");
#endif

#define OTA_URL_SIZE 256

static const char *TAG = "https_ota";
extern struct context_s m_context;

#define OTA_URI_BASE CONFIG_OTA_API_SERVER_URL "/api/firmware/versions/"
#if !defined(PROJECT_NAME)
#define PROJECT_NAME "espidf-gps-logger"
#endif
static const char project_name[] = PROJECT_NAME;

#if (C_LOG_LEVEL <= LOG_INFO_NUM)
static const char * const _http_ota_events [] = {
    "ESP_HTTPS_OTA_START",                    /*!< OTA started */
    "ESP_HTTPS_OTA_CONNECTED",                /*!< Connected to server */
    "ESP_HTTPS_OTA_GET_IMG_DESC",             /*!< Read app description from image header */
    "ESP_HTTPS_OTA_VERIFY_CHIP_ID",           /*!< Verify chip id of new image */
    "ESP_HTTPS_OTA_DECRYPT_CB",               /*!< Callback to decrypt function */
    "ESP_HTTPS_OTA_WRITE_FLASH",              /*!< Flash write operation */
    "ESP_HTTPS_OTA_UPDATE_BOOT_PARTITION",    /*!< Boot partition update after successful ota update */
    "ESP_HTTPS_OTA_FINISH",                   /*!< OTA finished */
    "ESP_HTTPS_OTA_ABORT",                    /*!< OTA aborted */
};
const char * http_ota_event_strings(int id) {
    return id < lengthof(_http_ota_events) ? _http_ota_events[id] : "ESP_HTTPS_OTA_UNKNOWN";
}

/* Event handler for catching system events */
static void event_handler(void *arg, esp_event_base_t event_base, int32_t id, void *event_data) {
    if (event_base == ESP_HTTPS_OTA_EVENT) {
        FUNC_ENTRY_ARGS(TAG, "%s", http_ota_event_strings(id));
        switch (id) {
            case ESP_HTTPS_OTA_WRITE_FLASH:
                FUNC_ENTRY_ARGSD(TAG, "%d written", *(int *)event_data);
                break;
            case ESP_HTTPS_OTA_UPDATE_BOOT_PARTITION:
                FUNC_ENTRY_ARGS(TAG, "Next Partition: %d", *(esp_partition_subtype_t *)event_data);
                break;
            default:
                break;
        }
    }
}
#endif

static int find_num(const char * str) {
    return 0;
}

typedef enum {
    OTA_CHECK_VERSION_ERROR = -1,
    OTA_CHECK_VERSION_CURRENT,
    OTA_CHECK_VERSION_STR_NOT_MATCH,
    OTA_CHECK_VERSION_CHANNEL_CHANGED,
    OTA_CHECK_VERSION_MAJOR_AVAILABLE,
    OTA_CHECK_VERSION_MINOR_AVAILABLE,
    OTA_CHECK_VERSION_PATCH_AVAILABLE,
    OTA_CHECK_VERSION_BUILD_AVAILABLE,
    OTA_CHECK_VERSION_AVAILABLE
} ota_check_result_t;

static ota_check_result_t compare_app_version(const char *new_version, const char *old_version) {
    FUNC_ENTRY(TAG);
    if (!new_version || !old_version) {
        return OTA_CHECK_VERSION_ERROR;
    }
    if(!strcmp(new_version, old_version)) return OTA_CHECK_VERSION_CURRENT;
    else {
        const char * new_ptr=new_version, *old_ptr=old_version;
        int new_num = atoi(new_ptr), old_num = atoi(old_ptr);
        if(new_num > old_num) return OTA_CHECK_VERSION_MAJOR_AVAILABLE;
        if(new_num < old_num) return OTA_CHECK_VERSION_CURRENT;  // Downgrade: reject

        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return OTA_CHECK_VERSION_STR_NOT_MATCH;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return OTA_CHECK_VERSION_MINOR_AVAILABLE;
        if(new_num < old_num) return OTA_CHECK_VERSION_CURRENT;  // Downgrade: reject

        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return OTA_CHECK_VERSION_STR_NOT_MATCH;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return OTA_CHECK_VERSION_PATCH_AVAILABLE;
        if(new_num < old_num) return OTA_CHECK_VERSION_CURRENT;  // Downgrade: reject

        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return OTA_CHECK_VERSION_STR_NOT_MATCH;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return OTA_CHECK_VERSION_BUILD_AVAILABLE;
        if(new_num < old_num) return OTA_CHECK_VERSION_CURRENT;  // Downgrade: reject

        return OTA_CHECK_VERSION_STR_NOT_MATCH;
    }
}

#ifdef COMPARE_APP_VERSION_SELFTEST
static const char *ota_check_result_str(ota_check_result_t r) {
    switch (r) {
        case OTA_CHECK_VERSION_ERROR: return "ERROR";
        case OTA_CHECK_VERSION_CURRENT: return "CURRENT";
        case OTA_CHECK_VERSION_STR_NOT_MATCH: return "STR_NOT_MATCH";
        case OTA_CHECK_VERSION_CHANNEL_CHANGED: return "CHANNEL_CHANGED";
        case OTA_CHECK_VERSION_MAJOR_AVAILABLE: return "MAJOR_AVAILABLE";
        case OTA_CHECK_VERSION_MINOR_AVAILABLE: return "MINOR_AVAILABLE";
        case OTA_CHECK_VERSION_PATCH_AVAILABLE: return "PATCH_AVAILABLE";
        case OTA_CHECK_VERSION_BUILD_AVAILABLE: return "BUILD_AVAILABLE";
        case OTA_CHECK_VERSION_AVAILABLE: return "AVAILABLE";
        default: return "UNKNOWN";
    }
}

typedef struct {
    const char *new_v;
    const char *old_v;
    ota_check_result_t expect;
} compare_case_t;

static void compare_app_version_selftest(void) {
    const compare_case_t cases[] = {
        {"1.0.5.0.dev", "1.0.5.0.dev", OTA_CHECK_VERSION_CURRENT},
        {"1.1.0.0.dev", "1.0.5.0.dev", OTA_CHECK_VERSION_MAJOR_AVAILABLE},
        {"1.0.6.0.dev", "1.0.5.0.dev", OTA_CHECK_VERSION_PATCH_AVAILABLE},
        {"1.0.5.10.dev", "1.0.5.0.dev", OTA_CHECK_VERSION_BUILD_AVAILABLE},
        // Downgrade case: new patch lower than current
        {"1.0.4.25.dev", "1.0.5.0.dev", OTA_CHECK_VERSION_STR_NOT_MATCH},
    };

    for (size_t i = 0; i < lengthof(cases); ++i) {
        ota_check_result_t r = compare_app_version(cases[i].new_v, cases[i].old_v);
        bool pass = (r == cases[i].expect);
        WLOG(TAG, "[compare_app_version_selftest] new=%s old=%s -> got=%s (%d) expect=%s (%d) %s",
            cases[i].new_v,
            cases[i].old_v,
            ota_check_result_str(r), r,
            ota_check_result_str(cases[i].expect), cases[i].expect,
            pass ? "PASS" : "FAIL");
    }
}
#endif

static ota_check_result_t validate_image_header(esp_app_desc_t *new_app_info) {
    FUNC_ENTRY(TAG);
    if (new_app_info == NULL) {
        return OTA_CHECK_VERSION_ERROR;
    }

    esp_app_desc_t running_app_info;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if(esp_ota_get_partition_description(running, &running_app_info)) {
        running_app_info.version[0] = '\0';
        return OTA_CHECK_VERSION_ERROR;
    }
    const char *new_version = *new_app_info->version ? new_app_info->version : "null";
    const char *running_version = *running_app_info.version ? running_app_info.version : "null";
    const char dev_str[] = "dev";
    size_t len = strlen(running_version), dlen = sizeof(dev_str) - 1;
    ota_check_result_t res = OTA_CHECK_VERSION_ERROR;
    if(g_rtc_config.fw_update.update_channel == FW_UPDATE_CHANNEL_DEV && running_version && len >= dlen && !strstr(running_version+len-dlen, dev_str)) { // device is prod, but should be dev
        WLOG(TAG, "[%s] Device is in dev channel, but running version(%s) is prod, will reload.", __func__, running_version);
        goto set;
    }
    if(g_rtc_config.fw_update.update_channel == FW_UPDATE_CHANNEL_PROD && running_version && len >= dlen && strstr(running_version+len-dlen, dev_str) >= running_version + len-dlen) { // device is dev, but should be prod
        WLOG(TAG, "[%s] Device is in prod channel, but running version(%s) is dev, will reload.", __func__, running_version);
        set:
        res = OTA_CHECK_VERSION_CHANNEL_CHANGED;
        goto done;
    }
#ifndef CONFIG_OTA_SKIP_VERSION_CHECK
    res = compare_app_version(new_version, running_version);
    WLOG(TAG, "[%s]  cur: %s, new: %s, check: %d.", __func__, running_version, new_version, res);
#endif
    done:
    return res;
}

#if (C_LOG_LEVEL <= LOG_INFO_NUM)
static const char * const _http_client_events [] = {
    "HTTP_EVENT_ERROR",
    "HTTP_EVENT_ON_CONNECTED",
    "HTTP_EVENT_HEADER_SENT",
    "HTTP_EVENT_ON_HEADER",
    "HTTP_EVENT_ON_DATA",
    "HTTP_EVENT_ON_FINISH",
    "HTTP_EVENT_DISCONNECTED",
    "HTTP_EVENT_REDIRECT",
};
static const size_t _http_client_events_count = sizeof(_http_client_events) / sizeof(_http_client_events[0]);
const char * http_client_events(int id) {
    return id < (int)_http_client_events_count ? _http_client_events[id] : "HTTP_EVENT";
}
#else
const char * http_client_events(int id) {
    return "HTTP_EVENT";
}
#endif

#define LOCAL_BUF_LEN 64
// static char *output_buffer=0;  // Buffer to store response of http request from event handler
static int output_len=0;       // Stores number of bytes read
static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    int32_t id = evt->event_id;
    FUNC_ENTRY_ARGS(TAG, "%s(%" PRId32 ")", http_client_events(id), id);
    switch (id) {
        case HTTP_EVENT_ERROR:
             break;
        case HTTP_EVENT_ON_DATA:
            if (output_len == 0 && evt->user_data) {
                // ILOG(TAG, "[%s] Resetting user_data buffer", __func__);
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, LOCAL_BUF_LEN);
            }
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    copy_len = MIN(evt->data_len, (LOCAL_BUF_LEN - output_len));
                    memcpy(evt->user_data + output_len, evt->data, copy_len);
                }
                output_len += copy_len;
                // FUNC_ENTRY_ARGS(TAG, "'%s' %d", (char*)evt->user_data, output_len);
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            output_len = 0;
            break;
        default:
            break;
    }
    return ESP_OK;
}

static char local_response_buffer[LOCAL_BUF_LEN] = {0};
static char version_url[OTA_URL_SIZE] = {0};  // Built per-request and cached for reuse
static char placeholder_url[OTA_URL_SIZE] = {0};  // Placeholder URL for client init
size_t version_url_len = 0;

RTC_DATA_ATTR uint64_t last_check = 0, next_check = 0;
static uint8_t ota_task_started = 0;
static TaskHandle_t ota_task_handle = NULL;  // Handle to wake task on stop

#ifdef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
#define OTA_URI "http://" OTA_URI_BASE
#else
#define OTA_URI "https://" OTA_URI_BASE
#endif

// Forward declare URL builder
static esp_err_t build_version_url(void);

static esp_http_client_config_t config = {
    .keep_alive_enable = true,
    .timeout_ms = CONFIG_OTA_RECV_TIMEOUT,
#ifndef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
    .cert_pem = (char *)server_cert_pem_start,
#ifdef CONFIG_SKIP_COMMON_NAME_CHECK
    .skip_cert_common_name_check = true;
#endif
#endif
};

/**
 * @brief Build version check URL based on update channel
 */
static esp_err_t build_version_url(void) {
    int i = snprintf(version_url, OTA_URL_SIZE, OTA_URI"_%sstable",
        (g_rtc_config.fw_update.update_channel == FW_UPDATE_CHANNEL_DEV) ? "un" : ""
    );
    if (i < 0 || (size_t)i >= OTA_URL_SIZE) {
        ELOG(TAG, "[%s] URL buffer overflow", __func__);
        return ESP_ERR_NO_MEM;
    }
    version_url_len = (size_t)i;
    FUNC_ENTRY_ARGS(TAG, "url:%s len:%zu", version_url, version_url_len);
    return ESP_OK;
}

static esp_err_t ota_get_image_path(char *ota_url, size_t ota_url_size) {
    FUNC_ENTRY(TAG);
    if (!ota_url) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t ret = ESP_OK;

    // Build version URL for this request
    esp_err_t url_err = build_version_url();
    if (url_err != ESP_OK) {
        return url_err;
    }
    // Create a fresh HTTP client for this request to avoid reuse issues
    esp_http_client_config_t vcfg = config;
    vcfg.url = version_url;
    vcfg.event_handler = _http_event_handler;
    vcfg.user_data = local_response_buffer;
    esp_http_client_handle_t client = esp_http_client_init(&vcfg);
    if (!client) {
        ELOG(TAG, "[%s] Failed to init http client", __func__);
        return ESP_FAIL;
    }

    memset(local_response_buffer, 0, LOCAL_BUF_LEN);
    output_len = 0;
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        uint32_t wait_until = get_millis() + 5000; // 5 seconds timeout
        while(!esp_http_client_is_complete_data_received(client)) {
            vTaskDelay(pdMS_TO_TICKS(100));
            if(get_millis() >= wait_until) {
                ELOG(TAG, "HTTP GET request complete timeout...");
                ret = ESP_ERR_TIMEOUT;
                goto done;
            }
        }
        DLOG(TAG, "HTTP GET Status = %d, content_length = %"PRId64" resp = %s",
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client), local_response_buffer);
        int len = esp_http_client_get_content_length(client);
        int copy_len = MIN(len, LOCAL_BUF_LEN - 1);
        local_response_buffer[copy_len] = 0;
        // FUNC_ENTRY_ARGSD(TAG, "'%s' %d %d", local_response_buffer, output_len, len);
        if (len > 0) {
            while(local_response_buffer[len-1] == '\n' || local_response_buffer[len-1] == '\r' || local_response_buffer[len-1] == ' ') {
                local_response_buffer[--len]=0;
            }
            if(!len) {
                ret = ESP_ERR_NOT_FOUND;
                goto done;
            }
            if(!strcmp(local_response_buffer, PROJECT_VER_PACKED)) {
                ILOG(TAG, "Firmware remote version %s is up to date with local.", local_response_buffer);
                ret = 1;
                goto done;
            }
            size_t ota_url_len = 0;
#ifdef AAAAA
            ota_url[ota_url_len] = sizeof(OTA_URI)-1;
            memcpy(ota_url, OTA_URI, ota_uri_len);
            memcpy(ota_url+ota_url_len, local_response_buffer, len), ota_url_len += len;
            *(ota_url+ota_url_len++) = '/';
            memcpy(ota_url+ota_url_len, project_name, sizeof(project_name)-1), ota_url_len += sizeof(project_name)-1;
            *(ota_url+ota_url_len++) = '-';
            memcpy(ota_url+ota_url_len, local_response_buffer, len), ota_url_len += len;
#if defined(VER_STR_EXT)
            *(ota_url+ota_url_len++) = '-';
            memcpy(ota_url+ota_url_len, VER_STR_EXT, sizeof(VER_STR_EXT)-1), ota_url_len += sizeof(VER_STR_EXT)-1;
#endif
            memcpy(ota_url+ota_url_len, ".bin", 4), ota_url_len += 4;
            ota_url[ota_url_len] = 0;
#else
            int n = snprintf(ota_url, ota_url_size, OTA_URI"%s/"PROJECT_NAME"-%s"
#if defined(VER_STR_EXT)
                    "-"VER_STR_EXT
#endif
            ".bin",
                    local_response_buffer,
                    local_response_buffer
                );
            if (n < 0 || (size_t)n >= ota_url_size) {
                ret = ESP_ERR_NO_MEM;
                goto done;
            }
#endif
            ILOG(TAG, "OTA URL: %s", ota_url);
        }
    } else {
        ELOG(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    done:
    if (client) {
        esp_http_client_cleanup(client);
    }
    return ret;
}

static esp_err_t _http_client_init_cb(esp_http_client_handle_t http_client) {
    esp_err_t err = ESP_OK;
    /* Uncomment to add custom headers to HTTP request */
    // err = esp_http_client_set_header(http_client, "Custom-Header", "Value");
    return err;
}

#define FW_ALLOW_WAIT_SLICE_MS 200
static bool wait_for_fw_permission(uint32_t deadline_ms) {
    while (!m_context.fw_update_is_allowed) {
        if (!ota_task_started || m_context.fw_update_postponed) {
            return false;
        }
        uint32_t now = get_millis();
        if (now >= deadline_ms) {
            return false;
        }
        uint32_t slice_ms = deadline_ms - now;
        if (slice_ms > FW_ALLOW_WAIT_SLICE_MS) {
            slice_ms = FW_ALLOW_WAIT_SLICE_MS;
        }
        if (ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(slice_ms))) {
            // Stop notification received
            return false;
        }
    }
    return true;
}

static esp_err_t ota_get_task(void *pvParameter) {
    FUNC_ENTRY(TAG);
    uint32_t wait_until = m_context.fw_update_postponed;
    esp_err_t ret = ESP_OK;
    if(wait_until && get_millis() < wait_until) {
        return ret;
    }
    if(xSemaphoreTake(xMutex, 0) == pdTRUE) {
        esp_https_ota_handle_t https_ota_handle = NULL;
        // esp_err_t ota_finish_err = ESP_OK;
        char img_url[OTA_URL_SIZE] = {0};
        ret = ota_get_image_path(img_url, OTA_URL_SIZE);
        if(ret == 1) {
            WLOG(TAG, "Remote image (%s) not found, cancel", img_url);
            goto ota_cancel;
        }
        else if(ret < 0) {
            goto ota_fail_no_msg;
        }

        // Build a per-download HTTP config without mutating global config
        esp_http_client_config_t dl_http_cfg = config;
        dl_http_cfg.url = img_url;
        esp_https_ota_config_t ota_config = {
            .http_config = &dl_http_cfg,
            .http_client_init_cb =
                _http_client_init_cb,  // Register a callback to be invoked after esp_http_client is initialized
#ifdef CONFIG_OTA_ENABLE_PARTIAL_HTTP_DOWNLOAD
            .partial_http_download = true,
            .max_http_request_size = CONFIG_OTA_HTTP_REQUEST_SIZE,
#endif
        };

        ret = esp_https_ota_begin(&ota_config, &https_ota_handle);
        if (ret != ESP_OK) {
            // ELOG(TAG, "[%s] Begin failed", __func__);
            goto ota_fail_no_msg;
        }

        esp_app_desc_t app_desc;
        ret = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
        if (ret != ESP_OK) {
            // ELOG(TAG, "[%s] esp_http_ota_read_img_desc failed", __func__);
            goto ota_fail_no_msg;
        }
        ota_check_result_t ota_check_result = validate_image_header(&app_desc);
        if (ota_check_result <= OTA_CHECK_VERSION_STR_NOT_MATCH) {
            if(ota_check_result > OTA_CHECK_VERSION_ERROR) {
                goto ota_cancel;
            }
            ret = ESP_ERR_OTA_VALIDATE_FAILED;
            goto ota_fail_no_msg;
        }

        esp_event_post(OTA_AUTO_EVENT, OTA_AUTO_EVENT_UPDATE_AVAILABLE, NULL,0, portMAX_DELAY);

        // m_context.firmware_update_started = 2;
        vTaskDelay(pdMS_TO_TICKS(100));

        wait_until = get_millis() + 60000;
        if (!wait_for_fw_permission(wait_until)) {
            if (ota_task_started) {
                WLOG(TAG, "Firmware update not allowed by user...");
            }
            goto ota_cancel;
        }
        esp_event_post(OTA_AUTO_EVENT, OTA_AUTO_EVENT_UPDATE_START, NULL,0, portMAX_DELAY);
        while (1) {
            ret = esp_https_ota_perform(https_ota_handle);
            if (ret != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
                break;
            }
            // esp_https_ota_perform returns after every read operation which gives
            // user the ability to monitor the status of OTA upgrade by calling
            // esp_https_ota_get_image_len_read, which gives length of image data
            // read so far.
        }

        if (!esp_https_ota_is_complete_data_received(https_ota_handle)) {
            // the OTA image was not completely received and user can customise the
            // response to this situation.
            // ELOG(TAG, "[%s] Complete data was not received.", __func__);
            ret = ESP_FAIL;
        } else {
            ret = esp_https_ota_finish(https_ota_handle);
            if (ret == ESP_OK) {
                https_ota_handle = NULL;
                FUNC_ENTRY_ARGS(TAG, "upgrade successful. Rebooting ...");
                // m_context.request_restart = 1;
                goto ota_finish;
            }
        }
    ota_finish:
        // m_context.firmware_update_started = 0;
        if(ret != ESP_OK) {
            ELOG(TAG, "[%s] upgrade failed, url: %s", __func__, img_url);
            esp_event_post(OTA_AUTO_EVENT, OTA_AUTO_EVENT_UPDATE_FAILED, NULL,0, portMAX_DELAY);
        }
        else {
            esp_event_post(OTA_AUTO_EVENT, OTA_AUTO_EVENT_UPDATE_FINISH, NULL,0, portMAX_DELAY);
        }
    ota_done:
        if(https_ota_handle)
            esp_https_ota_abort(https_ota_handle);
        if(xMutex)
            xSemaphoreGive(xMutex);

    }
    return ret;
    ota_cancel:
    ret = ESP_OK;
    goto ota_done;
    ota_fail_no_msg:
    goto ota_done;
}

void ota_task(void *pvParameter) {
    FUNC_ENTRY(TAG);
    esp_err_t ret = ESP_OK;
    uint32_t check_interval_ms = SEC_TO_MS(CONFIG_OTA_CHECK_INTERVAL) * 60UL; // Convert minutes to milliseconds
    ILOG(TAG, "Starting OTA task, check interval: %" PRIu32 " ms", check_interval_ms);

    // Initial delay before first check
    vTaskDelay(pdMS_TO_TICKS(SEC_TO_MS(10)));

    while (ota_task_started) {
        ota_get_task(pvParameter);

        if (!ota_task_started) {
            break;
        }

        // Block for the check interval or until notified to stop
        // ulTaskNotifyTake returns non-zero if notified, zero if timeout
        uint32_t notified = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(check_interval_ms));
        if (notified) {
            // Task was notified to stop immediately
            DLOG(TAG, "OTA task stop notification received");
            break;
        }
    }
    vTaskDelete(NULL);
}

void https_ota_start() {
    FUNC_ENTRY(TAG);
    esp_err_t err = 0;

    // Build version URL once at startup
    if (build_version_url() != ESP_OK) {
        ELOG(TAG, "[%s] Failed to build version URL", __func__);
        return;
    }

    // No cached client; we create and cleanup per request

#if C_LOG_LEVEL <= LOG_INFO_NUM
    esp_event_handler_register(ESP_HTTPS_OTA_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL);
#endif

#if defined(CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE)
    /**
     * We are treating successful WiFi connection as a checkpoint to cancel
     * rollback process and mark newly updated firmware image as active. For
     * production cases, please tune the checkpoint behavior per end application
     * requirement.
     */
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
                FUNC_ENTRY_ARGS(TAG, "App is valid, rollback cancelled successfully");
            } else {
                ELOG(TAG, "Failed to cancel rollback");
            }
        }
    }
#endif
    if (xMutex == NULL)
        xMutex = xSemaphoreCreateMutex();
    ota_task_started = 1;
    xTaskCreatePinnedToCore(&ota_task, "ota_task", CONFIG_OTA_AUTO_UPDATE_TASK_STACK_SIZE, NULL, 3, &ota_task_handle, 0);
}

void https_ota_stop() {
    FUNC_ENTRY(TAG);
    ota_task_started = 0;

    // Wake OTA task immediately to exit any pending delay
    if (ota_task_handle) {
        xTaskNotifyGive(ota_task_handle);
        ota_task_handle = NULL;
    }
#if C_LOG_LEVEL <= LOG_INFO_NUM
    esp_event_handler_unregister(ESP_HTTPS_OTA_EVENT, ESP_EVENT_ANY_ID, &event_handler);
#endif

    if (xMutex != NULL){
        vSemaphoreDelete(xMutex);
        xMutex = NULL;
    }
    // No cached HTTP client to cleanup
}

#endif
#endif
