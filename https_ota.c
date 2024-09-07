#include "https_ota.h"

#include "sdkconfig.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "freertos/timers.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"


#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"

#include "logger_events.h"
#include "logger_http_private.h"
#include "logger_common.h"
#include "context.h"
#include "logger_config.h"
#include "str.h"

#include "esp_tls.h"

#if !defined(CONFIG_OTA_USE_AUTO_UPDATE)
void https_ota_start() {
}
void https_ota_stop() {
}
#else

static SemaphoreHandle_t xMutex = 0;
extern const uint8_t server_cert_pem_start[] asm("_binary_majasa_ca_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_majasa_ca_pem_end");

#define OTA_URL_SIZE 256

static const char *TAG = "https_ota";
extern struct context_s m_context;

#define OTA_URI_BASE CONFIG_OTA_API_SERVER_URL "/api/firmware/versions/"

const char * const http_ota_events [] = {
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

/* Event handler for catching system events */
static void event_handler(void *arg, esp_event_base_t event_base, int32_t id, void *event_data) {
    if (event_base == ESP_HTTPS_OTA_EVENT) {
        switch (id) {
            case ESP_HTTPS_OTA_START:
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_CONNECTED:
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_GET_IMG_DESC:
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_VERIFY_CHIP_ID:
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_DECRYPT_CB:
                ILOG(TAG, "[%s] %s", __FUNCTION__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_WRITE_FLASH:
                ESP_LOGD(TAG, "[%s] %s: %d written", __func__, http_ota_events[id], *(int *)event_data);
                break;
            case ESP_HTTPS_OTA_UPDATE_BOOT_PARTITION:
                ILOG(TAG, "[%s] %s. Next Partition: %d", __func__, http_ota_events[id], *(esp_partition_subtype_t *)event_data);
                break;
            case ESP_HTTPS_OTA_FINISH:
                ILOG(TAG, "[%s] %s", __func__, http_ota_events[id]);
                break;
            case ESP_HTTPS_OTA_ABORT:
                ILOG(TAG, "[%s] %s", __func__, http_ota_events[id]);
                break;
            default:
                break;
        }
    }
}

static int find_num(const char * str) {
    return 0;
}

static int8_t compare_app_version(const char *new_version, const char *old_version) {
    if (!new_version || !old_version) {
        return -1;
    }
    if(!strcmp(new_version, old_version)) return 0;
    else {
        const char * new_ptr=new_version, *old_ptr=old_version;
        int new_num = atoi(new_ptr), old_num = atoi(old_ptr);
        if(new_num > old_num) return 1; // VERSION_MAJOR
        
        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return -1;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return 2; // VERSION_MINOR

        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return -1;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return 3; // VERSION_PATCH

        new_ptr = strchr(new_ptr, '.'), old_ptr = strchr(old_ptr, '.');
        if(!new_ptr || !old_ptr) return -1;
        if(++new_ptr) new_num = atoi(new_ptr);
        if(++old_ptr) old_num = atoi(old_ptr);
        if(new_num > old_num) return 4; // VERSION_BUILD

        return -1;
    }
}

static esp_err_t validate_image_header(esp_app_desc_t *new_app_info) {
    if (new_app_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_app_desc_t running_app_info;
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_get_partition_description(running, &running_app_info);
    const char *new_version = *new_app_info->version ? new_app_info->version : "null";
    const char *running_version = *running_app_info.version ? running_app_info.version : "null";

#ifndef CONFIG_OTA_SKIP_VERSION_CHECK
    if (compare_app_version(new_app_info->version, running_app_info.version) <= 0) {
        ESP_LOGW(TAG, "[%s] device version(%s) is sync with remote version(%s), will not continue.", __func__, running_version, new_version);
        return 1;
    } else {
        ESP_LOGI(TAG, "[%s] device version(%s) is < remote version(%s), continue.", __func__, running_version, new_version);
    }
#endif

#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    /**
     * Secure version check from firmware image header prevents subsequent
     * download and flash write of entire firmware image. However this is
     * optional because it is also taken care in API esp_https_ota_finish at the
     * end of OTA update procedure.
     */
    const uint32_t hw_sec_version = esp_efuse_read_secure_version();
    if (new_app_info->secure_version < hw_sec_version) {
        ESP_LOGW(TAG, "[%s] New firmware security version is less than eFuse programmed, "
                 "%" PRIu32 " < %" PRIu32, __func__, new_app_info->secure_version, hw_sec_version);
        return ESP_FAIL;
    }
#endif

    return ESP_OK;
}

const char * const http_client_events [] = {
    "HTTP_EVENT_ERROR",
    "HTTP_EVENT_ON_CONNECTED",
    "HTTP_EVENT_HEADER_SENT",
    "HTTP_EVENT_ON_HEADER",
    "HTTP_EVENT_ON_DATA",
    "HTTP_EVENT_ON_FINISH",
    "HTTP_EVENT_DISCONNECTED",
    "HTTP_EVENT_REDIRECT",
};

#define LOCAL_BUF_LEN 16
// static char *output_buffer=0;  // Buffer to store response of http request from event handler
static int output_len=0;       // Stores number of bytes read
static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    int32_t id = evt->event_id;
    switch (id) {
        // case HTTP_EVENT_ERROR:
        //     ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
        //     break;
        // case HTTP_EVENT_ON_CONNECTED:
        //     ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
        //     break;
        // case HTTP_EVENT_HEADER_SENT:
        //     ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
        //     break;
        // case HTTP_EVENT_ON_HEADER:
        //     ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
        //     printf("%.*s", evt->data_len, (char *)evt->data);
        //     break;
        case HTTP_EVENT_ON_DATA:
            ILOG(TAG, "[%s] %s, len=%d", __func__, http_client_events[id], evt->data_len);
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
                // ILOG(TAG, "[%s] '%s' %d", __func__, (char*)evt->user_data, output_len);
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
            output_len = 0;
            break;
        // case HTTP_EVENT_REDIRECT:
        //     ILOG(TAG, "[%s] %s", __FUNCTION__, http_client_events[id]);
        //     break;
        default:
            break;
    }
    return ESP_OK;
}

static char local_response_buffer[LOCAL_BUF_LEN] = {0};
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

static char version_url[OTA_URL_SIZE] = {0};
size_t version_url_len = 0;
static esp_err_t ota_get_image_path(char *ota_url, size_t ota_url_size) {
    ILOG(TAG, "[%s]", __func__);
    if (!ota_url) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t ret = ESP_OK;
    memset(local_response_buffer, 0, LOCAL_BUF_LEN);
    version_url_len = 7 + sizeof(OTA_URI_BASE) - 1;
#ifdef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
    memcpy(&version_url[0], "http://"OTA_URI_BASE, version_url_len);
#else
    memcpy(&version_url[0], "https://"OTA_URI_BASE, ++version_url_len);
#endif
    if(m_context.config->fwupdate.channel == FW_UPDATE_CHANNEL_DEV) {
        memcpy(&version_url[version_url_len], "_unstable", 9);
    } else {
        memcpy(&version_url[version_url_len], "_stable", 7);
    }
    version_url_len += (m_context.config->fwupdate.channel == FW_UPDATE_CHANNEL_DEV) ? 9 : 7;
    version_url[version_url_len] = 0;
    config.url = &version_url[0];
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 3)
    printf("URL: %s %u\n", config.url, version_url_len);
#endif
    config.event_handler = _http_event_handler;
    config.user_data = local_response_buffer;        // Pass address of local buffer to get response

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        uint32_t wait_until = get_millis() + 5000;
        while(!esp_http_client_is_complete_data_received(client)) {
            delay_ms(200);
            if(get_millis() >= wait_until) {
                ESP_LOGE(TAG, "HTTP GET request complete timeout...");
                break;
            }
        }
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 1)
        ILOG(TAG, "HTTP GET Status = %d, content_length = %"PRId64" resp = %s",
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client), local_response_buffer);
#endif
        int len = esp_http_client_get_content_length(client);
        local_response_buffer[len]=0;
        // ILOG(TAG, "[%s] '%s' %d %d", __func__, local_response_buffer, output_len, len);
        if (len > 0) {
            while(local_response_buffer[len-1] == '\n' || local_response_buffer[len-1] == '\r' || local_response_buffer[len-1] == ' ') {
                local_response_buffer[--len]=0;
            }
            if(!len) {
                ret = ESP_ERR_NOT_FOUND;
                goto done;
            }
            uint16_t version = atoi(local_response_buffer);
            if(version < semVer()) {
                ILOG(TAG, "Firmware version %hu is up to date with local %hu.", version, semVer());
                ret = 1;
                goto done;
            }
            size_t ota_url_len = 0;
            memcpy(ota_url, "http", 4), ota_url_len = 4;
#ifndef CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP
            ota_url[ota_url_len++] = 's';
#endif
            memcpy(ota_url+ota_url_len, "://", 3), ota_url_len += 3;
            memcpy(ota_url+ota_url_len, OTA_URI_BASE, sizeof(OTA_URI_BASE)-1), ota_url_len += sizeof(OTA_URI_BASE)-1;
            assert((ota_url_len + (2*len) + 16 + 8 + 8) < ota_url_size);
            memcpy(ota_url+ota_url_len, local_response_buffer, len), ota_url_len += len;
            memcpy(ota_url+ota_url_len, "/esp-gps-logger-", 16), ota_url_len += 16;
            memcpy(ota_url+ota_url_len, local_response_buffer, len), ota_url_len += len;     
#if defined(CONFIG_DISPLAY_DRIVER_SSD1681)
            memcpy(ota_url+ota_url_len, "-ssd1681", 8), ota_url_len += 8;
#endif
#if defined(CONFIG_DISPLAY_DRIVER_ST7789)
            memcpy(ota_url+ota_url_len, "-st7789", 7), ota_url_len += 7;
#endif
            memcpy(ota_url+ota_url_len, ".bin", 4), ota_url_len += 4;
            ota_url[ota_url_len] = 0;
            ILOG(TAG, "OTA URL: %s", ota_url);
        }
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    done:
    if(client) {
        esp_http_client_cleanup(client);
    }
    config.event_handler = 0;
    config.user_data = 0;
    return ret;
}

static esp_err_t _http_client_init_cb(esp_http_client_handle_t http_client) {
    esp_err_t err = ESP_OK;
    /* Uncomment to add custom headers to HTTP request */
    // err = esp_http_client_set_header(http_client, "Custom-Header", "Value");
    return err;
}

static esp_err_t ota_get_task(void *pvParameter) {
    ILOG(TAG, "[%s]", __FUNCTION__);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2)
                task_memory_info(__func__);
#endif
    uint32_t wait_until = m_context.fw_update_postponed;
    esp_err_t err = ESP_OK;
    if(wait_until && get_millis() < wait_until) {
        return err;
    }
    if(xSemaphoreTake(xMutex, 0) == pdTRUE){
        esp_https_ota_handle_t https_ota_handle = NULL;
        esp_err_t ota_finish_err = ESP_OK;
        char img_url[OTA_URL_SIZE] = {0};
        err = ota_get_image_path(img_url, OTA_URL_SIZE);
        if(err==1)
            goto ota_finish;
        else if(err) {
            goto ota_fail;
        }

        config.url = img_url;
        esp_https_ota_config_t ota_config = {
            .http_config = &config,
            .http_client_init_cb =
                _http_client_init_cb,  // Register a callback to be invoked after esp_http_client is initialized
    #ifdef CONFIG_OTA_ENABLE_PARTIAL_HTTP_DOWNLOAD
            .partial_http_download = true,
            .max_http_request_size = CONFIG_OTA_HTTP_REQUEST_SIZE,
    #endif
        };

        err = esp_https_ota_begin(&ota_config, &https_ota_handle);
        if (err != ESP_OK) {
            // ESP_LOGE(TAG, "[%s] Begin failed", __func__);
            goto ota_fail;
        }

        esp_app_desc_t app_desc;
        err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
        if (err != ESP_OK) {
            // ESP_LOGE(TAG, "[%s] esp_http_ota_read_img_desc failed", __func__);
            goto ota_fail;
        }
        err = validate_image_header(&app_desc);
        if (err != ESP_OK) {
            if(err == 1) {
                goto ota_finish;
            }
            goto ota_fail;
        }

        m_context.firmware_update_started = 2;
        delay_ms(100);
        ESP_ERROR_CHECK(esp_event_post(LOGGER_EVENT, LOGGER_EVENT_OTA_AUTO_UPDATE_START, NULL,0, portMAX_DELAY));

        wait_until = get_millis() + 60000;
        while(!m_context.fw_update_is_allowed) {
            delay_ms(200);
            if(get_millis() >= wait_until || m_context.fw_update_postponed) {
                ESP_LOGW(TAG, "Firmware update not allowed by user...");
                goto ota_finish;
            }
        }
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2)
                task_memory_info(__func__);
#endif

        while (1) {
            err = esp_https_ota_perform(https_ota_handle);
            if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
                break;
            }
            // esp_https_ota_perform returns after every read operation which gives
            // user the ability to monitor the status of OTA upgrade by calling
            // esp_https_ota_get_image_len_read, which gives length of image data
            // read so far.
    #if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 1)
            // ILOG(TAG, "[%s] Image bytes read: %d", __func__, esp_https_ota_get_image_len_read(https_ota_handle));
            // task_memory_info(__func__);
    #endif
        }

        if (esp_https_ota_is_complete_data_received(https_ota_handle) != true) {
            // the OTA image was not completely received and user can customise the
            // response to this situation.
            // ESP_LOGE(TAG, "[%s] Complete data was not received.", __func__);
        } else {
            ota_finish_err = esp_https_ota_finish(https_ota_handle);
            if ((err == ESP_OK) && (ota_finish_err == ESP_OK)) {
                https_ota_handle = NULL;
                ILOG(TAG, "[%s] upgrade successful. Rebooting ...", __func__);
                m_context.request_restart = 1;
                goto ota_finish;
            } else {
                if (ota_finish_err == ESP_ERR_OTA_VALIDATE_FAILED) {
                    ESP_LOGE(TAG, "[%s] Image validation failed, image is corrupted", __func__);
                }
                ESP_LOGE(TAG, "[%s] upgrade failed 0x%x", __func__, ota_finish_err);
            }
        }
    ota_fail:
        ESP_LOGE(TAG, "[%s] upgrade failed", __func__);
    ota_finish:
        m_context.firmware_update_started = 0;
        if(https_ota_handle)
            esp_https_ota_abort(https_ota_handle);
        xSemaphoreGive(xMutex);
        if(err||ota_finish_err) {
            ESP_ERROR_CHECK(esp_event_post(LOGGER_EVENT, LOGGER_EVENT_OTA_AUTO_UPDATE_FAILED, NULL,0, portMAX_DELAY));
        }
        else {
            ESP_ERROR_CHECK(esp_event_post(LOGGER_EVENT, LOGGER_EVENT_OTA_AUTO_UPDATE_FINISH, NULL,0, portMAX_DELAY));
        }
    }
    return err;
}

RTC_DATA_ATTR uint64_t last_check = 0, next_check=0;
static uint8_t ota_task_started = 0;

void ota_task(void *pvParameter) {
    ILOG(TAG, "[%s]", __FUNCTION__);
    next_check = esp_timer_get_time() + 10000000U; // 10 sec
    esp_err_t ret = ESP_OK;
    ILOG(TAG, "[%s] Starting OTA task, interval: %llu", __func__, (CONFIG_OTA_CHECK_INTERVAL*1000llu/1000000llu));
    while (ota_task_started) {
        if (next_check < esp_timer_get_time()) {
            ota_get_task(pvParameter);
            last_check = esp_timer_get_time();
            next_check = last_check + ((CONFIG_OTA_CHECK_INTERVAL)*1000llu);
        }
        delay_ms(10000);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2)
        task_memory_info(__func__);
#endif
    }
    esp_event_handler_unregister(ESP_HTTPS_OTA_EVENT, ESP_EVENT_ANY_ID, &event_handler);
    vTaskDelete(NULL);
}

void https_ota_start() {
    ILOG(TAG, "[%s]", __FUNCTION__);
    // Initialize NVS.
    esp_err_t err = 0;
    esp_event_handler_register(ESP_HTTPS_OTA_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL);

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
                ILOG(TAG, "[%s] App is valid, rollback cancelled successfully", __func__);
            } else {
                ESP_LOGE(TAG, "Failed to cancel rollback");
            }
        }
    }
#endif
    if (xMutex == NULL)
        xMutex = xSemaphoreCreateMutex();
    ota_task_started = 1;
    xTaskCreate(&ota_task, "ota_task", CONFIG_OTA_AUTO_UPDATE_TASK_STACK_SIZE, NULL, 3, NULL);
}

void https_ota_stop() {
    ILOG(TAG, "[%s]", __FUNCTION__);
    if (xMutex != NULL){
        vSemaphoreDelete(xMutex);
        xMutex = NULL;
    }
    ota_task_started = 0;
}

#endif
