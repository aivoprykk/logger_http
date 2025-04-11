#include "logger_http_private.h"
#if defined(CONFIG_LOGGER_HTTP_ENABLED)
#include <errno.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <esp_http_server.h>
#include <esp_system.h>
#include "esp_chip_info.h"

#include "uri_common.h"
#include "http_async_handler.h"
#include "http_rest_server.h"
#include "logger_config.h"
#include "context.h"
#if defined(CONFIG_USE_OTA)
#include "ota.h"
#endif
#include "numstr.h"
#include "strbf.h"
#if defined(CONFIG_LOGGER_VFS_ENABLED)
#include "vfs.h"
#endif
#if defined(CONFIG_LOGGER_ADC_ENABLED)
#include "adc.h"
#endif
#if defined(CONFIG_UBLOX_ENABLED)
// #include "ubx.h"
#endif
#if defined(CONFIG_LOGGER_WIFI_ENABLED)
#include "logger_wifi.h"
#endif
#if defined(CONFIG_GPS_LOG_ENABLED)
#include "gps_user_cfg.h"
#endif
#if defined(CONFIG_LOGGER_VFS_ENABLED)
#include "vfs.h"
#endif
#if defined(CONFIG_UBLOX_ENABLED)
#include "ubx.h"
#endif

#define ASYNC_WORKER_TASK_PRIORITY 5
#define ASYNC_WORKER_TASK_STACK_SIZE 1024 * 3

//#define CONFIG_MAX_ASYNC_REQUESTS 1

static const char *TAG = "asynchandler";

extern struct context_s m_context;
extern struct context_rtc_s m_context_rtc;
extern char base_path[ESP_VFS_PATH_MAX + 1];

// Async reqeusts are queued here while they wait to
// be processed by the workers
static QueueHandle_t async_req_queue;

// Track the number of free workers at any given time
static SemaphoreHandle_t worker_ready_count = 0;

// Each worker has its own thread
static uint8_t worker_num = CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS;
static TaskHandle_t worker_handles[CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS];
#define OLDDD 1

#if defined(X1)
static uint8_t is_on_async_worker_thread(void) {
    // is our handle one of the known async handles?
    TaskHandle_t handle = xTaskGetCurrentTaskHandle();
    uint8_t ret = false;
    for (int i = 0; i < worker_num; i++) {
        if (worker_handles[i] == handle) {
            ILOG(TAG, "[%s] found on async worker thread num %d", __func__, i);
            ret = true;
            goto done;
        }
    }
    ILOG(TAG, "[%s] Not on async worker thread", __func__);
    done:
    return false;
}

// Submit an HTTP req to the async worker queue
static esp_err_t submit_async_req(httpd_req_t *req, httpd_req_handler_t handler) {
    ILOG(TAG, "[%s]", __func__);
    // must create a copy of the request that we own
    httpd_req_t *copy = NULL;
    esp_err_t err = httpd_req_async_handler_begin(req, &copy);
    if (err != ESP_OK) {
        goto done;
    }
    httpd_async_req_t async_req = {
        .req = copy,
        .handler = handler,
    };

    // How should we handle resource exhaustion?
    // In this example, we immediately respond with an
    // http error if no workers are available.
    int ticks = 0;

    // counting semaphore: if success, we know 1 or
    // more asyncReqTaskWorkers are available.
    if (xSemaphoreTake(worker_ready_count, ticks) == false) {
        ESP_LOGE(TAG, "No workers are available");
        httpd_req_async_handler_complete(copy);  // cleanup
        err = ESP_FAIL;
        goto done;
    }

    // Since worker_ready_count > 0 the queue should already have space.
    // But lets wait up to 100ms just to be safe.
    if (xQueueSend(async_req_queue, &async_req, pdMS_TO_TICKS(100)) == false) {
        ESP_LOGE(TAG, "worker queue is full");
        httpd_req_async_handler_complete(copy);  // cleanup
        ret = ESP_FAIL;
    }
    done:
    return ESP_OK;
}
#endif

const char *http_file_extensions[] = {FILE_EXTENSIONS(STRINGIFY)};
const char *http_file_types[] = {FILE_TYPE_HANDLERS(STRINGIFY)};                     

static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filepath, size_t pathlen, char ** data) {
    assert(filepath);
#if (C_LOG_LEVEL < 2)
    ILOG(TAG, "[%s] uri:%s type:%s", __func__, req->uri, filepath);
#endif
    int ret = ESP_OK;
    if(!pathlen) pathlen = strlen(filepath);
    const char * ext = filepath + pathlen - 1;
    while (ext > filepath && *ext != '.') ext--;
    if (*ext != '.') {ret = ESP_FAIL; goto done;}
    ++ext;
    for(uint8_t i = 0, j=sizeof(http_file_extensions)/sizeof(http_file_extensions[0]), k=0; i<j; ++i) {
        if (!strcasecmp(ext, http_file_extensions[i])) {
            k = strlen(http_file_types[i]);
            memcpy(*data, http_file_types[i], k);
            switch(i) {
                case file_type_html:
                case file_type_js:
                case file_type_css:
                case file_type_json:
                    memcpy((*data)+k, ";charset=utf-8", 14);
                    (*data)[k+14] = 0;
                    break;
                default:
                    (*data)[k] = 0;
                    break;
            }
            break;
        }
    }
#if (C_LOG_LEVEL < 2)
    ILOG(TAG, "[%s] done file: %s, type: %s", __FUNCTION__, filepath, *data);
#endif
    if(**data)
        ret = httpd_resp_set_type(req, *data);
    done:
    return  ret;
}

static const char *http_async_handler_status_strings[] = {
    "OK",
    "Error",
    "Success",
    "Failed to send header",
};

static const char *http_async_handler_strings[] = {
    "{\"status\":\"",
    "\",\"msg\":\"",
    ",\"data\":",
    "}\r\n",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    ",\"total_space\":",
    ",\"free_space\":",
    "</td></tr><tr><td>",
    "</td><td>"
};

static esp_err_t http_send_json_msg(httpd_req_t *req, const char *msg, int msg_size, int status, char * data, int data_size) {
    DLOG(TAG, "[%s] %s\n", __func__, msg);
    httpd_resp_send_chunk(req, "{\"status\":\"", 11); // status
    if(status==0)
        httpd_resp_send_chunk(req, http_async_handler_status_strings[0], 2);
    else {
        httpd_resp_send_chunk(req, http_async_handler_status_strings[1], 5);
    }
    httpd_resp_send_chunk(req, "\",\"msg\":\"", 9); // msg
    httpd_resp_send_chunk(req, msg, msg_size==0 ? -1 : msg_size);
    httpd_resp_send_chunk(req, "\"", 1);
    if(data) {
        httpd_resp_send_chunk(req, ",\"data\":", 8); //data
        httpd_resp_send_chunk(req, data, data_size == 0 ? -1 : data_size);
    }
    httpd_resp_send_chunk(req, http_async_handler_strings[3], 3); // end
    return status;
}

static esp_err_t archive_file(httpd_req_t *req, const char *filename, const char *base) {
    ILOG(TAG, "[%s]", __func__);
    int ret = ESP_OK;
    strbf_t sb;
#ifdef CONFIG_LOGGER_VFS_ENABLED
    char tmp[PATH_MAX_CHAR_SIZE];
    strbf_inits(&sb, tmp, PATH_MAX_CHAR_SIZE);
    if(base) strbf_put_path(&sb, base);
    strbf_put_path(&sb, "Archive");
    if (!s_xfile_exists(strbf_finish(&sb))) {
        ret = mkdir(sb.start, 0755);
        if (ret < 0) {
            ESP_LOGE(TAG, "Failed to mkdir %s (%s)", sb.start, esp_err_to_name(ret));
            goto done;
        }
    }
    const char *p = filename;
    if (strstr(filename, base) == filename)
        p += strlen(base);
    strbf_put_path(&sb, p);
#if (C_LOG_LEVEL < 2)
    DLOG(TAG, "Move to arcive %s => %s\n", filename, sb.start);
#endif
    ret = s_rename_file_n(filename, sb.start, 0);
#endif
    done:
    return ret;
}

static esp_err_t send_file(httpd_req_t *req, int fd, uint32_t len) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    int ret = 0;
    int32_t read_bytes, i = len;
    if (fd <= 0 || !req) {
        ret = ESP_FAIL;
        goto done;
    }
    char tmp[8] = {0};
    if (len) {
        xultoa(len, &(tmp[0]));
        esp_err_t err = httpd_resp_set_hdr(req, "Content-Length", tmp);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
        }
#if (C_LOG_LEVEL < 2)
        else {
            ILOG(TAG, "[%s] content length set as %s bytes", __FUNCTION__, tmp);    
        }
#endif
    }
    size_t chunk_size = SCRATCH_BUFSIZE;
    char chunk[SCRATCH_BUFSIZE] = {0};
    do {
        read_bytes = read(fd, chunk, chunk_size-1);
#if (C_LOG_LEVEL < 1)
        DLOG(TAG, "%ld ", read_bytes);
#endif
        if (read_bytes == -1) {
            ESP_LOGE(TAG, "Failed to read file.");
            ret = ESP_FAIL;
            goto done;
        } else if (read_bytes > 0) {
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK) {
                // close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                ret = ESP_FAIL;
                goto done;
            }
        }
        i -= read_bytes;
    } while (read_bytes > 0);
#if (C_LOG_LEVEL < 1)
    DLOG(TAG, "%s", "\n");
#endif
    done:
    IMEAS_END(TAG, "[%s] sent %lu bytes took: %llu us", __func__, len - i);
    return ret;
}

static esp_err_t config_handler(httpd_req_t *req, const char *name, strbf_t * sb, size_t flush_size) {
    ILOG(TAG, "[%s] %s %s", __func__, req->uri, name && *name ? name : "-");
    IMEAS_START();
    const logger_config_t *config = m_context.config;
    int ret = ESP_OK;
    // const char *start_ptr = config_item_names;
    // const char *end_ptr = 0;
    if (name && *name) {
        gps_config_get(name, sb, 1);
        if(sb->cur == sb->start) config_get(config, name, sb, 1);
        if(sb->cur == sb->start){
            ret = ESP_FAIL;
            goto done;
        }
    } else {
        strbf_puts(sb, "[");
        if(sb->cur == sb->start){
            ret = ESP_FAIL;
            goto done;
        }
        
        for(uint8_t i = 0; i < gps_user_cfg_item_count; i++) {
            if(gps_cnf_get_item(i+CFG_GPS_ITEM_BASE, sb, 1) >= 253) {
                continue;
            }
            strbf_putc(sb, ',');
            // strbf_putc(sb, '\n');
            if(sb->cur - sb->start >= flush_size) {
                httpd_resp_send_chunk(req, sb->start, sb->cur - sb->start);
                strbf_shape(sb, 0);
            }
        }
        for(uint8_t i = 0; i < config_item_count; i++) {
            if(cnf_get_item(config, i, sb, 1) >= 253) {
                continue;
            }
            if(i < config_item_count-1) {
                strbf_putc(sb, ',');
            }
            if(sb->cur - sb->start >= flush_size) {
                httpd_resp_send_chunk(req, sb->start, sb->cur - sb->start);
                strbf_shape(sb, 0);
            }
        }
        strbf_puts(sb, "]\n");
    }
    if(sb->cur > sb->start) {
        httpd_resp_send_chunk(req, sb->start, sb->cur - sb->start);
    }    
done:
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    if(ret) {
        httpd_resp_set_status(req, HTTPD_500);
        http_send_json_msg(req, "fail", 4, 1, 0, 0);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t system_bat_get_handler(httpd_req_t * req) {
    ILOG(TAG, "[%s]", __func__);
    char buf[16] = {0};
    size_t len = 0;
    httpd_resp_send_chunk(req, "{\"battery\":\"", 12);
#ifdef USE_CUSTOM_CALIBRATION_VAL
    len = f3_to_char(volt_read(m_context_rtc.RTC_calibration_bat), buf);
#else
#if defined(CONFIG_LOGGER_ADC_ENABLED)
    len = f3_to_char(volt_read(), buf);
#endif
#endif
    if(len) {
        httpd_resp_send_chunk(req, buf, len);
    }
    else {
        httpd_resp_send_chunk(req, "0", 1);
    }
    httpd_resp_send_chunk(req, http_async_handler_strings[3], 3); // }\n
    return ESP_OK;
}

static int uint8_array_to_ipv4_string(uint8_t *ipv4, char *buf) {
    return sprintf(buf, "%hhu.%hhu.%hhu.%hhu", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
}

static void flush_d(httpd_req_t *req, const char * str, strbf_t * data, size_t flush_size) {
    size_t len = strlen(str);
    if(len + data->cur - data->start > flush_size) {
        httpd_resp_send_chunk(req, data->start, data->cur - data->start);
        strbf_shape(data, 0);
    }
    strbf_put(data, str, len);
}

/* Simple handler for getting system handler */
static esp_err_t system_info_get_handler(httpd_req_t *req, uint8_t mode, strbf_t *data, size_t flush_size) {
    ILOG(TAG, "[%s]", __func__);
    char lbuf[16] = {0};
    size_t llen = 0;
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    if(mode == 2) {
        flush_d(req, "<table class=\"table-2\"><tr><td>", data, flush_size);
    } else {
        flush_d(req, "{", data, flush_size);
    }
    if(mode == 2) { 
        flush_d(req, "Hostname", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, "\"hostname\":\"", data, flush_size);
    flush_d(req, wifi_context.hostname, data, flush_size);
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Cores", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, "\",\"cores\":", data, flush_size);
    strbf_putl(data,chip_info.cores);
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Model", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"model\":\"", data, flush_size);
    flush_d(req, "esp32", data, flush_size);
    if(chip_info.model != 1) flush_d(req, "s3", data, flush_size);
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Revision", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, "\",\"revision\":", data, flush_size);
    strbf_putl(data, chip_info.revision);
#if defined(CONFIG_UBLOX_ENABLED)
    if(mode == 2) {
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "GPS", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"gps\":\"", data, flush_size);
    flush_d(req, ubx_chip_str(m_context.gps.ubx_device), data, flush_size);
    if(mode != 2) {
        flush_d(req, "\"", data, flush_size);
    }
#endif
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Total Heap", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"totalheap\":", data, flush_size);
    strbf_putl(data, heap_caps_get_total_size(MALLOC_CAP_8BIT));
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Freeheap", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"freeheap\":", data, flush_size);
    strbf_putl(data, esp_get_free_heap_size());
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Minfreeheap", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"minfreeheap\":", data, flush_size);
    strbf_putl(data, esp_get_minimum_free_heap_size());
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Battery", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"battery\":", data, flush_size);
#if defined(CONFIG_LOGGER_ADC_ENABLED)
    llen = f3_to_char(volt_read(), lbuf);
#endif
    if(llen) {
        flush_d(req, lbuf, data, flush_size);
    } else {
        strbf_putc(data, '0');
    }
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "IDF version", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, ",\"version\":\"", data, flush_size);
    flush_d(req, IDF_VER, data, flush_size);
    if(mode == 2) { 
        flush_d(req, http_async_handler_strings[8], data, flush_size);
        flush_d(req, "Fwversion", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    } else flush_d(req, "\",\"fwversion\":\"", data, flush_size);
    flush_d(req, m_context.SW_version, data, flush_size);
    if(mode != 2) {
        flush_d(req, "\"", data, flush_size);
    }
#if defined(CONFIG_LOGGER_WIFI_ENABLED)
    if(wifi_context.s_ap_connection) {
        if(mode == 2) { 
            flush_d(req, http_async_handler_strings[8], data, flush_size);
            flush_d(req, "Ap_ssid", data, flush_size);
            flush_d(req, http_async_handler_strings[9], data, flush_size);
        } else flush_d(req, ",\"ap_ssid\":\"", data, flush_size);
        flush_d(req, wifi_context.ap.ssid, data, flush_size);
        if(mode == 2) { 
            flush_d(req, http_async_handler_strings[8], data, flush_size);
            flush_d(req, "Ap_address", data, flush_size);
            flush_d(req, http_async_handler_strings[9], data, flush_size);
        } else flush_d(req, "\",\"ap_address\":\"", data, flush_size);
        llen = uint8_array_to_ipv4_string(wifi_context.ap.ipv4_address, &lbuf[0]);
        flush_d(req, lbuf, data, flush_size);
        if(mode != 2) {
            flush_d(req, "\"", data, flush_size);
        } 
    }
    if(wifi_context.s_sta_connection) {
        if(mode == 2) { 
            flush_d(req, http_async_handler_strings[8], data, flush_size);
            flush_d(req, "Sta_ssid", data, flush_size);
            flush_d(req, http_async_handler_strings[9], data, flush_size);
        } else flush_d(req, ",\"sta_ssid\":\"", data, flush_size);
        if(wifi_context.s_sta_got_ip)
         flush_d(req, wifi_context.stas[wifi_context.s_sta_num_connect].ssid, data, flush_size);
        if(mode == 2) { 
            flush_d(req, http_async_handler_strings[8], data, flush_size);
            flush_d(req, "Sta_address", data, flush_size);
            flush_d(req, http_async_handler_strings[9], data, flush_size);
        } else flush_d(req, "\",\"sta_address\":\"", data, flush_size);
        if(wifi_context.s_sta_got_ip)
            llen = uint8_array_to_ipv4_string(wifi_context.stas[wifi_context.s_sta_num_connect].ipv4_address, &lbuf[0]);
        flush_d(req, lbuf, data, flush_size);
        if(mode != 2) {
            flush_d(req, "\"", data, flush_size);
        } 
    }
#endif
    if(mode == 2) { 
        flush_d(req, "</td></tr></table>", data, flush_size);
    } else 
        flush_d(req, http_async_handler_strings[3], data, flush_size); // }\n
    
    if(data->cur - data->start > 0) {
        httpd_resp_send_chunk(req, data->start, data->cur - data->start);
        strbf_shape(data, 0);
    }
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    return ESP_OK;
}

static esp_err_t paths_handler(httpd_req_t *req, uint8_t mode, strbf_t * data, size_t flush_size) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    DIR *dirp = NULL;
    const struct dirent *ent;
    char type;
    char size[16] = {0};
    char tpath[VFS_FILE_PATH_MAX];
    char tbuffer[92] ={0};
    uint8_t i = 0;
    if(mode==1)
        httpd_resp_send_chunk(req, "{\"paths\": [", 11);
    while(i < VFS_MAX_PARTS) {
        if(vfs_ctx.parts[i].is_mounted) {
            if(i > 0) {
                if(mode==1)
                    strbf_putc(data, ',');
                else
                    strbf_putc(data, '\n');
            }
            if(mode==1)
                flush_d(req, "{\"path\":\"", data, flush_size);
            else
                flush_d(req, "Path: ", data, flush_size);
            flush_d(req, vfs_ctx.parts[i].mount_point, data, flush_size);
            strbf_putc(data, '"');
            if(mode==1)
                flush_d(req, http_async_handler_strings[6], data, flush_size);
            else
                flush_d(req, ", Total bytes: ", data, flush_size);
            strbf_putul(data, vfs_ctx.parts[i].total_bytes);
            if(mode==1)
                flush_d(req, http_async_handler_strings[7], data, flush_size);
            else
                flush_d(req, ", Free bytes: ", data, flush_size);
            strbf_putul(data, vfs_ctx.parts[i].free_bytes);
            if(mode==1)
                strbf_putc(data, '}');
        }
        i++;
    }
    if(mode==1)
        flush_d(req, "]}\r\n", data, flush_size);
    if(data->cur - data->start > 0) {
        httpd_resp_send_chunk(req, data->start, data->cur - data->start);
        strbf_shape(data, 0);
    }
    IMEAS_END(TAG, "[%s] %s done, took: %llu us", __func__, req->uri);
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    return ESP_OK;
}

off_t file_handler(httpd_req_t *req, strbf_t *path, size_t len, const char * name, strbf_t *data, size_t flush_size, uint32_t idx, uint8_t mode) {
    struct tm *tm_info;
    struct stat sb;
    int statok;
    off_t ret = ESP_OK;
    char type;
    char tbuffer[92] ={0};
    strbf_shape(path, len);
    strbf_put_path(path, name);
    *path->cur = 0;
    statok = stat(path->start, &sb);
    if(statok) {
        goto done;
    }
    tbuffer[0] = '\0';
    if(mode == 2) flush_d(req, "<tr>", data, flush_size);
    else if(mode==1) {
        if(!idx) strbf_putc(data, '{');
        else flush_d(req, ",{", data, flush_size);
    }
    if (!statok) {
        tm_info = localtime(&sb.st_mtime);
        strftime(tbuffer, 92, "%Y-%m-%d %R", tm_info);
    }
    if ((sb.st_mode & S_IFMT) == S_IFDIR) type = 'd';
    else if (strstr(name, "config")) type = 'c';
    else type = 'f';
    if(mode==2) {
        if(type == 'f') flush_d(req, "<td><input type=\"checkbox\"></td>", data, flush_size);
        else flush_d(req, "<td></td>", data, flush_size);
        flush_d(req, "<td><a href=\"", data, flush_size);
        flush_d(req, path->start, data, flush_size);
        flush_d(req, "\">", data, flush_size);
    }
    else if(mode==1)  flush_d(req, "\"name\":\"", data, flush_size);
    else strbf_putc(data, ' ');
    flush_d(req, name, data, flush_size);
    if(mode==2) {
        flush_d(req, "</a>", data, flush_size);
        flush_d(req, http_async_handler_strings[9], data, flush_size);
    }
    else if(mode==1) flush_d(req, "\",\"date\":\"", data, flush_size);
    else strbf_putc(data, ' ');
    if (!statok) flush_d(req, tbuffer, data, flush_size);
    if(mode==2)  flush_d(req, http_async_handler_strings[9], data, flush_size);
    else if(mode==1) flush_d(req, "\",\"size\":\"", data, flush_size);
    else strbf_putc(data, ' ');
    if (!statok && (sb.st_mode & S_IFMT) == S_IFREG){
        if(mode == 2) {
            uint8_t pow = 0;
            uint64_t size = sb.st_size;
            while(size > 1024) {
                size /= 1024;
                pow++;
            }
            strbf_putul(data, size);
            strbf_putc(data, "BKMGT"[pow]);
        }
        else strbf_putul(data, sb.st_size);
        ret += sb.st_size;
    }
    if(mode==2) flush_d(req, "</td><td class=\"hide-xs\">", data, flush_size);
    else if(mode==1) flush_d(req, "\",\"type\":\"", data, flush_size);
    else strbf_putc(data, ' ');
    strbf_putc(data, type == 'c' ? 'f' : type);
    if(mode==2) flush_d(req, "</td><td class=\"hide-xs\">", data, flush_size);
    else if(mode==1) flush_d(req, "\",\"mode\":\"", data, flush_size);
    else strbf_putc(data, ' ');
    if (type == 'c')  strbf_putc(data, 'r');
    else flush_d(req, "rw", data, flush_size);
    if(mode==2) {
        flush_d(req, "</td>", data, flush_size);
        if(type == 'f') {
            flush_d(req, "<td><div role=\"group\" data-file=\"", data, flush_size);
            flush_d(req, name, data, flush_size);
            flush_d(req, "\"><button class=\"outline rm\">Delete</button><button class=\"outline ar\">Archive</button></div></td>", data, flush_size);
        }
        else {
            flush_d(req, "<td></td>", data, flush_size);
        }
        flush_d(req, "</tr>", data, flush_size);
    }
    if(mode==1) flush_d(req, "\"}", data, flush_size);
    else strbf_putc(data, '\n');
    *data->cur=0;
    done:
    return ret;
}

static esp_err_t directory_handler(httpd_req_t *req, const char *path, const char *match, uint8_t mode, strbf_t * data, size_t flush_size) {
    ILOG(TAG, "[%s] uri: %s, path: %s", __func__, req->uri, path ? path : "null");
    IMEAS_START();
    DIR *dirp = NULL;
    const struct dirent *ent;
    char tpath[VFS_FILE_PATH_MAX];
    int ret = ESP_OK;
    uint64_t total = 0;
    uint32_t nitems = 0;
    strbf_t pathbuf;
    strbf_inits(&pathbuf, tpath, VFS_FILE_PATH_MAX);
    strbf_puts(&pathbuf, path);
    size_t len = pathbuf.cur - pathbuf.start, i = 0;
    // Open directory
    dirp = opendir(path);
    if (!dirp) {
        httpd_resp_set_status(req, HTTPD_500);
        if(mode==2)      httpd_resp_send_chunk(req, "<div>Error opening directory</div>", 35);
        else if(mode==1) http_send_json_msg(req, "Error opening directory", 23, 1, 0, 0);
        else             httpd_resp_send_chunk(req, "Error opening directory.\n", 24);
        goto done;
    }
    httpd_resp_set_status(req, HTTPD_200);
    if(mode==2) {
       flush_d(req, "<table><thead><tr><th><input type=\"checkbox\"></th><th>Name</th><th>Date</th><th>Size</th><th>Size</th><th>Type</th><th>Mode</th><th>Actions</th></tr></thead><tbody>", data, flush_size);
    }
    else if(mode==1) {
        flush_d(req, "{\"path\":\"", data, flush_size);
        flush_d(req, path, data, flush_size);
        strbf_putc(data, '"');
        flush_d(req, ",\"data\":[", data, flush_size);
    }
    else {
        flush_d(req, "T  Name  Date/Time  Size Type Mode\n-----------------------------------\n", data, flush_size);
    }
    while ((ent = readdir(dirp)) != NULL) {
        if (match && !strstr(ent->d_name, match)) {
            continue;
        }
        total += file_handler(req, &pathbuf, len, ent->d_name, data, flush_size, nitems, mode);
        ++nitems;
    }
    closedir(dirp);
    if(mode == 2) flush_d(req, "</tbody></table>", data, flush_size);
    else if(mode == 1) {
        strbf_putc(data, ']');
        flush_d(req, ",\"total\":", data, flush_size);
        strbf_putul(data, total);
        flush_d(req, "}\r\n", data, flush_size);
    }
    else flush_d(req, "-----------------------------------\n", data, flush_size);
    if(data->cur > data->start) {
        httpd_resp_send_chunk(req, data->start, data->cur - data->start);
        strbf_shape(data, 0);
    }
    i += data->cur - data->start;
#if (C_LOG_LEVEL < 2)
    DLOG(TAG, "[%s] Total %lu items, %llu bytes, %u bytes sent.\n", __FUNCTION__, nitems, total, i);
#endif
    done:
    IMEAS_END(TAG, "[%s] %s done, took: %llu us", __func__, req->uri);
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    // strbf_free(&databuf);
    return ret;
}

static const char * html_handler_str[] = {
    "<img src=\"/logo.svg\" alt=\"Logger\" />",
};

static esp_err_t http_resp_file_html_handler(httpd_req_t *req, const char *name, strbf_t * data, size_t flush_size) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    flush_d(req, "<!DOCTYPE html><html lang=\"en\"><head><title>ESP-LOGGER ::", data, flush_size);
    flush_d(req, name, data, flush_size);
    flush_d(req, "</title><meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"index.css\"><script src=\"index.js\"></script>"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><header><nav><ul>"
    "<li class=\"brand\"><span class=\"lg\">ESP-LOGGER</span></ul><ul><li class=\"home\">"
    "<a href=\"/\">Home</a></li><li class=\"files\"><a href=\"/files.html\">"
    "Files</a></li><li class=\"config\"><a href=\"/config.html\">Config</a></li>"
    "<li class=\"fwupdate\"><a href=\"/fwupdate.html\">FW Update</a></li></ul></nav></header>"
    "<main><div class=\"container\"><article class=\"card ", data, flush_size);
    flush_d(req, name, data, flush_size);
    flush_d(req, "\"><header class=\"card-header\"><div class=\"flexrow\">", data, flush_size);
    if(!strcmp(name, "home")){ 
        flush_d(req, html_handler_str[0], data, flush_size);
    }
    else if(!strcmp(name,  "files")) {
        flush_d(req, "<h2>Files</h2><div class=\"left selection hide\" hidden><button class=\"outline dl\">Download selected</button>"
        "<button class=\"outline rm\">Delete selected</button><button class=\"outline ar\">Archive selected</button></div><div class=\"right upload-file\">"
        "<label class=\"upload-file-select\"><span class=\"file-text\">Upload file</span><input type=\"file\" /></label><button class=\"outline upload-submit hide\">Upload</button>"
        "</div></div><div class=\"flexrow info\">", data, flush_size);
    }
    else if(!strcmp(name, "config")) {
        flush_d(req, "<h2>Configuration</h2>", data, flush_size);
    }
    else if(!strcmp(name, "fwupdate")) {
        flush_d(req, "<h2>Firmware update</h2>", data, flush_size);
    }
    else if(!strcmp(name, "404")) {
        flush_d(req, "<h2>404 Not found</h2>", data, flush_size);
    }
    flush_d(req, "</div></header><div class=\"card-body", data, flush_size);
    if(!strcmp(name,"fwupdate")) {
        flush_d(req, " upload-file\"><label class=\"upload-file-select\"><span class=\"file-text\">Select firmware file</span><input type=\"file\" /></label>"
        "<button class=\"outline upload-submit\">Upload</button></div><footer class=\"card-bottom\"><span>Current firmware version: </span><span class=\"fwver-text\"></span></footer>", data, flush_size);
    } else {
        flush_d(req, "\">", data, flush_size);
        if(!strcmp(name, "home")){
            system_info_get_handler(req, 2, data, flush_size);
        } else {
            if(!strcmp(name, "404")) {
                flush_d(req, "<h2>404 Not found</h2>", data, flush_size);
            }
            // else if(!strcmp(name, "files")) {
            //     directory_handler(req, path, 2, 1, buf, blen);
            // }
            // else
            //     httpd_resp_sendstr_chunk(req, html_handler_str[0]); // logo
        }
        flush_d(req, "</div>", data, flush_size);
    }
    flush_d(req, "</article></div></main></html>\r\n", data, flush_size);
    if(data->cur > data->start) {
        httpd_resp_send_chunk(req, data->start, data->cur - data->start);
    }
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return ESP_OK;
}

extern const unsigned char index_css_start[] asm("_binary_index_css_gz_start");
extern const unsigned char index_css_end[]   asm("_binary_index_css_gz_end");
extern const unsigned char index_js_start[] asm("_binary_index_js_gz_start");
extern const unsigned char index_js_end[]   asm("_binary_index_js_gz_end");
extern const unsigned char logo_svg_start[] asm("_binary_logo_svg_gz_start");
extern const unsigned char logo_svg_end[]   asm("_binary_logo_svg_gz_end");

static esp_err_t embed_get_handler(httpd_req_t *req, const uint8_t *start, const uint8_t *end) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    int ret = ESP_OK;
    size_t embed_size = (end - start);
    size_t chunk_size = SCRATCH_BUFSIZE;
    if(!embed_size) {
        WLOG(TAG, "[%s] embed not found", __func__);
        goto done;
    }
    while(embed_size > 0) {
        chunk_size = embed_size > chunk_size ? chunk_size : embed_size;
        httpd_resp_send_chunk(req, (const char *)start, chunk_size);
        start += chunk_size;
        embed_size -= chunk_size;
    }
    done:
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return ret;
}

static esp_err_t js_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return embed_get_handler(req, index_js_start, index_js_end);
}

static esp_err_t logo_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return embed_get_handler(req, logo_svg_start, logo_svg_end);
}

static esp_err_t css_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return embed_get_handler(req, index_css_start, index_css_end);
}

#if defined(CONFIG_LOGGER_HTTP_FILES_EXTERNAL)
static esp_err_t index_get_handler(httpd_req_t * req, char *path) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    struct stat sb = {0};
    int statok = stat(path, &sb);
    int fd = open(path, O_RDONLY, 0);
    char *data = 0;
    int ret = ESP_OK;
    if (fd) {
        char hostname[24] = {0};
        char tmp[8] = {0}, *be = hostname;
        size_t bl = 0, hl = 0;
        memcpy(be, "http://", 7), be+=7;
        hl= strlen(wifi_context.hostname);
        memcpy(be, wifi_context.hostname, hl), be+=hl;
        memcpy(be, ".local", 6), be+=6;
        *be++ = '/', *be = 0;
        hl = be - &(hostname[0]);

        data = malloc(sb.st_size + hl);
        int read_bytes = read(fd, data, sb.st_size);
        *(data + sb.st_size) = 0;
        DLOG(TAG, "send index 0 : %s, %d, %s, %d\n", data, read_bytes, hostname, hl);
        if (close(fd)) {
            ESP_LOGE(TAG, "Failed to close (%s)", strerror(errno));
        }
        if (read_bytes > 0) {
            int diff = 0;
            char *bs = strstr(data, "<base href=\"");
            if (bs) {
                bl = 0;
                bs += 12;
                be = strchr(bs, '"');
                bl = be - bs;
                diff = bl - hl;
                ESP_LOGE(TAG, "send index diff: %d", diff);
                if (diff > 0) {  // smaller buffer needed
                    for (int i = bs - data + 12, j = read_bytes; i < j; ++i) {
                        data[i] = data[i + diff];
                    }
                }
                if (diff < 0) {  // need bigger buffer...
                    for (int i = be - data + diff, j = read_bytes - 1; i <= j; --j) {
                        data[j - diff] = data[j];
                    }
                }
                memcpy(bs, hostname, hl);
            }
            bl = read_bytes - diff;
            *(data + bl) = 0;
            xultoa(bl, &(tmp[0]));
            httpd_resp_set_type(req, HTTPD_TYPE_TEXT);
            httpd_resp_set_hdr(req, "Content-Length", tmp);
            DLOG(TAG, "send index 1 : %s, %d\n", data, bl);
            httpd_resp_send_chunk(req, data, bl);
        } else {
            ESP_LOGE(TAG, "send index failed.");
            ret = ESP_FAIL;
        }
    }
    else {
        ret = ESP_FAIL;
    }
    if (data)
        free(data);
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return ret;
}
#endif

static esp_err_t try_local_file(httpd_req_t *req, size_t ulen, const char *name, strbf_t * data, size_t blen) {
    ILOG(TAG, "[%s] uri:%s name:%s", __func__, req->uri, name ? name : "-");
    IMEAS_START();
    char tmp[16] = {0};
    const char *p, *s;
    size_t tlen = 0;
    int ret = ESP_OK;
    if(name && *name) {
        p = name;
        s = name;
        ulen = strlen(name);
    }
    else {
        p = req->uri;
        s = req->uri;
    }
    // set_content_type_from_file(req, ulen ? p : ".html", ulen ? ulen : 5);
    if(!ulen) goto index;
    if(*p == '/') ++p;
    while(p && *p &&*p != '/' && *p != '.') ++p;
    if(p && *p == '.' && p-s < 16) {
        tlen = p-s-1;
        memcpy(tmp, s+1, tlen);
        tmp[tlen] = 0;
    }
    // WLOG(TAG, "[%s] found file name %s ext %s or not.", __func__, &tmp[0], p ? p : "-");
    if((*req->uri == '/' && ulen == 1) || (tmp[0] && !strcmp(p, ".html"))) {
        index:
        if((!tmp[0] || !strcmp(tmp, "index")) && !http_resp_file_html_handler(req, "home", data, blen)) {
            goto finishing;
        }
        else if((!strcmp(tmp, "404") || !strcmp(tmp, "files") || !strcmp(tmp, "config") || !strcmp(tmp, "fwupdate")) && !http_resp_file_html_handler(req, &tmp[0], data, blen)) {
            goto finishing;
        }
    }
    else if(tmp[0] && !strcmp(tmp, "index")){
        if((!strcmp(p, ".css") && !css_get_handler(req)) || (!strcmp(p, ".js") && !js_get_handler(req))) {
            goto finishing;
        }
    }
    else if(tmp[0] && !strcmp(req->uri+1, "logo.svg")) {
        if(!logo_get_handler(req))
            goto finishing;
    }
    ret = ESP_FAIL;
    finishing:
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return ret;
}

esp_err_t add_cors(httpd_req_t *req, uint8_t api) {
    esp_err_t err = ESP_OK;
    err = httpd_resp_set_hdr(req, http_async_handler_strings[4], "*");
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
    }
    if(api) {
        uint8_t tlen = 8;
        if (strstr(req->uri+tlen, "files") == req->uri+tlen) {
            err = httpd_resp_set_hdr(req, http_async_handler_strings[5], "GET, DELETE, POST");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
            }
        } else if (strstr(req->uri+tlen, "config") == req->uri+tlen) {
            err = httpd_resp_set_hdr(req, http_async_handler_strings[5], "GET, POST, OPTIONS, PATCH");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
            }
        }
    }
    err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
    }
    return err;
}

esp_err_t head_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send_chunk(req, 0, 0);
    return ESP_OK;
}

int8_t try_file_path(httpd_req_t *req, strbf_t *pathbuf, const char * p) {
    char strbuf[SCRATCH_BUFSIZE] = {0};
    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context);
    size_t ulen = strlen(req->uri), tlen = p-req->uri;
    struct stat sb = {0};
    int statok = 0, i, j;
    uint8_t base_path_needed = 0;
    int8_t ret = 0;
    const char *r = req->uri + ulen;
    try_again:
    memset(pathbuf->start, 0, pathbuf->cur - pathbuf->start);
    pathbuf->cur = pathbuf->start;
    if(base_path_needed) {
        if(base_path_needed > 1) {
            for(i = 0, j = VFS_PART_MAX; j >= 0; --j) {
                if(vfs_ctx.parts[j].is_mounted && vfs_ctx.gps_log_part != j) {
                    strbf_puts(pathbuf, vfs_ctx.parts[j].mount_point);
                    break;
                }
            }
            if(j==0) goto err;
        } else {
            strbf_puts(pathbuf, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
        }
    }
    if (!ret && ulen > tlen && *p == '/') {
        if (!strcmp(p + 1, "delete")) {ret = 1; p = p + 7;}
        else if (!strcmp(p + 1, "archive")) {ret = 2; p = p + 8;}
    }
    if (r > p) {
        if((pathbuf->cur>pathbuf->start && *(pathbuf->cur-1)!='/') && *p != '/') strbf_putc(pathbuf, '/');
        s_uri_decode(pathbuf->cur, p, r - p); // only p string before delete or archive
    }
    while(pathbuf->cur && *pathbuf->cur) ++pathbuf->cur;
    *pathbuf->cur = 0;
#if (C_LOG_LEVEL < 2)
    ILOG(TAG, "[%s] filepath:%s p:%s r:%s len:%d", __FUNCTION__, pathbuf->start, p, r, r-p);
#endif
    statok = stat(pathbuf->start, &sb);
    if (!statok) {
        if (!ret) {
            if (S_ISDIR(sb.st_mode)) {
                ret = 3; // dir
            } 
            else ret = 4;  // file
        }
        else {
            ret = i==1 ? 8 : 9;
        }
    } else if (base_path_needed<2) {
        ++base_path_needed;
        goto try_again;
    }
    else {
        err:
        ret = -2;
    }
    return ret;
}

esp_err_t api_handler(httpd_req_t * req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    esp_err_t ret = ESP_OK;
    size_t ulen = strlen(req->uri), tlen = 8, flush_size = SCRATCH_BUFSIZE-128, msglen = 0;
    const char *uri = req->uri + tlen;
    const char *p = 0, *e = req->uri+ulen;
    char cbuf[64] = {0}, *c = &cbuf[0];
    const char * msg = "ok";
    strbf_t buf;
    strbf_init(&buf);
    set_content_type_from_file(req, ".json", 5, &c);
    add_cors(req, 1);
    if (strstr(uri, "config") == uri) {
        uri += 6;
        config_handler(req, uri, &buf, flush_size);
    } else if(strstr(uri, "paths") == uri) {
        paths_handler(req, 1, &buf, flush_size);
    } else if (strstr(uri, "login") == uri) {
        httpd_resp_send_chunk(req, "{\"user\":\"admin\",\"logged\":\"no\"}\r\n", 32);
    } else if (strstr(uri, "fw/version") == uri) {
        strbf_puts(&buf,"{\"version\":\"");
        strbf_puts(&buf, m_context.SW_version);
        strbf_puts(&buf, "\"}");
        http_send_json_msg(req, "ok", 2, 0, buf.start, buf.cur - buf.start);
    } else if (strstr(uri, "system") == uri) {
        uri += 7;
        if (strstr(uri, "info") == uri) {
            system_info_get_handler(req, 1, &buf, flush_size);
        } else if (strstr(uri, "bat") == uri) {
            system_bat_get_handler(req);
        } else if (strstr(uri, "restart") == uri) {
            http_send_json_msg(req, "restart pending.", 16, 0, 0, 0);
            m_context.request_restart = 1;
        }
        else {
            msg = "path not found";
            msglen = 14;
            goto err;
        }
    } else if (strstr(uri, "files") == uri) {
        uri += 5;    
        char filepath[VFS_FILE_PATH_MAX] = {0};
        strbf_t pathbuf;
        strbf_inits(&pathbuf, filepath, VFS_FILE_PATH_MAX);
        int err = try_file_path(req, &pathbuf, uri);
        switch(err) {
            case 1:
            case 2:
            case 9:
                p = err == 1 || err == 8 ? "unlink" : "archive";
                strbf_puts(&buf, "{\"name\":\"");
                strbf_put(&buf, pathbuf.start, pathbuf.cur - pathbuf.start);
                strbf_puts(&buf, "\",\"cmd\":\"");
                strbf_puts(&buf, p);
                strbf_puts(&buf, "\",\"result\":\"");
                if (err < 8) {
#if (C_LOG_LEVEL < 2)
                    DLOG(TAG, "Going to %s file: %s, uri: %s\n", p, pathbuf.start, req->uri);
#endif
                    if (ret == 2)
                        err = archive_file(req, pathbuf.start, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
                    else
                        err = unlink(pathbuf.start);
                }
                strbf_puts(&buf, !err ? "ok" : err > 7 ? "not found" : "failed");
                strbf_puts(&buf, "\"}\r\n");
                if (err) {
                    ESP_LOGE(TAG, "Failed to %s file : %s", p, pathbuf.start);
                    msg = buf.start;
                    msglen = buf.cur - buf.start;
                    goto err;
                }
                http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, buf.start, buf.cur - buf.start);
                break;
            case 3:
                directory_handler(req, filepath, 0, 1, &buf, flush_size);
                break;
            case -2:
                goto err;
            default:
                break;
        }
    }
    else {
        err:
        httpd_resp_set_status(req, HTTPD_500);
        http_send_json_msg(req, msg, msglen, 0, 0, 0);
    }
    strbf_free(&buf);
    httpd_resp_send_chunk(req, 0, 0);
    IMEAS_END(TAG, "[%s] %s done, took: %llu us", __func__, req->uri);
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    return ret;
}

esp_err_t get_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    char content_type[64] = {0}, *c = content_type;
    char filepath[VFS_FILE_PATH_MAX] = {0};
    //char strbuf[SCRATCH_BUFSIZE] = {0};
    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context);
    // int resp = (int)rest_context->request_no;
    //  char *resp_str = 0;
    strbf_t buf;
    strbf_init(&buf);
    //strbf_t data;
    //strbf_inits(&data, strbuf, SCRATCH_BUFSIZE);
    strbf_t pathbuf;
    strbf_inits(&pathbuf, filepath, VFS_FILE_PATH_MAX);
    size_t ulen = strlen(req->uri), tlen = 0;
    int fd = 0, err = ESP_OK;
    const char *p = 0;
    httpd_resp_set_hdr(req, "Connection", "close");
    add_cors(req, 0);
    p = req->uri + ulen - 1;
    while (p > req->uri && *p != '.' && *p != '/') --p;
#if (C_LOG_LEVEL < 2)
    DLOG(TAG, "uri part p:%s\n", p);
#endif
    if(ulen == 1)
        set_content_type_from_file(req, ".html", 5, &c);
    else 
        set_content_type_from_file(req, p, ulen - (p - req->uri), &c);
    if(try_local_file(req, ulen, 0, &buf, SCRATCH_BUFSIZE-128) == ESP_OK) {
        goto finishing;
    }
    if (strstr(req->uri, "/files") == req->uri) {
        err = try_file_path(req, &pathbuf, req->uri + 6);
        if (err == 3) {
            directory_handler(req, pathbuf.start, 0, 2, &buf, SCRATCH_BUFSIZE-128);
            goto finishing;
        }
        else goto get_file;
    } 
    else { // get file from base path
        err = try_file_path(req, &pathbuf, req->uri);
    get_file:
        if(err != 4){
            if(err==-2) httpd_resp_set_status(req, HTTPD_404);
            else httpd_resp_set_status(req, HTTPD_500);
            goto finishing;
        }
#if (C_LOG_LEVEL < 2)
       DLOG(TAG, "Going to open file: %s, uri: %s\n", &filepath[0], req->uri);
#endif
        fd = open(&(filepath[0]), O_RDONLY, 0);
        if (fd) {
            // set_content_type_from_file(req, pathbuf.start, pathbuf.cur - pathbuf.start);
            err = send_file(req, fd, 0);
            if(err) httpd_resp_set_status(req, HTTPD_500);
            if (fd<0 || close(fd)) {
                ELOG(TAG, "Failed to close (%s)", strerror(errno));
            }
        }
    }
finishing:
    httpd_resp_send_chunk(req, 0, 0);
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    strbf_free(&buf);
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return ESP_OK;
}

struct mpart_s {
    const char *start_mark;
    const char *end_mark;
    const char *fname_mark;
    bool done;
};

#define is_n_empty(b) ((b) && *(b))
#define is_eq(b, c) (*(b) == (c))
#define is_eq_safe(b, c) ((b) && is_eq(b, c))
#define is_crln(b) (is_eq(b, '\r') && is_eq(b + 1, '\n'))
#define is_crln_safe(b) (is_eq_safe(b, '\r') && is_eq_safe(b + 1, '\n'))
#define is_cr_o_ln(b) ((b) && (is_eq(b, '\r') || is_eq(b, '\n')))

#define FIND_B                       \
    if (mpb) {                       \
        mpb = strstr(mpb, boundary); \
    }
#define GOMP_S                                                        \
    while (mpb && mpb > parts[mpart_num].start_mark && *mpb == '-') { \
        --mpb;                                                        \
    }

typedef esp_err_t (*manage_file_cb_t)(httpd_req_t *req, const char *fname);

static esp_err_t delete_file_cb(httpd_req_t *req, const char *fname) {
    ILOG(TAG, "[%s] %s", __func__, fname);
    struct stat sb;
    if(!stat(fname, &sb)) {
        return unlink(fname);
    }
    return ESP_ERR_NOT_FOUND;
}

static esp_err_t archive_file_cb(httpd_req_t *req, const char *fname) {
    ILOG(TAG, "[%s] %s", __func__, fname);
    return archive_file(req, fname, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
}

static esp_err_t bulk_manage_files(httpd_req_t *req, char *fname, size_t flen, strbf_t *data, manage_file_cb_t cb, const char * action_name) {
    assert(data);
    ILOG(TAG, "[%s] %s %s", __func__, data->start, action_name ? action_name : "null");
    char * p = 0, *r = 0, *e = 0;
    esp_err_t ret = ESP_OK;
    if(data->start && data->cur > data->start) {
        strbf_t fbuf;
        p = data->start;
        strbf_inits(&fbuf, fname, flen);
        // strbf_puts(&fbuf, &base_path[0]);
        size_t len = fbuf.cur - fbuf.start;
        if((p=strchr(p, '{'))) { // json
            if((p=strstr(p, "\"name\":\""))) {
                p+=8;
                e = strchr(p, '"');
            }
            else {
                ret = http_send_json_msg(req, "No data.", 8, 1, 0, 0);
                goto done;
            }
        }
        else p = data->start;
#if (C_LOG_LEVEL < 1)
        DLOG(TAG, "data: %s\n", p);
#endif
        while(p && (!e || p<e)) {
            if(fbuf.cur-fbuf.start>len) strbf_shape(&fbuf, len);
            r = strchr(p, '|');
            if(!r) r = strchr(p, ',');
            if((!r && e) || (r && e && r > e) ) r = e;
            if(*(fbuf.cur-1)!='/' && *p != '/') strbf_putc(&fbuf, '/');
            if(r) {
                if(((fbuf.cur-fbuf.start) + (r-p) + 1) >= flen){
                    ret =http_send_json_msg(req, "Filename too long.", 18, 2, 0, 0);
                    goto done;
                }
                s_uri_decode(fbuf.cur, p, r - p);
                fbuf.cur += r - p;
            } else {
                s_uri_decode(fbuf.cur, p, e - p);
                fbuf.cur += e - p;
            }
            *fbuf.cur = 0;
#if (C_LOG_LEVEL < 2)
            DLOG(TAG, "%s file: %s\n", action_name, fbuf.start);
#endif
            if (!cb || cb(req, strbf_finish(&fbuf))) {
                ret =http_send_json_msg(req, "Failed", 6, 3, 0, 0);
                goto done;
            }
            p=r;
            if(p && (*p=='|' || *p == ',')) ++p;
        }
    } else {
        ret =http_send_json_msg(req, "No data.", 8, 1, 0, 0);
        goto done;
    }
    ret = http_send_json_msg(req, action_name, strlen(action_name), 0, 0, 0);
    done:
    return ret;
}

esp_err_t post_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
    IMEAS_START();
    struct mpart_s parts[4];
    memset(parts, 0, sizeof(parts));
    const char *mpb = 0, *mpb0 = 0;  //, *mpb1 = 0;
    char content_type[64] = {0}, *c = content_type;
    char prev[12] = {0};
    uint16_t buflen = SCRATCH_BUFSIZE, fnamelen = 0, boundarylen = 0;
    char *buf = malloc(buflen);
    char *boundary = malloc(80);
    char fname[64]={0};
    int fp = -1;
    bool mpart_open = false;
    uint8_t api = (strstr(req->uri, API_BASE) == req->uri) ? 1 : 0;
    uint8_t u_mode = strstr(req->uri, "/fw/update") >= req->uri ? 1 : 0;
    httpd_req_get_hdr_value_str(req, "Content-Type", buf, buflen);
    httpd_resp_set_hdr(req, "Connection", "close");
    mpb = strstr(buf, "multipart");
    bool is_multipart = (mpb && mpb == buf);
    if (mpb) {
        mpb = strstr(mpb, "boundary=");
        if (mpb) {
            mpb += 9;
            if (*mpb == '"') {
                ++mpb;
                mpb0 = strchr(mpb, '"') - 1;
            } else
                mpb0 = buf + strlen(buf);
            boundarylen = MIN(80, mpb0 - mpb);
            memcpy(boundary, mpb, boundarylen);
            boundary[boundarylen] = 0;
#if (C_LOG_LEVEL < 1)
            DLOG(TAG, "boundary found '%s' size '%" PRIu16 "'\n", boundary, boundarylen);
#endif
        }
    }

    esp_err_t err = ESP_OK;
    uint8_t mpart_num = 0;
    int recieved = 0, total_len = req->content_len;
    size_t tlen, ulen = strlen(req->uri);
    strbf_t data;
    strbf_init(&data);
    struct end_result_s ota_result;

    if (u_mode == 1) {
        err = ota_start();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start ota.");
            ota_deinit();
            goto toerr;
        }
    }
    uint32_t l = 0, now = 0;
    uint8_t retry_times = 0;
    while (total_len > 0) {
        // Read the data for the request
        now = get_millis();
        if ((recieved = httpd_req_recv(req, buf, MIN(total_len, buflen))) <= 0) {
            if (recieved == HTTPD_SOCK_ERR_TIMEOUT) {
                // Retry receiving if timeout occurred
                ESP_LOGW(TAG, "Socket timeout after %lu ms, retrying ...", get_millis() - now);
                if(retry_times++ < 3) continue;
            }
            ESP_LOGE(TAG, "http recieve data timeout, hanged at byte %lu", l);
            goto toerr; 
        }

        if (is_multipart) {
            parts[mpart_num].start_mark = buf;
            if (mpart_open) {
                parts[mpart_num].end_mark = buf + recieved;
            } else {
                parts[mpart_num].end_mark = 0;
            }
            if (recieved < buflen && recieved >= total_len) {
#if (C_LOG_LEVEL < 2)
                DLOG(TAG, "[%s] all data recieved bl:%" PRIu16 " rc:%d tl:%d\n", __FUNCTION__, buflen, recieved, total_len);
#endif
                *(buf + recieved) = 0;
            }
            mpb = mpb0 = buf;
            FIND_B
            if (mpb && !mpart_open) {  // mpart start
            open_mpart:
                mpart_open = true;
                mpb0 = strstr(mpb, "filename=\"");  // parse file name
                if (mpb0) {
                    mpb0 += 10;
                    mpb = strchr(mpb0, '"');
                    fnamelen = MIN(64, mpb - mpb0);
                    memcpy(fname, mpb0, fnamelen);
                    fname[fnamelen] = 0;
                }
#if (C_LOG_LEVEL < 3)
                ILOG(TAG, "[%s] found multipart file begin, fname: '%s' len: '%d'", __FUNCTION__, fname, fnamelen);
#endif
                parts[mpart_num].end_mark = (buf + recieved);
                // printf("[%s] start mpb(001): '%s' \n", __FUNCTION__, mpb);
                while (mpb && mpb < parts[mpart_num].end_mark && !(is_crln_safe(mpb) && is_crln_safe(mpb + 2))) {
                    ++mpb;
                }
                // printf("[%s] start mpb(01): '%s' \n", __FUNCTION__, mpb);
                while (is_cr_o_ln(mpb)) {  // pointer back to first char after CRLF
                    ++mpb;
                }
                parts[mpart_num].start_mark = mpb;
                // printf("[%s] start mpb(1): '%s' \n", __FUNCTION__, mpb);
                FIND_B  // try to find part end boundary
            }
            if (mpb && mpart_open) {  // mpart end
                if (!is_eq(mpb, '-') && is_eq_safe(mpb - 1, '-')) {
                    --mpb;
                }
                GOMP_S                         // move back to the beginning of second boundary
                    while (is_cr_o_ln(mpb)) {  // pointer back to last char before CRLF
                    --mpb;
                }
                ++mpb;  // first nl character shuld be fine.
                // printf("[%s] end mpb(002): '%s' \n", __FUNCTION__, mpb);
                parts[mpart_num].end_mark = mpb;
                parts[mpart_num].done = 1;
                mpart_open = false;

                mpb0 = buf + recieved;
                while (is_cr_o_ln(mpb)) {  // pointer back to last char before CRLF
                    ++mpb;
                }
                while (mpb && mpb < mpb0 && !is_crln_safe(mpb))  // move cursor to newline at end of boundary
                    ++mpb;
                if (is_cr_o_ln(mpb))  // move to last not crln char to test end of boundaries marking
                    --mpb;
                // printf("[%s] mpb(02): '%s' \n", __FUNCTION__, mpb);

                /* printf("[%s] filtered data part: \"", __FUNCTION__);
                mpb0 = parts[mpart_num].start_mark;
                while (mpb0 && mpb0 < parts[mpart_num].end_mark) {
                    printf("%c", *mpb0);
                    ++mpb0;
                }
                printf("\" \n"); */
                // check if there is more boundaries
                if (mpb && !(is_eq(mpb, '-') && is_eq_safe(mpb - 1, '-'))) {  // verify wether part end or not
                    ++mpart_num;
                    goto open_mpart;
                }
            }

            if (u_mode == 1 && parts[0].end_mark) {
                err = ota_write((uint8_t *)parts[0].start_mark, parts[0].end_mark - parts[0].start_mark);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to write ota.");
                    ota_deinit();
                    goto toerr;
                }
            } else if (u_mode == 0 && fnamelen) {
                if (!fname[0])  // no file name, no upload
                    goto toerr;
                else if (fp < 0) {
                    char path[128] = {0};
                    const char *p = req->uri, *e = req->uri;
                    strbf_t pbuf;
                    while(e && *e) ++e;
                    strbf_inits(&pbuf, path, MIN(e-p+1, 128));
                    // strbf_put_path(&pbuf, &base_path[0]);
                    
                    if((p=strstr(req->uri, "/files/")) && p[7]) {
                        p+=7;
                        while(*p && *p == '/') ++p;
                        while(*p && *p != '/') --p;
                        strbf_put_path_n(&pbuf, p, MIN(e-p, 128));
                        if(e-p>128) {
                            WLOG(TAG, "Too long path, max allowed 128 bytes: %s", pbuf.start);
                        }
                    } else {
                        strbf_put_path(&pbuf, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
                    }
#if CONFIG_LOGGER_HTTP_LOG_LEVEL < 2
                    DLOG(TAG, "[%s] open path: %s name: %s\n", __func__, pbuf.start, fname);
#endif
                    fp = s_open(fname, pbuf.start, "w+");
                }
                if (fp >= 0) {
                    write(fp, parts[0].start_mark, parts[0].end_mark - parts[0].start_mark);
                } else {
                    goto toerr;
                }
            }
            if (parts[mpart_num].done && mpart_open) {
                break;
            }
        } else {
#if (C_LOG_LEVEL < 2)
            DLOG(TAG, "[%s] got buffered data '%s'\n", __FUNCTION__, buf);
#endif
            if(l+recieved >= buflen) {
                ELOG(TAG, "[%s] Buffer overflow.", __func__);
                goto toerr;
            }
            strbf_put(&data, buf, recieved);
            
        }
        l += recieved;
#if (C_LOG_LEVEL < 2)
        DLOG(TAG, "[%s] recieved: %d, total: %d, l: %lu\n", __FUNCTION__, recieved, total_len, l);
#endif
        total_len -= recieved;
        memcpy(prev, buf + recieved - 11, 11);
        prev[11] = 0;
    }
    if (is_multipart) {
        if (u_mode == 1) {
            err = ota_end(&ota_result);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to finish ota.");
                ota_deinit();
            };
            ILOG(TAG, "Ota finished%s", ".");
        } else {
            if (fp > 0) {
#if (C_LOG_LEVEL < 2)
                DLOG(TAG, "[%s] Close file being saved to %s\n", __func__, fname);
#endif
                close(fp);
            } else
                goto toerr;
        }
    }
#if (C_LOG_LEVEL < 2)
    ILOG(TAG, "Post request saved %lu bytes.", l);
#endif
    if (!is_multipart) {
        if (!data.start || data.cur == data.start) {
            goto toerr;
        }
        ILOG(TAG, "got post request : '%s'", data.start);
    }

    /* rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context); */

    add_cors(req, api);
    if (api) {
        set_content_type_from_file(req, ".json", 5, &c);
        tlen = 8;
        mpb = req->uri + tlen;
        if (strstr(mpb, "files/delete") == mpb) {
            if(bulk_manage_files(req, fname, 64, &data, delete_file_cb, "delete") != 0) {
                ESP_LOGE(TAG, "[%s] delete failed.", __FUNCTION__);
            }
            goto done;
        }
        if (strstr(mpb, "files/archive") == mpb) {
            if(bulk_manage_files(req, fname, 64, &data, archive_file_cb, "archive") != 0) {
                ESP_LOGE(TAG, "[%s] archive failed.", __FUNCTION__);
            }
            goto done;
        }
        else if (strstr(mpb, "files/upload") == mpb) {
            http_send_json_msg(req, "uploaded.", 9, 0, 0, 0);
            goto done;
        } else if (strstr(mpb, "fw/update") == mpb) {
            tlen = 17;
            http_send_json_msg(req, "Firmware updated.", 17, 0, 0, 0);
            goto done;
        } else if (strstr(mpb, "config") == mpb) {
            tlen = 14;
            const char *p = req->uri + tlen, *r = 0;
            if (ulen > tlen && *p == '/') {
                r = req->uri + ulen - 1;
                while (r > p && r && *r != '/')
                    --r;
                if (r && *r == '/')
                    ++r;
                if (!r || r - req->uri == ulen) {
                    r = 0;
                }
            }
            strbf_t respsb;
            if (config_save_var(m_context.config, data.start, 0) > 0) {
                strbf_init(&respsb);
                config_get(m_context.config, r, &respsb, 1);
                http_send_json_msg(req, "Saved", 5, 0, respsb.start, respsb.cur - respsb.start);
                strbf_free(&respsb);
                goto done;
            } else {
                err = -1;
            }
        }
        if (err < 0) {
    toerr:
        ESP_LOGE(TAG, "[%s] Request failed.", __FUNCTION__);
        http_send_json_msg(req, "Could not finish.", 17, 1, 0, 0);
    } else
        http_send_json_msg(req, "Post data successfully", 22, 0, 0, 0);
    }
    else {
        httpd_resp_set_status(req, HTTPD_200);
    }
done:
    httpd_resp_send_chunk(req, 0, 0);
    if (ota_result.status == ESP_OK && ota_result.callback)
        ota_result.callback();  // will request restart
#if (C_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    strbf_free(&data);
    free(buf);
    free(boundary);
    IMEAS_END(TAG, "[%s] %s took: %llu us", __func__, req->uri);
    return err;
}

#undef FIND_B
#undef GOMP_S
#if defined(X1)
static void async_req_worker_task(void *p) {
    ILOG(TAG, "[%s]", __func__);
    uint16_t loops = 0;
    while (true) {
        // counting semaphore - this signals that a worker
        // is ready to accept work
        xSemaphoreGive(worker_ready_count);

        // wait for a request
        httpd_async_req_t async_req;
        if (xQueueReceive(async_req_queue, &async_req, portMAX_DELAY)) {
            httpd_req_t *req = async_req.req;
            ILOG(TAG, "invoking uri '%s'", req->uri);

            // call the handler
            async_req.handler(req);

            // Inform the server that it can purge the socket used for
            // this request, if needed.
            if (httpd_req_async_handler_complete(req) != ESP_OK) {
                ESP_LOGE(TAG, "failed to complete async req");
            }
            ILOG(TAG, "completed uri '%s'", req->uri);
        }
        // if(loops++ > 100) {
        //     loops = 0;
        // }
        delay_ms(50);
    }
}

void start_async_req_workers(void) {
    ILOG(TAG, "[%s]", __func__);
    // counting semaphore keeps track of available workers
    worker_ready_count = xSemaphoreCreateCounting(worker_num,  // Max Count
                                                  0);          // Initial Count
    if (worker_ready_count == NULL) {
        ESP_LOGE(TAG, "Failed to create workers counting Semaphore");
        return;
    }
    // create queue
    async_req_queue = xQueueCreate(3, sizeof(httpd_async_req_t));
    if (async_req_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create async_req_queue");
        if(worker_ready_count) {
            vSemaphoreDelete(worker_ready_count);
            worker_ready_count = NULL;
        }
        return;
    }
    // start worker tasks
    for (int i = 0; i < worker_num; i++) {
        ILOG(TAG, "Starting asyncReqWorker %d", i);
        bool success = xTaskCreate(async_req_worker_task, "async_req_worker",
                                   CONFIG_WEB_SERVER_ASYNC_WORKER_TASK_STACK_SIZE,  // stack size
                                   (void *)0,                     // argument
                                   ASYNC_WORKER_TASK_PRIORITY,    // priority
                                   &worker_handles[i]);
            if (!success) {
            ESP_LOGE(TAG, "Failed to start asyncReqWorker");
            continue;
        }
    }
}

void stop_async_req_workers(void) {
    ILOG(TAG, "[%s]", __func__);
    if (worker_ready_count == NULL) {
        return;
    }
    for (int i = 0; i < worker_num; i++) {
        vTaskDelete(worker_handles[i]);
        worker_handles[i] = NULL;
    }
    if (async_req_queue != NULL) {
        vQueueDelete(async_req_queue);
        async_req_queue = NULL;
    }
}
#endif
#endif
