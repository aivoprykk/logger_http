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
#if (OLDDD > 0)
#if (ESP_IDF_VERSION_MAJOR < 5 || (ESP_IDF_VERSION_MAJOR == 5 && (ESP_IDF_VERSION_MINOR < 2 )))

#define HTTPD_SCRATCH_BUF MAX(HTTPD_MAX_REQ_HDR_LEN, HTTPD_MAX_URI_LEN)
#define PARSER_BLOCK_SIZE 128
/**
 * @brief A database of all the open sockets in the system.
 */
struct sock_db {
    int fd;                       /*!< The file descriptor for this socket */
    void *ctx;                    /*!< A custom context for this socket */
    bool ignore_sess_ctx_changes; /*!< Flag indicating if session context
                                     changes should be ignored */
    void *transport_ctx;          /*!< A custom 'transport' context for this socket, to
                                     be   used by send/recv/pending */
    httpd_handle_t handle;        /*!< Server handle */
    httpd_free_ctx_fn_t free_ctx; /*!< Function for freeing the context */
    httpd_free_ctx_fn_t
        free_transport_ctx;               /*!< Function for freeing the 'transport' context */
    httpd_send_func_t send_fn;            /*!< Send function for this socket */
    httpd_recv_func_t recv_fn;            /*!< Receive function for this socket */
    httpd_pending_func_t pending_fn;      /*!< Pending function for this socket */
    uint64_t lru_counter;                 /*!< LRU Counter indicating when the socket was last
                                             used */
    bool lru_socket;                      /*!< Flag indicating LRU socket */
    char pending_data[PARSER_BLOCK_SIZE]; /*!< Buffer for pending data to be
                                             received */
    size_t pending_len;                   /*!< Length of pending data to be received */
    bool for_async_req;                   /*!< If true, the socket will not be LRU purged */
#ifdef CONFIG_HTTPD_WS_SUPPORT
    bool ws_handshake_done;                  /*!< True if it has done WebSocket handshake (if
                                                this socket is a valid WS) */
    bool ws_close;                           /*!< Set to true to close the socket later (when WS Close
                                                frame received) */
    esp_err_t (*ws_handler)(httpd_req_t *r); /*!< WebSocket handler, leave to
                                                null if it's not WebSocket */
    bool ws_control_frames;                  /*!< WebSocket flag indicating that control frames
                                                should be passed to user handlers */
    void *ws_user_ctx;                       /*!< Pointer to user context data which will be available
                                                to handler for websocket*/
#endif
};

struct httpd_req_aux {
    struct sock_db *sd; /*!< Pointer to socket database */
    char scratch[HTTPD_SCRATCH_BUF + 1];         /*!< Temporary buffer for our operations (1 byte extra for null termination) */
    size_t remaining_len;    /*!< Amount of data remaining to be fetched */
    char *status;            /*!< HTTP response's status code */
    char *content_type;      /*!< HTTP response's content type */
    bool first_chunk_sent;   /*!< Used to indicate if first chunk sent */
    unsigned req_hdrs_count; /*!< Count of total headers in request packet */
    unsigned
        resp_hdrs_count; /*!< Count of additional headers in response packet */
    struct resp_hdr {
        const char *field;
        const char *value;
    } *resp_hdrs;                         /*!< Additional headers in response packet */
    struct http_parser_url url_parse_res; /*!< URL parsing result, used for
                                             retrieving URL elements */
#ifdef CONFIG_HTTPD_WS_SUPPORT
    bool ws_handshake_detect; /*!< WebSocket handshake detection flag */
    httpd_ws_type_t ws_type;  /*!< WebSocket frame type */
    bool ws_final;            /*!< WebSocket FIN bit (final frame or not) */
    uint8_t mask_key[4];      /*!< WebSocket mask key for this payload */
#endif
};

esp_err_t httpd_req_async_handler_begin(httpd_req_t *r, httpd_req_t **out) {
    if (r == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // alloc async req
    httpd_req_t *async = malloc(sizeof(httpd_req_t));
    if (async == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(async, r, sizeof(httpd_req_t));

    // alloc async aux
    async->aux = malloc(sizeof(struct httpd_req_aux));
    if (async->aux == NULL) {
        free(async);
        return ESP_ERR_NO_MEM;
    }
    memcpy(async->aux, r->aux, sizeof(struct httpd_req_aux));
    // void * u = (void*)&(async->uri[0]), *v = (void*)&(r->uri[0]);
    // memcpy(u, v, sizeof(async->uri));
    // async->user_ctx = r->user_ctx;

    // mark socket as "in use"
    struct httpd_req_aux *ra = r->aux;
    ra->sd->for_async_req = true;

    *out = async;

    return ESP_OK;
}

esp_err_t httpd_req_async_handler_complete(httpd_req_t *r) {
    if (r == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    struct httpd_req_aux *ra = r->aux;
    ra->sd->for_async_req = false;

    free(r->aux);
    free(r);

    return ESP_OK;
}
#endif
#endif

static uint8_t is_on_async_worker_thread(void) {
    // is our handle one of the known async handles?
    TaskHandle_t handle = xTaskGetCurrentTaskHandle();
    for (int i = 0; i < worker_num; i++) {
        if (worker_handles[i] == handle) {
            ILOG(TAG, "[%s] found on async worker thread num %d", __func__, i);
            return true;
        }
    }
    ILOG(TAG, "[%s] Not on async worker thread", __func__);
    return false;
}

// Submit an HTTP req to the async worker queue
static esp_err_t submit_async_req(httpd_req_t *req, httpd_req_handler_t handler) {
    ILOG(TAG, "[%s]", __func__);
    // must create a copy of the request that we own
    httpd_req_t *copy = NULL;
    esp_err_t err = httpd_req_async_handler_begin(req, &copy);
    if (err != ESP_OK) {
        return err;
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
        return ESP_FAIL;
    }

    // Since worker_ready_count > 0 the queue should already have space.
    // But lets wait up to 100ms just to be safe.
    if (xQueueSend(async_req_queue, &async_req, pdMS_TO_TICKS(100)) == false) {
        ESP_LOGE(TAG, "worker queue is full");
        httpd_req_async_handler_complete(copy);  // cleanup
        return ESP_FAIL;
    }

    return ESP_OK;
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
    "}\n",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    ",\"total_space\":",
    ",\"free_space\":",
    "</td></tr><tr><td>",
    "</td><td>"
};

static esp_err_t http_send_json_msg(httpd_req_t *req, const char *msg, int msg_size, int status, char * data, int data_size) {
    DLOG(TAG, "[%s] %s", __func__, msg);
    httpd_resp_send_chunk(req, http_async_handler_strings[0], 11); // status
    if(status==0)
        httpd_resp_send_chunk(req, http_async_handler_status_strings[0], 2);
    else {
        httpd_resp_send_chunk(req, http_async_handler_status_strings[1], 5);
    }
    httpd_resp_send_chunk(req, http_async_handler_strings[1], 9); // msg
    httpd_resp_send_chunk(req, msg, msg_size==0 ? -1 : msg_size);
    httpd_resp_send_chunk(req, "\"", 1);
    if(data) {
        httpd_resp_send_chunk(req, http_async_handler_strings[2], 8); //data
        httpd_resp_send_chunk(req, data, data_size == 0 ? -1 : data_size);
    }
    httpd_resp_send_chunk(req, http_async_handler_strings[3], 2); // end
    return status;
}

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(void *_req, const char *filepath, size_t pathlen) {
    ILOG(TAG, "[%s]", __func__);
    assert(filepath);
    httpd_req_t *req = _req;
    const char *type = "text/plain";
    if (CHECK_FILE_EXTENSION(filepath, pathlen, ".html", 5)) {
        type = HTTPD_TYPE_TEXT;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".js", 3)) {
        type = "application/javascript";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".css", 4)) {
        type = "text/css";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".png", 4)) {
        type = "image/png";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".ico", 4)) {
        type = "image/x-icon";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".svg", 4)) {
        type = "text/xml";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".sbp", 4)) {
        type = HTTPD_TYPE_OCTET;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".ubx", 4)) {
        type = HTTPD_TYPE_OCTET;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".gpx", 4)) {
        type = HTTPD_TYPE_OCTET;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".gpy", 4)) {
        type = HTTPD_TYPE_OCTET;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".txt", 4)) {
        type = "text/plain";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".json", 5)) {
        type = HTTPD_TYPE_JSON;
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".eot", 4)) {
        type = "font/eot";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".ttf", 4)) {
        type = "font/ttf";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".woff", 5)) {
        type = "font/woff";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".woff2", 6)) {
        type = "font/woff2";
    } else if (CHECK_FILE_EXTENSION(filepath, pathlen, ".jpg", 4)) {
        type = "image/jpg";
    }
    DLOG(TAG, "[%s] done file: %s, type: %s", __FUNCTION__, filepath, type);
    return httpd_resp_set_type(req, type);
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
            return ret;
        }
    }
    const char *p = filename;
    if (strstr(filename, base) == filename)
        p += strlen(base);
    strbf_put_path(&sb, p);
    DLOG(TAG, "Move to arcive %s => %s", filename, sb.start);
    ret = s_rename_file_n(filename, sb.start, 0);
#endif
    return ret;
}

static esp_err_t send_file(httpd_req_t *req, int fd, uint32_t len, char * chunk, size_t chunk_size) {
    ILOG(TAG, "[%s]", __func__);
    if (fd <= 0) {
        return ESP_FAIL;
    }
    if(!req)
        return ESP_FAIL;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    char tmp[8] = {0};
    if (len) {
        xultoa(len, &(tmp[0]));
        esp_err_t err = httpd_resp_set_hdr(req, "Content-Length", tmp);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
        } else {
            ILOG(TAG, "[%s] content length set as %s bytes", __FUNCTION__, tmp);    
        }
    }
    int32_t read_bytes, i = len;
    do {
        read_bytes = read(fd, chunk, chunk_size-1);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 1)
        printf("%ld ", read_bytes);
#endif
        if (read_bytes == -1) {
            ESP_LOGE(TAG, "Failed to read file.");
            httpd_resp_set_status(req, HTTPD_500);
            // http_send_json_msg(req, "Failed to send file", 19, 1, 0, 0);
            return ESP_FAIL;
        } else if (read_bytes > 0) {
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK) {
                // close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                // httpd_resp_sendstr_chunk(req, NULL);
                httpd_resp_set_status(req, HTTPD_500);
                // http_send_json_msg(req, "Failed to send file", 19, 1, 0, 0);
                return ESP_FAIL;
            }
        }
        i -= read_bytes;
    } while (read_bytes > 0);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 1)
    printf("\n");
#endif
    // send complete
    // httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t config_handler_json(httpd_req_t *req, strbf_t *sb, const char *str, char * buf, size_t blen) {
    ILOG(TAG, "[%s]", __func__);
    //ESP_LOGI(TAG, "[%s] %s, config: '%s' method(%d)", __FUNCTION__, req->uri, str ? str : "null", req->method);
    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    const logger_config_t *config = m_context.config;
    // const uint8_t ublox_hw = g_context_get_ubx_hw(&m_context);
    size_t flush_size = blen;
    
    if (str) {
        gps_config_get(str, sb, 1);
        if(sb->cur == sb->start) config_get(config, str, sb, 1);
        if(sb->cur > sb->start){
            httpd_resp_set_status(req, HTTPD_200);
        }
        else
            goto err;
    } else {
        strbf_puts(sb, "[");
        if(sb->cur > sb->start){
            httpd_resp_set_status(req, HTTPD_200);
        }
        else {
            goto err;
        }

        const char *start_ptr = config_item_names;
        const char *end_ptr = 0;
        
        for(uint8_t i = 0; i < gps_user_cfg_item_count; i++) {
            if(gps_cnf_get_item(i+CFG_GPS_ITEM_BASE, sb, 1) >= 253) {
                continue;
            }
            strbf_putc(sb, ',');
            strbf_putc(sb, '\n');
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
                strbf_putc(sb, '\n');
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
        return ESP_OK;
    }    
err:
    httpd_resp_set_status(req, HTTPD_500);
    http_send_json_msg(req, "fail", 4, 1, 0, 0);
    return ESP_FAIL;
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
    httpd_resp_send_chunk(req, http_async_handler_strings[3], 2); // }\n
    httpd_resp_send_chunk(req, 0, 0);
    return ESP_OK;
}

static int uint8_array_to_ipv4_string(uint8_t *ipv4, char *buf) {
    return sprintf(buf, "%hhu.%hhu.%hhu.%hhu", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
}

/* Simple handler for getting system handler */
static esp_err_t system_info_get_handler(httpd_req_t *req, uint8_t mode, char * buf, size_t blen) {
    ILOG(TAG, "[%s]", __func__);
    char lbuf[16] = {0};
    size_t llen = 0;
    strbf_t databuf;
    strbf_inits(&databuf, buf, blen);
    size_t flush_size = SCRATCH_BUFSIZE-128;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    if(mode == 2) { 
        strbf_puts(&databuf, "<table class=\"table-2\"><tr><td>IDF version");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, "{\"version\":\"");
    strbf_puts(&databuf, IDF_VER);
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Cores");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, "\",\"cores\":");
    strbf_putl(&databuf,chip_info.cores);
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Model");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, ",\"model\":\"");
    strbf_puts(&databuf, "esp32");
    if(chip_info.model != 1) strbf_put(&databuf, "s3", 2);
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Revision");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, "\",\"revision\":");
    strbf_putl(&databuf, chip_info.revision);
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Fwversion");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, ",\"fwversion\":\"");
    strbf_puts(&databuf, m_context.SW_version);
    #if defined(CONFIG_LOGGER_WIFI_ENABLED)
    if(wifi_context.s_ap_connection) {
        if(mode == 2) { 
            strbf_puts(&databuf, http_async_handler_strings[8]);
            strbf_puts(&databuf,"Ap_ssid");
            strbf_puts(&databuf, http_async_handler_strings[9]);
        } else strbf_puts(&databuf, "\",\"ap_ssid\":\"");
        strbf_puts(&databuf, wifi_context.ap.ssid);
        if(mode == 2) { 
            strbf_puts(&databuf, http_async_handler_strings[8]);
            strbf_puts(&databuf,"Ap_address");
            strbf_puts(&databuf, http_async_handler_strings[9]);
        } else strbf_puts(&databuf, "\",\"ap_address\":\"");
        llen = uint8_array_to_ipv4_string(wifi_context.ap.ipv4_address, &lbuf[0]);
        strbf_put(&databuf, lbuf, llen);
    }
    if(wifi_context.s_sta_connection) {
        if(mode == 2) { 
            strbf_puts(&databuf, http_async_handler_strings[8]);
            strbf_puts(&databuf,"Sta_sid");
            strbf_puts(&databuf, http_async_handler_strings[9]);
        } else strbf_puts(&databuf, "\",\"sta_ssid\":\"");
        if(wifi_context.s_sta_got_ip)
         strbf_puts(&databuf, wifi_context.stas[wifi_context.s_sta_num_connect].ssid);
        if(mode == 2) { 
            strbf_puts(&databuf, http_async_handler_strings[8]);
            strbf_puts(&databuf,"Sta_address");
            strbf_puts(&databuf, http_async_handler_strings[9]);
        } else strbf_puts(&databuf, "\",\"sta_address\":\"");
        if(wifi_context.s_sta_got_ip)
            llen = uint8_array_to_ipv4_string(wifi_context.stas[wifi_context.s_sta_num_connect].ipv4_address, &lbuf[0]);
        strbf_put(&databuf, lbuf, llen);
    }
    #endif
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Hostname");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, "\",\"hostname\":\"");
    strbf_puts(&databuf, wifi_context.hostname);
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Freeheap");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, "\",\"freeheap\":");
    strbf_putl(&databuf, esp_get_free_heap_size());
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Minfreeheap");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, ",\"minfreeheap\":");
    strbf_putl(&databuf, esp_get_minimum_free_heap_size());
    if(mode == 2) { 
        strbf_puts(&databuf, http_async_handler_strings[8]);
        strbf_puts(&databuf,"Battery");
        strbf_puts(&databuf, http_async_handler_strings[9]);
    } else strbf_puts(&databuf, ",\"battery\":");
#if defined(CONFIG_LOGGER_ADC_ENABLED)
    llen = f3_to_char(volt_read(), lbuf);
#endif
    if(llen) {
        strbf_put(&databuf, lbuf, llen);
    } else {
        strbf_putc(&databuf, '0');
    }
    if(mode == 2) { 
        strbf_puts(&databuf, "</td></tr></table>");
    } else strbf_puts(&databuf, http_async_handler_strings[3]); // }\n
    httpd_resp_send_chunk(req, databuf.start, databuf.cur - databuf.start);
    return ESP_OK;
}

static esp_err_t paths_handler(httpd_req_t *req, uint8_t mode, char * buf, size_t blen) {
    ILOG(TAG, "[%s]", __func__);
    DIR *dirp = NULL;
    const struct dirent *ent;
    char type;
    char size[16] = {0};
    char tpath[VFS_FILE_PATH_MAX];
    char tbuffer[92] ={0};
    uint8_t i = 0;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    httpd_resp_set_type(req, mode==1 ? HTTPD_TYPE_JSON : HTTPD_TYPE_TEXT);
    strbf_t databuf;
    strbf_inits(&databuf, buf, blen);
    size_t flush_size = SCRATCH_BUFSIZE-128;
    if(mode==1)
        httpd_resp_send_chunk(req, "{\"paths\": [", 11);
    while(i < VFS_MAX_PARTS) {
        if(vfs_ctx.parts[i].is_mounted) {
            if(i > 0) {
                if(mode==1)
                    strbf_putc(&databuf, ',');
                else
                    strbf_putc(&databuf, '\n');
            }
            if(mode==1)
                strbf_puts(&databuf, "{\"path\":\"");
            else
                strbf_puts(&databuf, "Path: ");
            strbf_puts(&databuf, vfs_ctx.parts[i].mount_point);
            strbf_putc(&databuf, '"');
            if(mode==1)
                strbf_put(&databuf, http_async_handler_strings[6], 15);
            else
                strbf_puts(&databuf, ", Total bytes: ");
            strbf_putul(&databuf, vfs_ctx.parts[i].total_bytes);
            if(mode==1)
                strbf_put(&databuf, http_async_handler_strings[7], 14);
            else
                strbf_puts(&databuf, ", Free bytes: ");
            strbf_putul(&databuf, vfs_ctx.parts[i].free_bytes);
            if(mode==1)
                strbf_putc(&databuf, '}');
            if(databuf.cur - databuf.start >= flush_size) {
                httpd_resp_send_chunk(req, databuf.start, databuf.cur - databuf.start);
                strbf_shape(&databuf, 0);
            }
        }
        i++;
    }
    if(databuf.cur - databuf.start > 0) {
        httpd_resp_send_chunk(req, databuf.start, databuf.cur - databuf.start);
    }
    if(mode==1)
        httpd_resp_send_chunk(req, "]\n}", 3);
    return ESP_OK;
}

static esp_err_t directory_handler(httpd_req_t *req, const char *path, const char *match, uint8_t mode, char * buf, size_t blen) {
    ILOG(TAG, "[%s] uri: %s, path: %s", __func__, req->uri, path ? path : "null");
    DIR *dirp = NULL;
    const struct dirent *ent;
    char type;
    char size[16] = {0};
    char tpath[VFS_FILE_PATH_MAX];
    char tbuffer[92] ={0};
    struct stat statbuf;
    struct tm *tm_info;
    // char *lpath = NULL;
    int statok;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif

    httpd_resp_set_type(req, mode==1 ? HTTPD_TYPE_JSON : HTTPD_TYPE_TEXT);
    
    // Open directory
    dirp = opendir(path);
    if (!dirp) {
        httpd_resp_set_status(req, HTTPD_500);
        if(mode==1) {
            http_send_json_msg(req, "Error opening directory", 23, 1, 0, 0);
            // httpd_resp_send_chunk(req, "[]", 1);
        }
        else{
            httpd_resp_send_chunk(req, "Error opening directory.\n", 24);
        }
        return 0;
    }
    httpd_resp_set_status(req, HTTPD_200);

    // Read directory entries
    uint64_t total = 0;
    uint32_t nfiles = 0, nitems = 0;
    strbf_t databuf, pathbuf;
    
    // path buffer
    strbf_inits(&pathbuf, tpath, VFS_FILE_PATH_MAX);
    strbf_puts(&pathbuf, path);
    size_t len = pathbuf.cur - pathbuf.start;

    // data buffer
    strbf_inits(&databuf, buf, blen);
    size_t flush_size = SCRATCH_BUFSIZE-128;

    size_t i = 0;
    if(mode==1) {
        httpd_resp_send_chunk(req, "{\"path\":\"", 9);
        httpd_resp_send_chunk(req, path, len);
        httpd_resp_send_chunk(req, "\"", 1);
        httpd_resp_send_chunk(req, ",\"data\":[", 9);
    }
    else {
        httpd_resp_send_chunk(req, "T  Size      Date/Time         Name\n-----------------------------------\n", 72);
    }

    while ((ent = readdir(dirp)) != NULL) {
        strbf_shape(&pathbuf, len);
        strbf_put_path(&pathbuf, ent->d_name);
        tbuffer[0] = '\0';
        if ((match == NULL) || (fnmatch(match, &(tpath[0]), (FNM_PERIOD)) == 0)) {
            // Get file stat
            statok = stat(&(tpath[0]), &statbuf);
            if(mode==1){
                if(!nitems)
                    strbf_putc(&databuf, '{');
                else
                    strbf_puts(&databuf, ",{");
            }
            if (statok == 0) {
                tm_info = localtime(&statbuf.st_mtime);
                strftime(tbuffer, 92, "%Y-%m-%d %R", tm_info);
            }
            else if(mode==0) { // text
                strbf_puts(&databuf, "                ");
            }

            if (ent->d_type == DT_REG) {
                type = 'f';
                nfiles++;
                if (statok){
                    if(mode == 1)
                        *size = '?';
                    else
                        sprintf(size, "%8s", "?");
                }
                else {
                    total += statbuf.st_size;
                    if (statbuf.st_size < (1024 * 1024))
                        sprintf(size, "%8d", (int)statbuf.st_size);
                    else if ((statbuf.st_size / 1024) < (1024 * 1024))
                        sprintf(size, "%6dKB", (int)(statbuf.st_size / 1024));
                    else
                        sprintf(size, "%6dMB", (int)(statbuf.st_size / (1024 * 1024)));
                }
            } else {
                type = 'd';
                if(mode == 1)
                    *size = '-';
                else
                    sprintf(size, "%8s", "-");
            }
            ++nitems;
            if(mode==1)
                strbf_puts(&databuf, "\"name\":\"");
            strbf_puts(&databuf, ent->d_name);
            if(mode==1)
                strbf_puts(&databuf, "\",\"date\":\"");
            else
                strbf_puts(&databuf, " ");
            if (!statok)
                strbf_puts(&databuf, tbuffer);
            if(mode==1)
                strbf_puts(&databuf, "\",\"size\":\"");
            else
                strbf_puts(&databuf, " ");
            if (!statok && ent->d_type == DT_REG)
                strbf_putul(&databuf, (int)statbuf.st_size);
            if(mode==1)
                strbf_puts(&databuf, "\",\"type\":\"");
            else
                strbf_puts(&databuf, " ");
            strbf_putc(&databuf, type);
            if(mode==1)
                strbf_puts(&databuf, "\",\"mode\":\"");
            else
                strbf_puts(&databuf, " ");
            if (strstr(ent->d_name, "config")) {
                strbf_puts(&databuf, "r");
            } else
                strbf_puts(&databuf, "rw");
            if(mode==1)
                strbf_puts(&databuf, "\"}");
            else
                strbf_puts(&databuf, "\n");
            *databuf.cur=0;
            i+=databuf.cur - databuf.start;
            if(databuf.cur - databuf.start > flush_size) {
                httpd_resp_send_chunk(req, databuf.start, databuf.cur - databuf.start);
                strbf_shape(&databuf, 0);
                DLOG(TAG, "[%s] Flush at %lu files, %lu items, %llu bytes, %u bytes sent.", __FUNCTION__, nfiles, nitems, total, i);
            }
        }
    }
    strbf_puts(&databuf, mode==1 ? "]}" : "\n");
    if(databuf.cur > databuf.start) {
        httpd_resp_send_chunk(req, databuf.start, databuf.cur - databuf.start);
    }
    closedir(dirp);
    DLOG(TAG, "[%s] Total %lu files, %lu items, %llu bytes, %u bytes sent.", __FUNCTION__, nfiles, nitems, total, i);
    // strbf_free(&databuf);
    return ESP_OK;
}

static const char * html_handler_str[] = {
    "<!DOCTYPE html><html lang=\"en\"><head><title>ESP-LOGGER ::",
    "</title><meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"index.css\"><script src=\"index.js\"></script>"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><header><nav><ul>"
    "<li class=\"brand\"><span class=\"lg\">ESP-LOGGER</span><span class=\"sm\">GPS</span></li></ul><ul><li class=\"home\">"
    "<a class=\"secondary\" href=\"/\">Home</a></li><li class=\"files\"><a class=\"secondary\" href=\"/files.html\">"
    "Files</a></li><li class=\"config\"><a class=\"secondary\" href=\"/config.html\">Config</a></li>"
    "<li class=\"fwupdate\"><a class=\"secondary\" href=\"/fwupdate.html\">FW Update</a></li></ul></nav></header>"
    "<main><div class=\"container\"><article class=\"card ",
    "\"><header class=\"card-header\"><div class=\"flexrow\">",
    "<img src=\"/logo.svg\" alt=\"Logger\" />",
    "<h2>Files</h2><div class=\"left selection\" style=\"display:none\" hidden><button class=\"outline dl\">Download selected</button>"
    "<button class=\"outline rm\">Delete selected</button><button class=\"outline ar\">Archive selected</button></div><div class=\"right upload-file\">"
    "<label class=\"upload-file-select\"><span class=\"file-text\">Upload file</span><input type=\"file\" /></label><button class=\"outline upload-submit\" style=\"display:none\">Upload</button>"
    "</div></div><div class=\"flexrow info\">",
    "<h2>Configuration</h2>",
    "<h2>Firmware update</h2>",
    "</div></header><div class=\"card-body",
    " upload-file\"><label class=\"upload-file-select\"><span class=\"file-text\">Select firmware file</span><input type=\"file\" /></label>"
    "<button class=\"outline upload-submit\">Upload</button></div><footer class=\"card-bottom\"><span>Current firmware version: </span><span class=\"fwver-text\"></span></footer>",
    "\">",
    "</article></div></main></html>\r\n",
};

static esp_err_t http_resp_file_html_handler(httpd_req_t *req, const char *name, char * buf, size_t blen) {
    ILOG(TAG, "[%s]", __func__);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req, html_handler_str[0]);
    httpd_resp_sendstr_chunk(req, name);
    httpd_resp_sendstr_chunk(req, html_handler_str[1]);
    httpd_resp_sendstr_chunk(req, name);
    httpd_resp_sendstr_chunk(req, html_handler_str[2]);
    if(!strcmp(name, "home")){ 
        httpd_resp_sendstr_chunk(req, html_handler_str[3]);
    }
    else if(!strcmp(name,  "files")) {
        httpd_resp_sendstr_chunk(req, html_handler_str[4]);
    }
    else if(!strcmp(name, "config")) {
         httpd_resp_sendstr_chunk(req, "<h2>Configuration</h2>");
    }
    else if(!strcmp(name, "fwupdate")) {
         httpd_resp_sendstr_chunk(req, "<h2>Firmware update</h2>");
    }
    httpd_resp_sendstr_chunk(req, html_handler_str[7]);
    if(!strcmp(name,"fwupdate")) {
        httpd_resp_sendstr_chunk(req, html_handler_str[8]);
    } else {
        httpd_resp_sendstr_chunk(req, "\">");
        if(!strcmp(name, "home")){
            system_info_get_handler(req, 2, buf, blen);
        } else {
            httpd_resp_sendstr_chunk(req, html_handler_str[3]); // logo
        }
        httpd_resp_sendstr_chunk(req, "</div>");
    }
    httpd_resp_sendstr_chunk(req, html_handler_str[10]);
    return ESP_OK;
}

static esp_err_t css_get_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s]", __func__);
    extern const unsigned char index_css_start[] asm("_binary_index_css_gz_start");
    extern const unsigned char index_css_end[]   asm("_binary_index_css_gz_end");
    const size_t index_css_size = (index_css_end - index_css_start);
    if(!index_css_size) {
        WLOG(TAG, "[%s] embed index_css not found", __func__);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/css");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (const char *)index_css_start, index_css_size);
    return ESP_OK;
}

static esp_err_t js_get_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s]", __func__);
    extern const unsigned char index_js_start[] asm("_binary_index_js_gz_start");
    extern const unsigned char index_js_end[]   asm("_binary_index_js_gz_end");
    const size_t index_js_size = (index_js_end - index_js_start);
    if(!index_js_size) {
        WLOG(TAG, "[%s] embed index_js not found", __func__);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (const char *)index_js_start, index_js_size);
    return ESP_OK;
}

static esp_err_t logo_get_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s]", __func__);
    extern const unsigned char logo_svg_start[] asm("_binary_logo_svg_gz_start");
    extern const unsigned char logo_svg_end[]   asm("_binary_logo_svg_gz_end");
    const size_t logo_svg_size = (logo_svg_end - logo_svg_start);
    if(!logo_svg_size) {
        WLOG(TAG, "[%s] embed logo_svg not found", __func__);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "image/svg+xml");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (const char *)logo_svg_start, logo_svg_size);
    return ESP_OK;
}

static esp_err_t try_local_file(httpd_req_t *req, size_t ulen, const char *name, char * buf, size_t blen) {
    ILOG(TAG, "[%s]", __func__);
    char tmp[16] = {0};
    const char *p;
    size_t tlen = 0;
    if(!ulen) goto index;
    if(*(p = req->uri) == '/') {
        while(++p && *p &&*p != '/' && *p != '.');
        if(p && *p == '.' && p-req->uri < 16) {
            tlen = p-req->uri-1;
            memcpy(tmp, req->uri+1, tlen);
            tmp[tlen] = 0;
        }
    }
    // WLOG(TAG, "[%s] found file name %s ext %s or not.", __func__, &tmp[0], p ? p : "-");
    if((*req->uri == '/' && ulen == 1) || (tmp[0] && !strcmp(p, ".html"))) {
        index:
        if((!tmp[0] || !strcmp(tmp, "index")) && !http_resp_file_html_handler(req, "home", buf, blen)) {
            goto finishing;
        }
        else if((!strcmp(tmp, "files") || !strcmp(tmp, "config") || !strcmp(tmp, "fwupdate")) && !http_resp_file_html_handler(req, &tmp[0], buf, blen)) {
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
    return ESP_FAIL;
    finishing:
    return ESP_OK;
}

/* Send HTTP response with the contents of the requested file */
esp_err_t rest_async_get_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
#if (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 1)
    if (is_on_async_worker_thread() == false) {
        // submit
        if (submit_async_req(req, rest_async_get_handler) == ESP_OK) {
            ILOG(TAG, "[%s] submitted", __func__);
            return ESP_OK;
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, "503 Busy");
            httpd_resp_sendstr(
                req, "{\"error\":\"no workers available. server busy.\"}\n");
            return ESP_OK;
        }
    }
#endif
    char filepath[VFS_FILE_PATH_MAX] = {0};
    char strbuf[SCRATCH_BUFSIZE] = {0};
    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context);
    // int resp = (int)rest_context->request_no;
    //  char *resp_str = 0;
    strbf_t buf;
    strbf_init(&buf);
    strbf_t pathbuf;
    strbf_inits(&pathbuf, filepath, VFS_FILE_PATH_MAX);
    size_t ulen = strlen(req->uri), tlen = 0;
    struct stat sb = {0};
    int statok = 0, fd = 0;
    const char *p = 0;
    uint8_t del_flag = 0, archive_flag = 0;
    char *data = 0;
    int err = 0;
    uint8_t base_path_needed = 0;
    if(try_local_file(req, ulen, 0, strbuf, SCRATCH_BUFSIZE) == ESP_OK) {
        goto finishing;
    }
    else if (strstr(req->uri, "/api/v1/") == req->uri) {
        tlen = 8;
        esp_err_t err = httpd_resp_set_hdr(req, http_async_handler_strings[4], "*");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
        }
        if (!strcmp(&(req->uri[tlen]), "files")) {
            esp_err_t err = httpd_resp_set_hdr(req, http_async_handler_strings[5], "GET, DELETE, POST");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
            }
        } else if (!strcmp(&(req->uri[tlen]), "config")) {
            esp_err_t err = httpd_resp_set_hdr(req, http_async_handler_strings[5], "GET, POST, OPTIONS, PATCH");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
            }
        }
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "%s", http_async_handler_status_strings[3]);
        }
    }
    if (req->method == HTTP_HEAD || req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, HTTPD_200);
        goto finishing;
    }
    if(strstr(req->uri, "/api/v1/") == req->uri) {
        const char *uri = req->uri + 8;
        if (strstr(uri, "config") == uri) {
            tlen = 14;
            p = req->uri + tlen;
            const char *r = 0;
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
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            config_handler_json(req, &buf, r, &strbuf[0], SCRATCH_BUFSIZE);
        } else if(strstr(uri, "paths") == uri) {
            paths_handler(req, 1, &strbuf[0], SCRATCH_BUFSIZE);
            goto finishing;
        } else if (strstr(uri, "login") == uri) {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, HTTPD_200);
            http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, "{\"user\":\"admin\",\"logged\":\"no\"}\n", 31);
        } else if (strstr(uri, "fw/version") == uri) {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, HTTPD_200);
            strbf_puts(&buf,"{\"version\":\"");
            strbf_puts(&buf, m_context.SW_version);
            strbf_puts(&buf, "\"}");
            http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, buf.start, buf.cur-buf.start);
        } else if (strstr(uri, "system/info") == uri) {
            system_info_get_handler(req, 0, &strbuf[0], SCRATCH_BUFSIZE);
            goto finishing;
        } else if (strstr(uri, "system/bat") == uri) {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            system_bat_get_handler(req);
            goto finishing;
        } else if (strstr(uri, "system/restart") == uri) {
            httpd_resp_set_status(req, HTTPD_200);
            http_send_json_msg(req, "restart pending.", 16, 0, 0, 0);
            m_context.request_restart = 1;
            goto finishing;
        } else if (strstr(uri, "files") == uri) {
            tlen = 13;
        process_file:
            p = req->uri + tlen;
            if(*(req->uri + tlen) == '.') { // static files.html
                p = req->uri;
            }
            if(base_path_needed) {
                strbf_shape(&pathbuf, 0);
                if(base_path_needed == 1 && *(req->uri + tlen) == '.') { // static files.html
                    strbf_puts(&pathbuf, rest_context->base_path);
                } else {
                    strbf_puts(&pathbuf, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
                }
                *pathbuf.cur = 0;
            }
            const char *r = p;
            if (ulen > tlen && *p == '/') {
                r = req->uri + ulen - 1;
                while (r >= p && r && *r != '/')
                    --r;
                if (r > p && r && *r == '/') {
                    if (!strcmp(r + 1, "delete"))
                        del_flag = 1;
                    else if (!strcmp(r + 1, "archive"))
                        archive_flag = 1;
                }
            }
            if (!del_flag && !archive_flag) {
                r=p;
                while (r && *r) ++r;
                if((pathbuf.cur>pathbuf.start && *(pathbuf.cur-1)!='/') && *p != '/') strbf_putc(&pathbuf, '/');
                s_uri_decode(pathbuf.cur, p, r - p);
                //strbf_put_path_n(&pathbuf, p, r - p);
            } else if (r > p) {
                if((pathbuf.cur>pathbuf.start && *(pathbuf.cur-1)!='/') && *p != '/') strbf_putc(&pathbuf, '/');
                s_uri_decode(pathbuf.cur, p, r - p);
                //strbf_put_path_n(&pathbuf, p, r - p);
            }
            while(pathbuf.cur && *pathbuf.cur) ++pathbuf.cur;
            *pathbuf.cur = 0;
            ILOG(TAG, "[%s] filepath:%s p:%s r:%s len:%d", __FUNCTION__, filepath, p, r, r-p);
            statok = stat(strbf_finish(&pathbuf), &sb);
            if (statok == 0) {
                if (S_ISDIR(sb.st_mode)) {
                    if (tlen < 13)
                        goto get_index;
                    //httpd_resp_set_type(req, HTTPD_TYPE_JSON);
                    directory_handler(req, filepath, 0, 1, &strbuf[0], SCRATCH_BUFSIZE);
                    
                } else {
                    if (del_flag || archive_flag)
                        goto manage_file;
                    else
                        goto get_file;  // file
                }
            } else if(base_path_needed<2) {
                ++base_path_needed;
                goto process_file;
            } else {
                httpd_resp_set_type(req, HTTPD_TYPE_JSON);
                httpd_resp_set_status(req, HTTPD_404);
                http_send_json_msg(req, "File not found", 14, 1, 0, 0);
            }

        }
        else {
            httpd_resp_set_status(req, HTTPD_404);
            http_send_json_msg(req, "None", 4, 1, 0, 0);
        }
    }
    else if (strstr(req->uri, "/files") == req->uri) {
        tlen = 6;
        goto process_file;
    } 
    else { // get file from base path
        DLOG(TAG, "Going to open file base: %s, uri: %s", rest_context->base_path, req->uri);
        if ((ulen == 1 && *req->uri == '/') || strstr(req->uri, "/index.html") == req->uri) {
            goto get_index;
        }
        strbf_puts(&pathbuf, rest_context->base_path);
        strbf_put_path(&pathbuf, req->uri);
        strbf_finish(&pathbuf);
        DLOG(TAG, "1. oopen file : %s", pathbuf.start);
        statok = stat(pathbuf.start, &sb);
    get_file:
        fd = open(&(filepath[0]), O_RDONLY, 0);
        if (fd < 0 && strcmp(rest_context->base_path, &base_path[0])) {
            if ((ulen == 1 && *req->uri == '/') || strstr(req->uri, "/index.html") == req->uri) {
                goto get_index;
            }
            strbf_shape(&pathbuf, 0);
            strbf_puts(&pathbuf, &base_path[0]);
            strbf_put_path(&pathbuf, req->uri);
            strbf_finish(&pathbuf);
            DLOG(TAG, "2. oopen file : %s", pathbuf.start);
            statok = stat(pathbuf.start, &sb);
            fd = open(pathbuf.start, O_RDONLY, 0);
        }
        if (fd < 0) {
        get_index:
            strbf_shape(&pathbuf, 0);
            strbf_puts(&pathbuf, rest_context->base_path);
            strbf_put_path(&pathbuf, "/index.html");
            strbf_finish(&pathbuf);
            DLOG(TAG, "send index.html : %s", pathbuf.start);
            statok = stat(pathbuf.start, &sb);
            fd = open(pathbuf.start, O_RDONLY, 0);
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
                DLOG(TAG, "send index 0 : %s, %d, %s, %d", data, read_bytes, hostname, hl);
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
                    DLOG(TAG, "send index 1 : %s, %d", data, bl);
                    httpd_resp_send_chunk(req, data, bl);
                    goto finishing;
                } else {
                    ESP_LOGE(TAG, "send index failed.");
                }
            }
            if (fd < 0) {
                ESP_LOGE(TAG, "Failed to open : %s, error:'%s'", filepath, strerror(errno));
                httpd_resp_set_status(req, HTTPD_404);
                http_send_json_msg(req, "Failed to open", 14, 1, 0, 0);
                return ESP_FAIL;
            }
        }
        if (fd) {
            set_content_type_from_file(req, pathbuf.start, pathbuf.cur - pathbuf.start);
            err = send_file(req, fd, !statok && S_ISREG(sb.st_mode) ? sb.st_size : 0, strbuf, SCRATCH_BUFSIZE);
            if (fd<0 || close(fd)) {
                ESP_LOGE(TAG, "Failed to close (%s)", strerror(errno));
            }
            // ESP_LOGI(TAG, "File sending complete");
        }
    }
    if (del_flag || archive_flag) {

    manage_file:
        p = del_flag ? "unlink" : "archive";
        DLOG(TAG, "Going to %s file: %s, uri: %s", p, pathbuf.start, req->uri);
        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        
        if (archive_flag)
            err = archive_file(req, pathbuf.start, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point); // was &base_path[0]
        else
            err = unlink(pathbuf.start);


        if (err) {
            ESP_LOGE(TAG, "Failed to %s file : %s", p, filepath);
            httpd_resp_set_status(req, HTTPD_400);
        } else {
            httpd_resp_set_status(req, HTTPD_200);
        }
        strbf_puts(&buf, "{\"name\":\"");
        strbf_put(&buf, pathbuf.start, pathbuf.cur - pathbuf.start);
        strbf_puts(&buf, "\",\"cmd\":\"");
        strbf_puts(&buf, p);
        strbf_puts(&buf, "\"}");
        if(err)
            http_send_json_msg(req, "Failed", 6, 1, buf.start, buf.cur - buf.start);
        else
            http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, buf.start, buf.cur - buf.start);
    }
finishing:
    httpd_resp_send_chunk(req, NULL, 0);
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
    memory_info_large("asyncHandlerGet");
#endif
    if (data)
        free(data);
    strbf_free(&buf);
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
    return unlink(fname);
}

static esp_err_t archive_file_cb(httpd_req_t *req, const char *fname) {
    ILOG(TAG, "[%s] %s", __func__, fname);
    return archive_file(req, fname, vfs_ctx.parts[vfs_ctx.gps_log_part].mount_point);
}

static esp_err_t bulk_manage_files(httpd_req_t *req, char *fname, size_t flen, strbf_t *data, manage_file_cb_t cb, const char * action_name) {
    assert(data);
    ILOG(TAG, "[%s] %s %s", __func__, data->start, action_name ? action_name : "null");
    char * p = 0, *r = 0, *e = 0;
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
                return http_send_json_msg(req, "No data.", 8, 1, 0, 0);
            }
        }
        else p = data->start;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 1)
        printf("data: %s\n", p);
#endif
        while(p && (!e || p<e)) {
            if(fbuf.cur-fbuf.start>len) strbf_shape(&fbuf, len);
            r = strchr(p, '|');
            if(!r) r = strchr(p, ',');
            if((!r && e) || (r && e && r > e) ) r = e;
            if(*(fbuf.cur-1)!='/' && *p != '/') strbf_putc(&fbuf, '/');
            if(r) {
                if(((fbuf.cur-fbuf.start) + (r-p) + 1) >= flen){
                    return http_send_json_msg(req, "Filename too long.", 18, 2, 0, 0);
                }
                s_uri_decode(fbuf.cur, p, r - p);
                // strbf_put_path_n(&fbuf, p, r-p);
            } else {
                s_uri_decode(fbuf.cur, p, e - p);
                // strbf_put_path(&fbuf, p);
            }
            while(fbuf.cur && *fbuf.cur) ++fbuf.cur;
            *fbuf.cur = 0;
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2)
            printf("%s file: %s\n", action_name, fbuf.start);
#endif
            if (!cb || cb(req, strbf_finish(&fbuf))) {
                return http_send_json_msg(req, "Failed", 6, 3, 0, 0);
            }
            p=r;
            if(p && (*p=='|' || *p == ',')) ++p;
        }
    } else {
        return http_send_json_msg(req, "No data.", 8, 1, 0, 0);
    }
    return http_send_json_msg(req, action_name, strlen(action_name), 0, 0, 0);
}

/* A long running HTTP GET handler */
esp_err_t post_async_handler(httpd_req_t *req) {
    ILOG(TAG, "[%s] %s", __func__, req->uri);
#if (CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS > 1)
    if (is_on_async_worker_thread() == false) {
        // submit
        if (submit_async_req(req, post_async_handler) == ESP_OK) {
            ILOG(TAG, "[%s] submitted", __func__);
            return ESP_OK;
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, HTTPD_500);
            httpd_resp_sendstr(req, "{\"error\":\"no workers available. server busy.\"}\n");
            return ESP_OK;
        }
    }
#endif
    struct mpart_s parts[4];
    memset(parts, 0, sizeof(parts));
    const char *mpb = 0, *mpb0 = 0;  //, *mpb1 = 0;
    char prev[12] = {0};
    uint16_t buflen = SCRATCH_BUFSIZE, fnamelen = 0, boundarylen = 0;
    char *buf = malloc(buflen);
    char *boundary = malloc(80);
    char fname[64]={0};
    int fp = -1;
    bool mpart_open = false;
    uint8_t u_mode = strstr(req->uri, "/api/v1/fw/update") == req->uri ? 1 : 0;
    httpd_req_get_hdr_value_str(req, "Content-Type", buf, buflen);
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
#if CONFIG_LOGGER_HTTP_LOG_LEVEL < 2
            printf("boundary found '%s' size '%" PRIu16 "'\n", boundary, boundarylen);
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
    if (req->method == HTTP_POST) {
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
                    DLOG(TAG, "[%s] all data recieved bl:%" PRIu16 " rc:%d tl:%d", __FUNCTION__, buflen, recieved, total_len);
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
                    DLOG(TAG, "[%s] found multipart file begin, fname: '%s' len: '%d'", __FUNCTION__, fname, fnamelen);
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
                        printf("[%s] open path: %s name: %s\n", __FUNCTION__, pbuf.start, fname);
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
                DLOG(TAG, "[%s] got buffered data '%s' ", __FUNCTION__, buf);
                if(l+recieved >= buflen) {
                    ESP_LOGE(TAG, "Buffer overflow.");
                    goto toerr;
                }
                strbf_put(&data, buf, recieved);
                
            }
            l += recieved;
#if CONFIG_LOGGER_HTTP_LOG_LEVEL < 1
            printf("[%s] recieved: %d, total: %d, l: %lu\n", __FUNCTION__, recieved, total_len, l);
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
            } else {
                if (fp > 0) {
#if CONFIG_LOGGER_HTTP_LOG_LEVEL < 1
                    printf("Close file being saved to %s\n", fname);
#endif
                    close(fp);
                } else
                    goto toerr;
            }
        }
        ESP_LOGI(TAG, "Post request saved %lu bytes.", l);
    }
    if (!is_multipart) {
        if (!data.start || data.cur == data.start) {
            goto toerr;
        }
        ESP_LOGI(TAG, "got post request : '%s'", data.start);
    }

    /* rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context); */

    if (strstr(req->uri, "/api/v1/") == req->uri) {
        tlen = 8;
        err = httpd_resp_set_hdr(req, http_async_handler_strings[4], "*");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send header.");
        }
    }

    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    if (strstr(req->uri, "/api/v1/files/delete") == req->uri) {
        if(bulk_manage_files(req, fname, 64, &data, delete_file_cb, "delete") != 0) {
            ESP_LOGE(TAG, "[%s] delete failed.", __FUNCTION__);
        }
        goto done;
    }
    if (strstr(req->uri, "/api/v1/files/archive") == req->uri) {
        if(bulk_manage_files(req, fname, 64, &data, archive_file_cb, "archive") != 0) {
            ESP_LOGE(TAG, "[%s] archive failed.", __FUNCTION__);
        }
        goto done;
    }
    else if (strstr(req->uri, "/api/v1/files/upload") == req->uri) {
        http_send_json_msg(req, "uploaded.", 9, 0, 0, 0);
        // httpd_resp_send_chunk(req, "{\"status\": \"OK\",\"msg\":\"uploaded.\"\n}", 43);
        goto done;
    } else if (strstr(req->uri, "/api/v1/fw/update") == req->uri) {
        tlen = 17;
        http_send_json_msg(req, "Firmware updated.", 17, 0, 0, 0);
        // httpd_resp_send_chunk(req, "{\"status\": \"OK\",\"msg\":\"Firmware updated.\"\n}", 43);
        goto done;
    } else if (strstr(req->uri, "/api/v1/config") == req->uri) {
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
        //httpd_resp_send_chunk(req, "{\"status\": \"Failed\",\"msg\":\"Could not finish.\"}", 46);
    } else
        http_send_json_msg(req, "Post data successfully", 22, 0, 0, 0);
        // httpd_resp_send_chunk(req, "{\"status\": \"OK\",\"msg\":\"Post data successfully\n}", 47);
done:
    httpd_resp_send_chunk(req, NULL, 0);
    if (ota_result.status == ESP_OK && ota_result.callback)
        ota_result.callback();  // will request restart
#if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
    task_memory_info(__func__);
#endif
    strbf_free(&data);
    free(buf);
    free(boundary);

    return err;
}

#undef FIND_B
#undef GOMP_S

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
        }
        // if(loops++ > 100) {
        //     loops = 0;
        // }
        // if(loops == 0) {
    #if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
            task_memory_info(__func__);
    #endif
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
 #if (CONFIG_LOGGER_HTTP_LOG_LEVEL < 2 || defined(DEBUG))
            task_memory_info(__func__);
#endif
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