
#include <errno.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_system.h>
#include "cJSON.h"
#include "esp_chip_info.h"

#include "http_async_handler.h"
#include "http_rest_server.h"
#include "logger_config.h"
#include "logger_common.h"
#include "context.h"
#include "ota.h"
#include "str.h"
#include "strbf.h"
#include "vfs.h"
#include "adc.h"
#include "wifi.h"
#include "ubx.h"

#define ASYNC_WORKER_TASK_PRIORITY 5
#define ASYNC_WORKER_TASK_STACK_SIZE 1024 * 3

//#define CONFIG_MAX_ASYNC_REQUESTS 1

static const char *TAG = "asynchandler";

extern struct context_s m_context;
extern struct context_rtc_s m_context_rtc;
extern struct m_wifi_context wifi_context;

// Async reqeusts are queued here while they wait to
// be processed by the workers
static QueueHandle_t async_req_queue;

// Track the number of free workers at any given time
static SemaphoreHandle_t worker_ready_count;

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
            return true;
        }
    }
    return false;
}

// Submit an HTTP req to the async worker queue
static esp_err_t submit_async_req(httpd_req_t *req, httpd_req_handler_t handler) {
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
};

static const char *http_async_handler_strings[] = {
    "{\"status\":\"",
    "\",\"msg\":\"",
    ",\"data\":",
    "}\n",
};

static void http_send_json_msg(httpd_req_t *req, const char *msg, int msg_size, int status, char * data, int data_size) {
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
}

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(void *_req, const char *filepath,
                                     size_t pathlen) {
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
    ESP_LOGI(TAG, "[%s] done file: %s, type: %s", __FUNCTION__, filepath, type);
    return httpd_resp_set_type(req, type);
}

static esp_err_t archive_file(httpd_req_t *req, const char *filename, const char *base) {
    int ret = ESP_OK;
    strbf_t sb;
    char tmp[PATH_MAX_CHAR_SIZE];
    strbf_inits(&sb, tmp, PATH_MAX_CHAR_SIZE);
    strbf_put_path(&sb, base);
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
    ESP_LOGI(TAG, "Move to arcive %s => %s", filename, sb.start);
    ret = s_rename_file_n(filename, sb.start, 0);
    return ret;
}

static esp_err_t send_file(httpd_req_t *req, int fd, uint32_t len) {
    if (fd <= 0) {
        return ESP_FAIL;
    }
    size_t chunk_size = SCRATCH_BUFSIZE;
    char chunk[chunk_size], tmp[8] = {0};
    if (len) {
        xultoa(len, &(tmp[0]));
        esp_err_t err = httpd_resp_set_hdr(req, "Content-Length", tmp);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send header.");
        } else
            ESP_LOGI(TAG, "[%s] content length set as %s bytes", __FUNCTION__, tmp);
    }
    int32_t read_bytes, i = len;
    do {
        read_bytes = read(fd, chunk, chunk_size);
        if (read_bytes == -1) {
            ESP_LOGE(TAG, "Failed to read file.");
        } else if (read_bytes > 0) {
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK) {
                // close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                // httpd_resp_sendstr_chunk(req, NULL);
                httpd_resp_set_status(req, HTTPD_500);
                http_send_json_msg(req, "Failed to send file", 19, 1, 0, 0);
                return ESP_FAIL;
            }
        }
        i -= read_bytes;
    } while (read_bytes > 0);
    // send complete
    // httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t config_handler_json(httpd_req_t *req, strbf_t *sb, const char *str) {
    //ESP_LOGI(TAG, "[%s] %s, config: '%s' method(%d)", __FUNCTION__, req->uri, str ? str : "null", req->method);
    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    // config_get_json(m_context.config, sb, str, g_context_get_ubx_hw(&m_context));
    logger_config_t *config = m_context.config;
    uint8_t ublox_hw = g_context_get_ubx_hw(&m_context);
    size_t blen = SCRATCH_BUFSIZE, flush_size = blen, len = 0;
    char buf[blen], *p = 0;
#define CONF_GETC(a)                                    \
    p = config_get(config, a, buf, &len, blen, 1, ublox_hw); \
    if (len) {                                          \
        strbf_puts(sb, p);                               \
    }
#define CONF_GET(a, i) \
    p = config_get(config, a, buf, &len, blen, 1, ublox_hw); \
    if (len) {                                            \
        if(i>0) strbf_putc(sb, ',');                              \
        strbf_puts(sb, p);                               \
    }

    if (str) {
        CONF_GETC(str);
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

        const char *startPtr = config_item_names;
        const char *endPtr;
        int i = 0;
        // Use strtok to iterate over the comma-separated values
        while ((endPtr = strchr(startPtr, ',')) != NULL) {
            int tokenLength = endPtr - startPtr;
            if (tokenLength > 0) {
                char tempBuffer[tokenLength + 1];
                memcpy(tempBuffer, startPtr, tokenLength);
                tempBuffer[tokenLength] = '\0';
                CONF_GET(tempBuffer, i);
                if(sb->cur - sb->start >= flush_size) {
                    httpd_resp_send_chunk(req, sb->start, sb->cur - sb->start);
                    strbf_shape(sb, 0);
                }
            }
            startPtr = endPtr + 1; 
            ++i;
        }
        // Handle the last token (or the only one if no commas were found)
        if (*startPtr) { // Check if there's anything left
            CONF_GET(startPtr, i); // Directly use startPtr as it's already null-terminated
            if (sb->cur - sb->start >= flush_size) {
                httpd_resp_send_chunk(req, sb->start, sb->cur - sb->start);
                strbf_shape(sb, 0);
            }
        }
        strbf_puts(sb, "]\n");
    }
#undef CONF_GETC
#undef CONF_GET
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
    cJSON *root = cJSON_CreateObject();
#ifdef USE_CUSTOM_CALIBRATION_VAL
    cJSON_AddNumberToObject(root, "battery", volt_read(m_context_rtc.RTC_calibration_bat));
#else
    cJSON_AddNumberToObject(root, "battery", volt_read());
#endif
    const char *sys_info = cJSON_Print(root);
    httpd_resp_sendstr(req, sys_info);
    free((void *)sys_info);
    cJSON_Delete(root);
    return ESP_OK;
}

/* Simple handler for getting system handler */
static esp_err_t system_info_get_handler(httpd_req_t *req) {
    char buf[16] = {0};
    size_t len = 0;
    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    httpd_resp_send_chunk(req, "{\"version\":\"", 12);
    httpd_resp_send_chunk(req, IDF_VER, strlen(IDF_VER));
    httpd_resp_send_chunk(req, "\",\"cores\":", 10);
    len = xltoa(chip_info.cores, buf);
    httpd_resp_send_chunk(req, buf, len);
    httpd_resp_send_chunk(req, ",\"model\":\"", 10);
    httpd_resp_send_chunk(req, chip_info.model == 1 ? "esp32" : "esp32s2", chip_info.model == 1 ? 5 : 7);
    httpd_resp_send_chunk(req, "\",\"revision\":", 13);
    len = xltoa(chip_info.revision, buf);
    httpd_resp_send_chunk(req, buf, len);
    httpd_resp_send_chunk(req, ",\"fwversion\":\"", 14);
    httpd_resp_send_chunk(req, m_context.SW_version, strlen(m_context.SW_version));
    httpd_resp_send_chunk(req, "\",\"ipaddress\":\"", 15);
    httpd_resp_send_chunk(req, wifi_context.ip_address, strlen(wifi_context.ip_address));
    httpd_resp_send_chunk(req, "\",\"freeheap\":", 13);
    len = xltoa(esp_get_free_heap_size(), buf);
    httpd_resp_send_chunk(req, buf, len);
    httpd_resp_send_chunk(req, ",\"minfreeheap\":", 15);
    len = xltoa(esp_get_minimum_free_heap_size(), buf);
    httpd_resp_send_chunk(req, buf, len);
    httpd_resp_send_chunk(req, ",\"battery\":", 11);
    len = f3_to_char(volt_read(), buf);
    httpd_resp_send_chunk(req, buf, len);
    httpd_resp_send_chunk(req, http_async_handler_strings[3], 2); // }\n
    httpd_resp_send_chunk(req, 0, 0);
    return ESP_OK;
}

static esp_err_t directory_handler(httpd_req_t *req, const char *path, const char *match, uint8_t mode) {
    DIR *dir = NULL;
    struct dirent *ent;
    char type;
    char size[16];
    char tpath[FILE_PATH_MAX];
    char tbuffer[92];
    struct stat sb;
    struct tm *tm_info;
    char *lpath = NULL;
    int statok;

    httpd_resp_set_type(req, mode==1 ? HTTPD_TYPE_JSON : HTTPD_TYPE_TEXT);
    
    // Open directory
    dir = opendir(path);
    if (!dir) {
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
    strbf_t buf, fbuf;
    strbf_inits(&fbuf, tpath, FILE_PATH_MAX);
    strbf_puts(&fbuf, path);
    size_t len = fbuf.cur - fbuf.start;
    strbf_init(&buf);
    size_t flush_size = SCRATCH_BUFSIZE;

    size_t i = 0;
    if(mode==1) 
        httpd_resp_send_chunk(req, "[", 1);
    else {
        httpd_resp_send_chunk(req, "T  Size      Date/Time         Name\n-----------------------------------\n", 72);
    }

    while ((ent = readdir(dir)) != NULL) {
        strbf_shape(&fbuf, len);
        strbf_put_path(&fbuf, ent->d_name);
        tbuffer[0] = '\0';
        if ((match == NULL) || (fnmatch(match, &(tpath[0]), (FNM_PERIOD)) == 0)) {
            // Get file stat
            statok = stat(&(tpath[0]), &sb);
            if(mode==1){
                if(!nitems)
                    strbf_putc(&buf, '{');
                else
                    strbf_puts(&buf, ",{");
            }
            if (statok == 0) {
                tm_info = localtime(&sb.st_mtime);
                strftime(tbuffer, 92, "%Y-%m-%d %R", tm_info);
            }
            else if(mode==0) { // text
                strbf_puts(&buf, "                ");
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
                    total += sb.st_size;
                    if (sb.st_size < (1024 * 1024))
                        sprintf(size, "%8d", (int)sb.st_size);
                    else if ((sb.st_size / 1024) < (1024 * 1024))
                        sprintf(size, "%6dKB", (int)(sb.st_size / 1024));
                    else
                        sprintf(size, "%6dMB", (int)(sb.st_size / (1024 * 1024)));
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
                strbf_puts(&buf, "\"name\":\"");
            strbf_puts(&buf, ent->d_name);
            if(mode==1)
                strbf_puts(&buf, "\",\"date\":\"");
            else
                strbf_puts(&buf, " ");
            if (!statok)
                strbf_puts(&buf, tbuffer);
            if(mode==1)
                strbf_puts(&buf, "\",\"size\":\"");
            else
                strbf_puts(&buf, " ");
            if (!statok && ent->d_type == DT_REG)
                strbf_putul(&buf, (int)sb.st_size);
            if(mode==1)
                strbf_puts(&buf, "\",\"type\":\"");
            else
                strbf_puts(&buf, " ");
            strbf_putc(&buf, type);
            if(mode==1)
                strbf_puts(&buf, "\",\"mode\":\"");
            else
                strbf_puts(&buf, " ");
            if (strstr(ent->d_name, "config")) {
                strbf_puts(&buf, "r");
            } else
                strbf_puts(&buf, "rw");
            if(mode==1)
                strbf_puts(&buf, "\"}");
            else
                strbf_puts(&buf, "\n");
            *buf.cur=0;
            i+=buf.cur - buf.start;
            if(buf.cur - buf.start > flush_size) {
                httpd_resp_send_chunk(req, buf.start, buf.cur - buf.start);
                strbf_shape(&buf, 0);
                ESP_LOGI(TAG, "[%s] Flush at %lu files, %lu items, %llu bytes, %u bytes sent.", __FUNCTION__, nfiles, nitems, total, i);
            }
        }
    }
    strbf_puts(&buf, mode==1 ? "]" : "\n");
    if(buf.cur > buf.start) {
        httpd_resp_send_chunk(req, buf.start, buf.cur - buf.start);
    }
    closedir(dir);
    ESP_LOGI(TAG, "[%s] Total %lu files, %lu items, %llu bytes, %u bytes sent.", __FUNCTION__, nfiles, nitems, total, i);

    free(lpath);
    return ESP_OK;
}

/* Send HTTP response with the contents of the requested file */
esp_err_t rest_async_get_handler(httpd_req_t *req) {
    /* if (is_on_async_worker_thread() == false) {
        // submit
        if (submit_async_req(req, rest_async_get_handler) == ESP_OK) {
            return ESP_OK;
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, "503 Busy");
            httpd_resp_sendstr(
                req, "{\"error\":\"no workers available. server busy.\"}\n");
            return ESP_OK;
        }
    } */
    char filepath[FILE_PATH_MAX];
    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context);
    // int resp = (int)rest_context->request_no;
    //  char *resp_str = 0;
    strbf_t buf;
    strbf_init(&buf);
    strbf_t fbuf;
    strbf_inits(&fbuf, filepath, FILE_PATH_MAX);
    size_t ulen = strlen(req->uri), tlen = 0;
    struct stat sb = {0};
    int statok, fd = 0;
    const char *p = 0;
    uint8_t del_flag = 0, archive_flag = 0;
    char *data = 0;
    if (strstr(req->uri, "/api/v1/") == req->uri) {
        tlen = 8;
        esp_err_t err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send header.");
        }
        if (!strcmp(&(req->uri[tlen]), "files")) {
            esp_err_t err = httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, DELETE, POST");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to send header.");
            }
        } else if (!strcmp(&(req->uri[tlen]), "config")) {
            esp_err_t err = httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS, PATCH");
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to send header.");
            }
        }
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send header.");
        }
    }
    if (req->method == HTTP_HEAD || req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, HTTPD_200);
        goto finishing;
    }

    if (strstr(req->uri, "/api/v1/config") == req->uri) {
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
        config_handler_json(req, &buf, r);
    } else if (strstr(req->uri, "/api/v1/login") == req->uri) {
        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        httpd_resp_set_status(req, HTTPD_200);
        http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, "{\"user\":\"admin\",\"logged\":\"no\"}\n", 31);
    } else if (strstr(req->uri, "/api/v1/fw/version") == req->uri) {
        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        httpd_resp_set_status(req, HTTPD_200);
        strbf_puts(&buf,"{\"version\":\"");
        strbf_puts(&buf, m_context.SW_version);
        strbf_puts(&buf, "\"}");
        http_send_json_msg(req, http_async_handler_status_strings[2], 7, 0, buf.start, buf.cur-buf.start);
    } else if (strstr(req->uri, "/api/v1/system/info") == req->uri) {
        system_info_get_handler(req);
        goto finishing;
    } else if (strstr(req->uri, "/api/v1/system/bat") == req->uri) {
        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        system_bat_get_handler(req);
        goto finishing;
    } else if (strstr(req->uri, "/api/v1/system/restart") == req->uri) {
        httpd_resp_set_status(req, HTTPD_200);
        http_send_json_msg(req, "restart pending.", 16, 0, 0, 0);
        m_context.request_restart = 1;
        goto finishing;
    } else if (strstr(req->uri, "/files") == req->uri) {
        tlen = 6;
        goto process_file;
    } else if (strstr(req->uri, "/api/v1/files") == req->uri) {
        tlen = 13;
    process_file:
        p = req->uri + tlen;
        strbf_puts(&fbuf, CONFIG_SD_MOUNT_POINT);
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
            strbf_put_path(&fbuf, p);
        } else if (r > p) {
            strbf_put_path_n(&fbuf, p, r - p);
        }
        ESP_LOGI(TAG, "[%s] base directory: filepath: %s p: %s r: %s", __FUNCTION__, filepath, p, r);
        statok = stat(strbf_finish(&fbuf), &sb);
        if (statok == 0) {
            if (S_ISDIR(sb.st_mode)) {
                if (tlen < 13)
                    goto get_index;
                //httpd_resp_set_type(req, HTTPD_TYPE_JSON);
                directory_handler(req, filepath, 0, 1);
                
            } else {
                if (del_flag || archive_flag)
                    goto manage_file;
                else
                    goto get_file;  // file
            }
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, HTTPD_404);
            http_send_json_msg(req, "File not found", 14, 1, 0, 0);
        }

    } else {
        ESP_LOGI(TAG, "Going to open file base: %s, uri: %s", rest_context->base_path, req->uri);
        if ((ulen == 1 && *req->uri == '/') || strstr(req->uri, "/index.html") == req->uri) {
            goto get_index;
        }
        strbf_puts(&fbuf, rest_context->base_path);
        strbf_put_path(&fbuf, req->uri);

        ESP_LOGI(TAG, "1. oopen file : %s", strbf_finish(&fbuf));
        statok = stat(fbuf.start, &sb);
    get_file:
        fd = open(&(filepath[0]), O_RDONLY, 0);
        if (fd < 0 && strcmp(rest_context->base_path, CONFIG_SD_MOUNT_POINT)) {
            if ((ulen == 1 && *req->uri == '/') || strstr(req->uri, "/index.html") == req->uri) {
                goto get_index;
            }
            strbf_shape(&fbuf, 0);
            strbf_puts(&fbuf, CONFIG_SD_MOUNT_POINT);
            strbf_put_path(&fbuf, req->uri);

            ESP_LOGI(TAG, "2. oopen file : %s", strbf_finish(&fbuf));
            statok = stat(fbuf.start, &sb);
            fd = open(fbuf.start, O_RDONLY, 0);
        }
        if (fd < 0) {
        get_index:
            strbf_shape(&fbuf, 0);
            strbf_puts(&fbuf, rest_context->base_path);
            strbf_put_path(&fbuf, "/index.html");
            ESP_LOGI(TAG, "send index.html : %s", strbf_finish(&fbuf));
            statok = stat(fbuf.start, &sb);
            fd = open(fbuf.start, O_RDONLY, 0);
            if (fd) {
                char hostname[24] = {0};
                char tmp[8] = {0}, *be = 0;
                size_t bl = 0, hl = strlen(wifi_context.ip_address);
                memcpy(&(hostname[0]), "http://", 7);
                memcpy(&(hostname[7]), wifi_context.ip_address, hl);
                hostname[7 + hl] = '/';
                hostname[7 + hl + 1] = 0;
                hl = &(hostname[7 + hl + 1]) - &(hostname[0]);

                data = malloc(sb.st_size + hl);
                int read_bytes = read(fd, data, sb.st_size);
                *(data + sb.st_size) = 0;
                ESP_LOGI(TAG, "send index 0 : %s, %d, %s, %d", data, read_bytes, hostname, hl);
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
                    ESP_LOGI(TAG, "send index 1 : %s, %d", data, bl);
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
            set_content_type_from_file(req, fbuf.start, fbuf.cur - fbuf.start);
            send_file(req, fd, !statok && S_ISREG(sb.st_mode) ? sb.st_size : 0);
            if (close(fd)) {
                ESP_LOGE(TAG, "Failed to close (%s)", strerror(errno));
            }
            // ESP_LOGI(TAG, "File sending complete");
        }
    }
    if (del_flag || archive_flag) {
    manage_file:
        const char *p = del_flag ? "unlink" : "archive";
        ESP_LOGI(TAG, "Going to %s file: %s, uri: %s", p, fbuf.start, req->uri);
        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        int err = 0;
        if (archive_flag)
            err = archive_file(req, fbuf.start, CONFIG_SD_MOUNT_POINT);
        else
            err = unlink(fbuf.start);


        if (err) {
            ESP_LOGE(TAG, "Failed to %s file : %s", p, filepath);
            httpd_resp_set_status(req, HTTPD_400);
        } else {
            httpd_resp_set_status(req, HTTPD_200);
        }
        strbf_puts(&buf, "{\"name\":\"");
        strbf_put(&buf, fbuf.start, fbuf.cur - fbuf.start);
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
    task_memory_info("asyncHandlerGet");
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

/* A long running HTTP GET handler */
esp_err_t post_async_handler(httpd_req_t *req) {
    /* if (is_on_async_worker_thread() == false) {
        // submit
        if (submit_async_req(req, post_async_handler) == ESP_OK) {
            return ESP_OK;
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_JSON);
            httpd_resp_set_status(req, HTTPD_500);
            httpd_resp_sendstr(req, "{\"error\":\"no workers available. server busy.\"}\n");
            return ESP_OK;
        }
    } */
    struct mpart_s parts[4];
    memset(parts, 0, sizeof(parts));
    const char *mpb = 0, *mpb0 = 0;  //, *mpb1 = 0;
    char prev[12] = {0};
    uint16_t buflen = 4096, fnamelen = 0, boundarylen = 0;
    char *buf = malloc(buflen);
    char *boundary = malloc(80);
    char *fname = malloc(64);
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
            printf("boundary found '%s' size '%" PRIu16 "'\n", boundary, boundarylen);
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
        uint16_t l = 0;
        while (total_len > 0) {
            // Read the data for the request
            if ((recieved = httpd_req_recv(req, buf, MIN(total_len, buflen))) <= 0) {
                if (recieved == HTTPD_SOCK_ERR_TIMEOUT) {
                    // Retry receiving if timeout occurred
                    continue;
                }
                ESP_LOGE(TAG, "http recieve data error (%d)", recieved);
                return ESP_FAIL;
            }

            if (is_multipart) {
                parts[mpart_num].start_mark = buf;
                if (mpart_open) {
                    parts[mpart_num].end_mark = buf + recieved;
                } else {
                    parts[mpart_num].end_mark = 0;
                }
                if (recieved < buflen && recieved >= total_len) {
                    ESP_LOGI(TAG, "[%s] all data recieved bl:%" PRIu16 " rc:%d tl:%d", __FUNCTION__, buflen, recieved, total_len);
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
                    ESP_LOGI(TAG, "[%s] found multipart file begin, fname: '%s' len: '%d'", __FUNCTION__, fname, fnamelen);
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
                    if (!fname)  // no file name, no upload
                        goto toerr;
                    else if (fp < 0) {
                        fp = s_open(fname, CONFIG_SD_MOUNT_POINT, "w+");
                        if (fp < 0) {
                            fp = s_open(fname, CONFIG_SD_MOUNT_POINT, "w+");
                        }
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
                ESP_LOGI(TAG, "[%s] got buffered data '%s' ", __FUNCTION__, buf);
                strbf_put(&data, buf, recieved);
            }
            total_len -= recieved;
            memcpy(prev, buf + recieved - 11, 11);
            prev[11] = 0;
            ++l;
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
                    close(fp);
                } else
                    goto toerr;
            }
        }
        ESP_LOGI(TAG, "Post request saved.");
    }
    if (!is_multipart) {
        if (!data.start || data.cur == data.start) {
            goto toerr;
        }
        ESP_LOGI(TAG, "got post request : %s", data.start);
    }

    /* rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    assert(rest_context); */

    if (strstr(req->uri, "/api/v1/") == req->uri) {
        tlen = 8;
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send header.");
        }
    }

    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    if (strstr(req->uri, "/api/v1/files/upload") == req->uri) {
        tlen = 20;
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
        if (config_save_var(m_context.config, m_context.filename, m_context.filename_backup, data.start, 0, g_context_get_ubx_hw(&m_context)) > 0) {
            strbf_init(&respsb);
            config_get_json(m_context.config, &respsb, r, g_context_get_ubx_hw(&m_context));
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
    task_memory_info("asyncHandlerPost");
    strbf_free(&data);
    free(buf);
    free(boundary);
    free(fname);

    return err;
}

#undef FIND_B
#undef GOMP_S

static void async_req_worker_task(void *p) {
    uint16_t loops = 0;
    while (true) {
        // counting semaphore - this signals that a worker
        // is ready to accept work
        xSemaphoreGive(worker_ready_count);

        // wait for a request
        httpd_async_req_t async_req;
        if (xQueueReceive(async_req_queue, &async_req, portMAX_DELAY)) {
            httpd_req_t *req = async_req.req;
            ESP_LOGI(TAG, "invoking uri '%s'", req->uri);

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
            task_memory_info("asyncWorkerTask");
        // }
        delay_ms(50);
    }
}

void start_async_req_workers(void) {
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
        vSemaphoreDelete(worker_ready_count);
        return;
    }
    // start worker tasks
    for (int i = 0; i < worker_num; i++) {
        ESP_LOGI(TAG, "Starting asyncReqWorker %d", i);
        task_memory_info("asyncWorkerStart");
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
    if (worker_ready_count == NULL) {
        return;
    }
    for (int i = 0; i < worker_num; i++) {
        vTaskDelete(worker_handles[i]);
    }
    if (async_req_queue != NULL) {
        vQueueDelete(async_req_queue);
    }
}
