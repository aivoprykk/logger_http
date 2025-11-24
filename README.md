# Logger HTTP Component

A comprehensive HTTP server component for ESP32-based GPS logger applications, providing REST API, web interface, over-the-air updates, file management, and configuration capabilities.

## Features

### HTTP Server & Web Interface
- **REST API**: Full RESTful API for device control and data access
- **Web Dashboard**: Embedded web interface for configuration and monitoring
- **File Management**: Upload/download GPS logs and configuration files
- **Async Processing**: Asynchronous request handling for improved performance
- **mDNS Discovery**: Automatic service discovery on local networks

### Over-The-Air Updates
- **Firmware Updates**: Secure OTA firmware updates with rollback protection
- **Auto-Update**: Automatic update checking and installation
- **Partial Downloads**: Resume interrupted downloads with range requests
- **Version Management**: Firmware version checking and validation

### File Operations
- **Archive Management**: List and download archived GPS data
- **Configuration Upload**: Remote configuration file management
- **File Browser**: Web-based file system navigation
- **Pattern Matching**: Advanced file filtering with fnmatch support

### Security & Authentication
- **Basic Authentication**: HTTP basic auth for protected endpoints
- **Certificate Validation**: SSL/TLS certificate verification for OTA
- **Request Validation**: Input validation and sanitization
- **Access Control**: Configurable endpoint permissions

### System Integration
- **Event-Driven**: Integration with ESP-IDF event system
- **Context Awareness**: Access to device context and configuration
- **WiFi Coordination**: Automatic hostname and network integration
- **VFS Integration**: Unified file system access

## Installation

### ESP-IDF Integration
Add this component to your ESP-IDF project:

```cmake
# In your project's CMakeLists.txt
set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/components logger_http)
```

### PlatformIO Integration
Add to your `platformio.ini`:

```ini
[env]
lib_deps =
    ; Add other dependencies
    file://./components/logger_http
```

## Configuration

### Kconfig Options

#### Core Configuration
```kconfig
CONFIG_LOGGER_HTTP_ENABLED=y                    # Enable HTTP component
CONFIG_WEB_SERVER_TASK_STACK_SIZE=4608         # HTTP server task stack
CONFIG_WEB_SERVER_ASYNC_WORKER_TASK_STACK_SIZE=5120 # Async worker stack
CONFIG_WEB_SERVER_NUM_ASYNC_WORKERS=1          # Number of async workers
```

#### Network Configuration
```kconfig
CONFIG_MDNS_HOST_NAME="esp"                    # mDNS hostname base
CONFIG_WEB_SERVER_APPEND_MAC_TO_HOSTNAME=y     # Append MAC to hostname
CONFIG_WEB_APP_PATH="/www"                     # Web app VFS path
```

#### OTA Configuration
```kconfig
CONFIG_USE_OTA=y                               # Enable OTA updates
CONFIG_OTA_USE_AUTO_UPDATE=y                   # Enable auto-update checks
CONFIG_OTA_AUTO_UPDATE_TASK_STACK_SIZE=3840    # OTA task stack size
CONFIG_OTA_API_SERVER_URL="esplogger.majasa.ee" # OTA server URL
CONFIG_OTA_CHECK_INTERVAL=60000                # Update check interval (ms)
CONFIG_OTA_RECV_TIMEOUT=5000                   # OTA receive timeout (ms)
```

#### Security Configuration
```kconfig
CONFIG_OTA_SKIP_COMMON_NAME_CHECK=n            # Skip certificate CN check
CONFIG_OTA_SKIP_VERSION_CHECK=n                # Skip version validation
CONFIG_OTA_ENABLE_PARTIAL_HTTP_DOWNLOAD=n      # Enable partial downloads
```

#### Logging Configuration
```kconfig
CONFIG_LOGGER_HTTP_LOG_LEVEL_INFO=y            # Log level (TRACE, DEBUG, INFO, WARN, ERROR, USER, NONE)
```

## Usage

### Basic HTTP Server Setup

```c
#include "http_rest_server.h"

// Initialize HTTP server with web app path
esp_err_t ret = http_rest_init("/www");
if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize HTTP server");
    return ret;
}

// Start web server
ret = http_start_webserver();
if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start web server");
    return ret;
}

// Server is now running on port 80
// Access via: http://<hostname>.local or http://<ip-address>

// Stop server when done
http_stop_webserver();
```

### OTA Firmware Updates

#### Manual OTA Update
```c
#include "ota.h"

// Initialize OTA
esp_err_t ret = ota_start();
if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start OTA");
    return ret;
}

// Write firmware data (typically from HTTP request)
uint8_t *firmware_data = get_firmware_chunk();
uint16_t data_length = get_chunk_length();

ret = ota_write(firmware_data, data_length);
if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to write OTA data");
    return ret;
}

// Complete OTA update
struct end_result_s result;
ret = ota_end(&result);
if (ret == ESP_OK) {
    ESP_LOGI(TAG, "OTA update successful");
    // System will reboot automatically
} else {
    ESP_LOGE(TAG, "OTA update failed: %s", esp_err_to_name(ret));
}

// Cleanup
ota_deinit();
```

#### Auto-Update Configuration
```c
#include "https_ota.h"

// Configure auto-update (typically done via Kconfig)
// Server URL: CONFIG_OTA_API_SERVER_URL
// Check interval: CONFIG_OTA_CHECK_INTERVAL

// Auto-update will run in background and check for updates
// Events will be posted for update availability and status
```

### REST API Endpoints

#### System Information
```http
GET /api/sysinfo
```
Returns system information including:
- Firmware version
- Hardware info
- Network status
- Storage usage
- GPS status

#### File Operations
```http
GET /api/archive/list
```
Returns list of archived files with metadata.

```http
GET /api/archive/file?path=/sdcard/gps_log.txt
```
Download specific file.

```http
POST /api/upload
Content-Type: multipart/form-data
```
Upload file to device.

#### Configuration Management
```http
GET /api/config
```
Get current configuration.

```http
POST /api/config
Content-Type: application/json
```
Update device configuration.

#### Firmware Updates
```http
POST /api/update
Content-Type: application/octet-stream
```
Upload and install firmware update.

### Web Interface

The embedded web interface provides:

- **Dashboard**: Real-time system monitoring
- **File Browser**: GPS log file management
- **Configuration**: Runtime settings modification
- **Firmware Update**: OTA update interface
- **System Info**: Detailed device information

Access the web interface at: `http://<hostname>.local`

### Event Handling

```c
#include "ota_events.h"

// Register OTA event handlers
esp_event_handler_register(OTA_AUTO_EVENT, ESP_EVENT_ANY_ID, ota_auto_event_handler, NULL);
esp_event_handler_register(OTA_FW_EVENT, ESP_EVENT_ANY_ID, ota_fw_event_handler, NULL);

static void ota_auto_event_handler(void* arg, esp_event_base_t event_base,
                                  int32_t event_id, void* event_data)
{
    switch (event_id) {
        case OTA_AUTO_EVENT_UPDATE_AVAILABLE:
            ESP_LOGI(TAG, "Firmware update available");
            break;
        case OTA_AUTO_EVENT_UPDATE_START:
            ESP_LOGI(TAG, "Starting automatic update");
            break;
        case OTA_AUTO_EVENT_UPDATE_FINISH:
            ESP_LOGI(TAG, "Automatic update completed");
            break;
        case OTA_AUTO_EVENT_UPDATE_FAILED:
            ESP_LOGE(TAG, "Automatic update failed");
            break;
    }
}

static void ota_fw_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    switch (event_id) {
        case OTA_FW_EVENT_UPDATE_START:
            ESP_LOGI(TAG, "Manual firmware update started");
            break;
        case OTA_FW_EVENT_UPDATE_FINISH:
            ESP_LOGI(TAG, "Manual firmware update completed");
            break;
        case OTA_FW_EVENT_UPDATE_FAILED:
            ESP_LOGE(TAG, "Manual firmware update failed");
            break;
    }
}
```

### File Pattern Matching

```c
#include "http_rest_server.h"

// Use fnmatch for file filtering
const char *pattern = "*.txt";  // Match all .txt files
const char *filename = "gps_log_001.txt";

int result = fnmatch(pattern, filename, FNM_CASEFOLD);
if (result == 0) {
    ESP_LOGI(TAG, "File matches pattern");
} else if (result == FNM_NOMATCH) {
    ESP_LOGI(TAG, "File does not match pattern");
}
```

## API Reference

### HTTP Server Functions

#### Server Management
- `http_rest_init(const char *path)` - Initialize HTTP server with web path
- `http_start_webserver()` - Start HTTP server
- `http_stop_webserver()` - Stop HTTP server

#### Request Handlers
- `post_handler(httpd_req_t *req)` - Handle POST requests
- `get_handler(httpd_req_t *req)` - Handle GET requests
- `head_handler(httpd_req_t *req)` - Handle HEAD requests
- `api_handler(httpd_req_t *req)` - Handle API requests

### OTA Functions

#### Manual OTA
- `ota_start()` - Initialize OTA update process
- `ota_write(uint8_t* data, uint16_t length)` - Write firmware data
- `ota_end(struct end_result_s *result)` - Complete OTA update
- `ota_deinit()` - Cleanup OTA resources

#### Auto-Update
- Functions provided by `https_ota.h` for automatic updates

### Utility Functions

#### File Pattern Matching
- `fnmatch(const char *pattern, const char *string, int flags)` - Pattern matching
- `rangematch(const char *pattern, char test, int flags)` - Range matching

#### Base64 URL Encoding
- Functions provided by `base64url.h` for URL-safe base64 encoding

### Data Structures

#### REST Server Context
```c
typedef struct rest_server_context {
    uint8_t request_no;      // Request number identifier
    uint16_t _pad0;          // Padding for alignment
} rest_server_context_t;
```

#### OTA End Result
```c
struct end_result_s {
    esp_err_t status;        // OTA completion status
    callback_t callback;     // Completion callback function
};
```

### Request Types

```c
#define R_NONE 1              // No specific request
#define R_ARCHIVE_LIST 2      // List archived files
#define R_ARCHIVE_FILE 3      // Get specific archive file
#define R_UPLOAD 4            // File upload
#define R_FUPLOAD 5           // Firmware upload
#define R_CONFIG 6            // Configuration access
#define R_CONFIGUPLOAD 7      // Configuration upload
#define R_UPDATE 8            // Update request
#define R_FIRMWARE 9          // Firmware information
#define R_SYSINFO 10          // System information
#define R_LOGIN 11            // Authentication
#define R_ELSE 12             // Other requests
#define R_END 13              // End marker
```

### Events

#### Auto-Update Events (OTA_AUTO_EVENT)
- `OTA_AUTO_EVENT_UPDATE_AVAILABLE` - New firmware version available
- `OTA_AUTO_EVENT_UPDATE_START` - Auto-update process started
- `OTA_AUTO_EVENT_UPDATE_FINISH` - Auto-update completed successfully
- `OTA_AUTO_EVENT_UPDATE_FAILED` - Auto-update failed

#### Firmware Events (OTA_FW_EVENT)
- `OTA_FW_EVENT_UPDATE_START` - Manual firmware update started
- `OTA_FW_EVENT_UPDATE_FINISH` - Manual firmware update completed
- `OTA_FW_EVENT_UPDATE_FAILED` - Manual firmware update failed

## Web Interface

### Pages

#### Dashboard (`index.html`)
- Real-time GPS data display
- Battery and storage status
- Network information
- System health monitoring

#### File Browser (`files.html`)
- GPS log file listing
- File download functionality
- Archive management
- Storage usage visualization

#### Configuration (`config.html`)
- WiFi network settings
- GPS logging configuration
- Display preferences
- System parameters

#### Firmware Update (`fwupdate.html`)
- OTA update interface
- Version information
- Update progress tracking
- Rollback capabilities

### Assets
- `index.js` - Frontend JavaScript logic
- `index.css` - Styling and layout
- `logo.svg` - Application branding

## Examples

### Complete HTTP Server Setup

```c
#include "http_rest_server.h"
#include "ota_events.h"

static const char *TAG = "http_example";

static void ota_event_handler(void* arg, esp_event_base_t event_base,
                             int32_t event_id, void* event_data)
{
    ESP_LOGI(TAG, "OTA Event: %s", ota_auto_event_strings(event_id));
}

void app_main(void) {
    // Initialize HTTP server
    ESP_ERROR_CHECK(http_rest_init("/www"));

    // Register OTA event handlers
    ESP_ERROR_CHECK(esp_event_handler_register(OTA_AUTO_EVENT, ESP_EVENT_ANY_ID,
                                              ota_event_handler, NULL));

    // Start web server
    ESP_ERROR_CHECK(http_start_webserver());

    ESP_LOGI(TAG, "HTTP server started");
    ESP_LOGI(TAG, "Web interface: http://esp.local");
    ESP_LOGI(TAG, "API endpoint: http://esp.local/api");

    // Main application loop
    while (1) {
        // Your application logic here
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

### OTA Update with Progress Tracking

```c
#include "ota.h"
#include "ota_events.h"

static void ota_progress_callback(void) {
    ESP_LOGI(TAG, "OTA update completed, rebooting...");
    esp_restart();
}

esp_err_t perform_ota_update(uint8_t *firmware_data, size_t data_size) {
    ESP_LOGI(TAG, "Starting OTA update, size: %d bytes", data_size);

    // Initialize OTA
    esp_err_t ret = ota_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start OTA: %s", esp_err_to_name(ret));
        return ret;
    }

    // Write firmware data in chunks
    size_t offset = 0;
    const size_t chunk_size = 1024;

    while (offset < data_size) {
        size_t write_size = MIN(chunk_size, data_size - offset);

        ret = ota_write(&firmware_data[offset], write_size);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to write OTA data at offset %d: %s",
                     offset, esp_err_to_name(ret));
            ota_deinit();
            return ret;
        }

        offset += write_size;
        ESP_LOGI(TAG, "OTA progress: %d/%d bytes", offset, data_size);
    }

    // Complete update
    struct end_result_s result = {
        .status = ESP_OK,
        .callback = ota_progress_callback
    };

    ret = ota_end(&result);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to complete OTA: %s", esp_err_to_name(ret));
        ota_deinit();
        return ret;
    }

    ESP_LOGI(TAG, "OTA update successful");
    return ESP_OK;
}
```

## Troubleshooting

### Common Issues

#### HTTP Server Won't Start
- Check for port conflicts (default port 80)
- Verify web app path exists in VFS
- Check stack size configuration
- Enable debug logging: `CONFIG_LOGGER_HTTP_LOG_LEVEL_DEBUG=y`

#### OTA Update Failures
- Verify firmware image integrity
- Check available flash space (need 2 OTA partitions)
- Validate server certificate (unless skipped)
- Monitor OTA events for detailed error information

#### File Upload Issues
- Check VFS mount status and available space
- Verify file permissions and path validity
- Check upload size limits
- Enable async worker debugging

#### Web Interface Not Loading
- Verify embedded files are properly linked in build
- Check mDNS hostname resolution
- Try direct IP access instead of hostname
- Clear browser cache and reload

#### Auto-Update Not Working
- Verify OTA server URL and network connectivity
- Check update check interval configuration
- Validate firmware version format
- Monitor auto-update events

### Debug Configuration

Enable detailed debugging:

```kconfig
CONFIG_LOGGER_HTTP_LOG_LEVEL_DEBUG=y
CONFIG_OTA_SKIP_COMMON_NAME_CHECK=y    # For testing only
CONFIG_OTA_SKIP_VERSION_CHECK=y        # For testing only
```

### Network Diagnostics

```c
// Check server status
if (server != NULL) {
    ESP_LOGI(TAG, "HTTP server is running");
} else {
    ESP_LOGI(TAG, "HTTP server is not running");
}

// Check mDNS status
ESP_LOGI(TAG, "mDNS hostname: %s", CONFIG_MDNS_HOST_NAME);
ESP_LOGI(TAG, "Full URL: http://%s.local", CONFIG_MDNS_HOST_NAME);
```

### OTA Diagnostics

```c
#include "ota_events.h"

// Monitor OTA events
ESP_LOGI(TAG, "OTA Event strings:");
for (int i = 0; i < 4; i++) {
    ESP_LOGI(TAG, "  %d: %s", i, ota_auto_event_strings(i));
}
```

## Dependencies

- ESP-IDF v4.4 or later
- logger_common component
- esp_http_server
- esp_https_ota
- mdns
- logger_config (optional)
- logger_wifi (optional)
- logger_vfs (optional)

## Contributing

1. Follow ESP-IDF coding conventions
2. Add comprehensive error handling
3. Include event notifications for state changes
4. Update web interface for new features
5. Test with multiple browsers and devices
6. Document API changes in README

## License

See LICENSE file in component directory.