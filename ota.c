
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/timers.h"

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"

#include "ota.h"
#include "context.h"

static const char* TAG = "ota";

static TimerHandle_t timeout_timer;
static esp_ota_handle_t handle;

typedef enum  {
    ota_state_Idle=0,
    ota_state_InProgress,
    ota_state_Reboot,
    ota_state_Error
} ota_state_t;

static struct
{
    // This state is a very bad and lazy way of cordinating multiple OTA handles.
    ota_state_t state;
} ota;

extern struct context_s m_context;

esp_err_t ota_deinit() {
    // Remove timeout timer
    esp_err_t result = ESP_OK;
    if (timeout_timer != NULL) {
        if (xTimerDelete(timeout_timer, 0) == pdPASS)
            timeout_timer = NULL;
        else
            ESP_LOGW(TAG, "Failed to delete timeout timer.");
    }

    // Check for non-initalized or error state
    if (ota.state != ota_state_InProgress) {
        ota.state = ota_state_Idle;
        return ESP_ERR_INVALID_STATE;
    }

   result = esp_ota_end(handle);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed, err=0x%x.", result);
        ota.state = ota_state_Idle;
        goto finish;
    }

    ota.state = ota_state_Idle;

    finish:
    m_context.firmware_update_started = 0;

    return ESP_OK;
}

static struct end_result_s timer_state;

static void timer_cb(TimerHandle_t t) {
    ESP_LOGW(TAG, "Timeout during update. Performing cleanup...");
    struct end_result_s * handle = (struct end_result_s*)pvTimerGetTimerID(t);
    if (handle != 0)
        handle->callback();
}

static void timer_b_cb() {
    ota_deinit();
}

esp_err_t ota_start() {
    // Don't attempt to re-init an ongoing OTA
    if (ota.state != ota_state_Idle)
        return ESP_ERR_INVALID_STATE;

    // Check that the active and boot partition are the same otherwise we might be trying to double update
    const esp_partition_t* boot = esp_ota_get_boot_partition();
    const esp_partition_t* active = esp_ota_get_running_partition();
    if (boot != active)
        return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "Boot partition type %d subtype %d at offset 0x%"PRIu32".", boot->type, boot->subtype, boot->address);
    ESP_LOGI(TAG, "Active partition type %d subtype %d at offset 0x%"PRIu32".", active->type, active->subtype, active->address);

    // Grab next update target
    const esp_partition_t* target = esp_ota_get_next_update_partition(NULL);
    if (target == NULL)
        return ESP_ERR_NOT_FOUND;

    ESP_LOGI(TAG, "Target partition type %d subtype %d at offset 0x%"PRIu32".", target->type, target->subtype, target->address);

    esp_err_t result = esp_ota_begin(target, OTA_SIZE_UNKNOWN, &handle);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed, error=%d.", result);
        return result;
    }

    timer_state.callback = timer_b_cb;
    timer_state.status = ESP_OK;

    // Create a timer that will handle timeout events
    timeout_timer = xTimerCreate("OTATimeout", pdMS_TO_TICKS(10000), false, &timer_state, timer_cb);

    // Start the timer
    if (xTimerStart(timeout_timer, pdMS_TO_TICKS(100)) != pdPASS)
        ESP_LOGE(TAG, "Failed to start timeout timer.");

    m_context.firmware_update_started = 1;
    ota.state = ota_state_InProgress;
    return ESP_OK;
}

esp_err_t ota_write(uint8_t* data, uint16_t length) {
    
    // Check for non-initialized or error state
    if (ota.state != ota_state_InProgress)
        return ESP_ERR_INVALID_STATE;

    esp_err_t result = esp_ota_write(handle, data, length);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_write failed, err=%d.", result);
        ota.state = ota_state_Error;
        return result;
    }

    // Reset timeout timer
    if (timeout_timer != NULL)
        xTimerReset(timeout_timer, pdMS_TO_TICKS(10));

    return ESP_OK;
}

static void cb_when_done() {
    ota.state = ota_state_Reboot;
    m_context.request_restart = 1;
    //esp_restart();
}

esp_err_t ota_end(struct end_result_s * result) {
    // Construct result object
    result->callback = 0;

    // Perform clean up operations
    result->status = ota_deinit();
    if (result->status != ESP_OK)
        goto finish;

    const esp_partition_t* target = esp_ota_get_next_update_partition(NULL);
    result->status = esp_ota_set_boot_partition(target);
    if (result->status != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed, err=%d.", result->status);
        ota.state = ota_state_Idle;
        goto finish;
    }

    const esp_partition_t* boot = esp_ota_get_boot_partition();
    ESP_LOGI(TAG, "Boot partition type %d subtype %d at offset 0x%"PRIu32".", boot->type, boot->subtype, boot->address);

    // Success. Update status and set reboot callback
    result->status = ESP_OK;
    result->callback = cb_when_done;

    finish:
    return result->status;
}