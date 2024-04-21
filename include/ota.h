#ifndef FAF0CA02_9A09_4F49_9416_D94AAE0BE223
#define FAF0CA02_9A09_4F49_9416_D94AAE0BE223

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*callback_t)(void);

struct end_result_s {
    esp_err_t status;
    callback_t callback;
};

esp_err_t ota_deinit();
esp_err_t ota_start();
esp_err_t ota_write(uint8_t* data, uint16_t length);
esp_err_t ota_end(struct end_result_s * result);

#ifdef __cplusplus
}
#endif

#endif /* FAF0CA02_9A09_4F49_9416_D94AAE0BE223 */
