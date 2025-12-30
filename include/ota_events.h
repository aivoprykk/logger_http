#ifndef C960B643_0C87_4766_B8B3_D547C8E631C7
#define C960B643_0C87_4766_B8B3_D547C8E631C7

#include "esp_event.h"
#include "logger_common.h"

#define OTA_EVENT_BASE 0x70  // Component ID 7
#define OTA_FW_EVENT_BASE 0x71  // Component ID 7.1

// Declare an event base
ESP_EVENT_DECLARE_BASE(OTA_AUTO_EVENT);        // declaration of the OTA_EVENT family
#define OTA_AUTO_EVENT_ENUM(l) OTA_AUTO_EVENT_##l,
// Declare an event base
ESP_EVENT_DECLARE_BASE(OTA_FW_EVENT);        // declaration of the OTA_EVENT family
#define OTA_FW_EVENT_ENUM(l) OTA_FW_EVENT_##l,

#define OTA_EVENT_LIST(l) \
    l(UPDATE_START) \
    l(UPDATE_FINISH) \
    l(UPDATE_FAILED) \
    l(UPDATE_AVAILABLE)

// declaration of the specific events under the OTA_EVENT family
enum {                                       
    OTA_EVENT_LIST(OTA_AUTO_EVENT_ENUM)
};
enum {                                       
    OTA_EVENT_LIST(OTA_FW_EVENT_ENUM)
};

const char * ota_auto_event_strings(int id);
const char * ota_fw_event_strings(int id);

#endif /* C960B643_0C87_4766_B8B3_D547C8E631C7 */
