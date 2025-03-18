#ifndef C960B643_0C87_4766_B8B3_D547C8E631C7
#define C960B643_0C87_4766_B8B3_D547C8E631C7

#include "esp_event.h"
#include "logger_common.h"

// Declare an event base
ESP_EVENT_DECLARE_BASE(OTA_AUTO_EVENT);        // declaration of the OTA_EVENT family

#define OTA_AUTO_EVENT_LIST(l) \
    l(OTA_AUTO_EVENT_UPDATE_START) \
    l(OTA_AUTO_EVENT_UPDATE_FINISH) \
    l(OTA_AUTO_EVENT_UPDATE_FAILED) \
    l(OTA_AUTO_EVENT_UPDATE_HAS_UPDATE)

// declaration of the specific events under the OTA_EVENT family
enum {                                       
    OTA_AUTO_EVENT_LIST(ENUM)
};

extern const char * const ota_auto_event_strings[];

#endif /* C960B643_0C87_4766_B8B3_D547C8E631C7 */
