#ifndef CA04E48E_16BA_4068_8925_26E8ABD75074
#define CA04E48E_16BA_4068_8925_26E8ABD75074

#include <stdint.h>
#include "strbf.h"

#ifdef __cplusplus
extern "C" {
#endif


#define OTA_HOST_SIZE 24
#define OTA_PATH_SIZE 64
#define OTA_REQ_SIZE 256

struct m_ota_ctx {
    char host[OTA_HOST_SIZE];
    uint16_t port;
    uint32_t last_ota_check;
    uint32_t delay_in_sec;
    char path[OTA_PATH_SIZE];
    char req[OTA_REQ_SIZE];
    struct strbf_s request;
    unsigned char ok;
};

void https_ota_start();
void https_ota_stop();

#ifdef __cplusplus
}
#endif
#endif /* CA04E48E_16BA_4068_8925_26E8ABD75074 */
