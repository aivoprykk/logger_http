#ifndef FC0AF177_160E_4294_8D44_3953BBB70C15
#define FC0AF177_160E_4294_8D44_3953BBB70C15

#ifdef __cplusplus
extern "C" {
#endif

#include "sdkconfig.h"

extern struct m_wifi_context wifi_context;
#if !defined(CONFIG_LOGGER_WIFI_ENABLED)
struct m_wifi_context {
    char hostname[32];
};
#endif

#if defined(CONFIG_LOGGER_USE_GLOBAL_LOG_LEVEL)
#define C_LOG_LEVEL LOGGER_GLOBAL_LOG_LEVEL
#else
#define C_LOG_LEVEL CONFIG_LOGGER_HTTP_LOG_LEVEL
#endif
#include "common_log.h"

#ifdef __cplusplus
}
#endif

#endif /* FC0AF177_160E_4294_8D44_3953BBB70C15 */
