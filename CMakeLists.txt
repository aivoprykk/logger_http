
set(REQ esp_http_server)
set(PRIVREQ app_update mdns logger_wifi logger_common logger_str json logger_adc logger_vfs logger_config logger_context gps_log logger_ubx)

file(GLOB SOURCES *.c)
SET(INCS include)

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCS}
    REQUIRES ${REQ}
    PRIV_REQUIRES ${PRIVREQ}
)
