
set(REQ esp_http_server)
set(PRIVREQ app_update mdns logger_wifi logger_common logger_str logger_adc logger_vfs logger_config logger_context gps_log logger_ubx app_update)
set(PRIVREQ ${PRIVREQ} esp_http_client esp_https_ota esp-tls)

file(GLOB SOURCES *.c)
SET(INCS include)

set(pdir ${CMAKE_CURRENT_SOURCE_DIR})

if(CONFIG_OTA_USE_AUTO_UPDATE)
set(srcs ${srcs} https_ota.c)
if(CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP AND EXISTS ${pdir}/certs/majasa_ca.pem)
set(ota_crt ${pdir}/certs/majasa_ca.pem)
endif()
endif()

if(CONFIG_OTA_USE_AUTO_UPDATE AND CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP)
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCS}
    EMBED_TXTFILES ${ota_crt} 
    REQUIRES ${REQ}
    PRIV_REQUIRES ${PRIVREQ}
)
else()
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCS}
    REQUIRES ${REQ}
    PRIV_REQUIRES ${PRIVREQ}
)
endif()
