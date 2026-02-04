
set(REQ vfs)
set(PRIVREQ logger_common strutil logger_context)

file(GLOB SOURCES *.c)
SET(INCS include)

set(pdir ${CMAKE_CURRENT_SOURCE_DIR})

if(CONFIG_OTA_USE_AUTO_UPDATE)
    set(srcs ${srcs} https_ota.c)

    if(NOT CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP AND EXISTS ${pdir}/certs/majasa_ca.pem)
        set(ota_crt ${pdir}/certs/majasa_ca.pem)
    endif()
endif()

if(CONFIG_OTA_USE_AUTO_UPDATE AND NOT CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP)
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

if(CONFIG_LOGGER_HTTP_ENABLED)
    set(ENV{HTTP_ENABLED} "true")
    target_link_libraries(${COMPONENT_LIB} PUBLIC idf::esp_http_server)
    target_add_binary_data(${COMPONENT_LIB} "${pdir}/web-frontend-tiny/public/index.css.gz" BINARY)
    target_add_binary_data(${COMPONENT_LIB} "${pdir}/web-frontend-tiny/public/index.js.gz" BINARY)
    target_add_binary_data(${COMPONENT_LIB} "${pdir}/web-frontend-tiny/public/logo.svg.gz" BINARY)
endif()

if(CONFIG_LOGGER_VFS_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::logger_vfs)
endif()

if(CONFIG_GPS_LOG_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::gps_log)
endif()

if(CONFIG_UBLOX_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::logger_ubx)
endif()

if(CONFIG_LOGGER_ADC_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::logger_adc)
endif()

if(CONFIG_LOGGER_WIFI_ENABLED)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::logger_wifi)
endif()

if(CONFIG_USE_OTA)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::app_update)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::esp_partition)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::esp_system)
endif()

if(CONFIG_OTA_USE_AUTO_UPDATE)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::esp_https_ota)
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::esp_http_client)

    if(NOT CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP)
        target_link_libraries(${COMPONENT_LIB} PRIVATE idf::esp-tls)
    endif()
endif()