# CROSS COMPILER SETTING
SET(CMAKE_SYSTEM_NAME Generic)
CMAKE_MINIMUM_REQUIRED (VERSION 3.10.0)

# THE VERSION NUMBER
SET (Tutorial_VERSION_MAJOR 1)
SET (Tutorial_VERSION_MINOR 0)

if (DEFINED ENV{SdkRootDirPath})
	SET(SdkRootDirPath "$ENV{SdkRootDirPath}")
endif()

if (NOT DEFINED SdkRootDirPath)
	MESSAGE(FATAL_ERROR "SDK path could not be determined. Please update SdkRootDirPath value from your CMake presets file(s).")
endif()

project(SmartphoneKey_bm)

# ENABLE ASM
ENABLE_LANGUAGE(ASM)

# RESET FLAG VALUES
SET(CMAKE_ASM_FLAGS_DEBUG "")
SET(CMAKE_ASM_FLAGS_RELEASE "")
SET(CMAKE_C_FLAGS_DEBUG "")
SET(CMAKE_C_FLAGS_RELEASE "")
SET(CMAKE_CXX_FLAGS_DEBUG "")
SET(CMAKE_CXX_FLAGS_RELEASE "")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "")
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "")

SET(CMAKE_STATIC_LIBRARY_PREFIX)
SET(CMAKE_STATIC_LIBRARY_SUFFIX)

SET(CMAKE_EXECUTABLE_LIBRARY_PREFIX)
SET(CMAKE_EXECUTABLE_LIBRARY_SUFFIX)

# CURRENT DIRECTORY
SET(ProjDirPath ${CMAKE_CURRENT_SOURCE_DIR})

SET(EXECUTABLE_OUTPUT_PATH ${ProjDirPath}/${CMAKE_BUILD_TYPE})
SET(LIBRARY_OUTPUT_PATH ${ProjDirPath}/${CMAKE_BUILD_TYPE})

set(CMAKE_USER_MAKE_RULES_OVERRIDE "user_override.cmake")

set(MCUX_SDK_PROJECT_NAME SmartphoneKey_bm.elf)

include(${ProjDirPath}/flags.cmake)

include(${ProjDirPath}/board.cmake)
include(${ProjDirPath}/cmsis.cmake)
include(${ProjDirPath}/components.cmake)
include(${ProjDirPath}/device.cmake)
include(${ProjDirPath}/drivers.cmake)
include(${ProjDirPath}/nxpnfcrdlib.cmake)
include(${ProjDirPath}/rtt.cmake)
include(${ProjDirPath}/utilities.cmake)

set(ALL_SOURCES
	${SOURCES_BOARD}
	${SOURCES_CMSIS}
	${SOURCES_COMPONENTS}
	${SOURCES_DEVICE}
	${SOURCES_DRIVERS}
	${SOURCES_NXPNFCRDLIB}
	${SOURCES_RTT}
	${SOURCES_UTILITIES}
)

set(ALL_INCLUDES
	${INCLUDE_BOARD}
	${INCLUDE_CMSIS}
	${INCLUDE_COMPONENTS}
	${INCLUDE_DEVICE}
	${INCLUDE_DRIVERS}
	${INCLUDE_NFCRDLIB}
	${INCLUDE_RTT}
	${INCLUDE_UTILITIES}
)

set(ProjSrcPath ${ProjDirPath}/source)

add_executable(${MCUX_SDK_PROJECT_NAME}
	${ALL_SOURCES}
	"${ProjDirPath}/startup/startup_pn7642.c"
	"${ProjDirPath}/mbedcrypto/src/sha256_alt.c"
	"${ProjDirPath}/mbedcrypto/src/bignum.c"
	"${ProjDirPath}/mbedcrypto/src/memory_buffer_alloc.c"
	"${ProjDirPath}/mbedcrypto/src/crypto_helper.c"
	"${ProjDirPath}/mbedcrypto/src/ecc_alt.c"
	"${ProjDirPath}/mbedcrypto/src/platform.c"
	"${ProjDirPath}/mbedcrypto/src/platform_util.c"
	"${ProjSrcPath}/SmartLock.c"
	"${ProjSrcPath}/phApp_PN76XX_Init.c"
	"${ProjSrcPath}/phApp_Init.c"
	"${ProjSrcPath}/phApp_Helper.c"
	"${ProjSrcPath}/picc_manager/picc_manager.c"
	"${ProjSrcPath}/semihost_hardfault.c"
	"${ProjSrcPath}/apple_pass_manager/apple_pass_manager.c"
	"${ProjSrcPath}/device_manager/device_manager.c"
	"${ProjSrcPath}/key_manager/key_manager.c"
	"${ProjSrcPath}/nfc_comm/nfc_comm.c"
	"${ProjSrcPath}/nrf_comm/nrf_comm_protocol.c"
	"${ProjSrcPath}/nrf_comm/nrf_comm.c"
	"${ProjSrcPath}/ota/ota.c"
	"${ProjSrcPath}/taskmanager/peripheral/taskmanager_peripheral.c"
	"${ProjSrcPath}/taskmanager/taskmanager_test.c"
	"${ProjSrcPath}/taskmanager/taskmanager.c"
	"${ProjSrcPath}/delay_ms/delay_ms.c"
	"${ProjSrcPath}/led_blinky/led_blinky.c"
	"${ProjSrcPath}/google_pass_manager/ApduEx.c"
	"${ProjSrcPath}/google_pass_manager/NdefEx.c"
	"${ProjSrcPath}/google_pass_manager/NdefEx_helper.c"
	"${ProjSrcPath}/google_pass_manager/google_pass_manager.c"
)

if(${LIBRARY_TYPE} STREQUAL "REDLIB")
    target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE $ENV{ARMGCC_DIR}/redlib/include)
endif()

set(c_include_directories
	${ALL_INCLUDES}
	"${ProjDirPath}/pnev7642fama/nfc_examples/NfcrdlibEx2_ECP"
	"${ProjDirPath}/mbedtls/include"
	"${ProjDirPath}/mbedtls/library"
	"${ProjDirPath}/mbedcrypto/inc"
	"${ProjDirPath}/NxpCtRdlib/comps/phpalCt/inc"
	"${ProjDirPath}/NxpCtRdlib/comps/phpalCt/src"
	"${ProjDirPath}/NxpCtRdlib/phhalCt/phhal_Lower"
	"${ProjDirPath}/NxpCtRdlib/phhalCt/phhal_upper"
	"${ProjSrcPath}"
	"${ProjSrcPath}/apple_pass_manager"
	"${ProjSrcPath}/device_manager"
	"${ProjSrcPath}/key_manager"
	"${ProjSrcPath}/nfc_comm"
	"${ProjSrcPath}/nrf_comm"
	"${ProjSrcPath}/ota"
	"${ProjSrcPath}/picc_manager"
	"${ProjSrcPath}/taskmanager"
	"${ProjSrcPath}/delay_ms"
	"${ProjSrcPath}/led_blinky"
	"${ProjSrcPath}/google_pass_manager"
)


target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE $<$<COMPILE_LANGUAGE:C>:${c_include_directories}>)

set(cpp_include_directories "")

target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${cpp_include_directories}>)

set(include_files "")

target_precompile_headers(${MCUX_SDK_PROJECT_NAME} PRIVATE ${include_files})

set(link_directories "${ProjDirPath}/device/hal_intfs/lib")


set(link_libraries "intfs")


target_link_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE ${link_directories})
target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE -Wl,--start-group)
target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE ${TARGET_LINK_SYSTEM_LIBRARIES} ${link_libraries})
target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE -Wl,--end-group)


add_custom_command(TARGET ${MCUX_SDK_PROJECT_NAME} POST_BUILD
    # generate Intel HEX next to the ELF
    COMMAND ${CMAKE_OBJCOPY}
            -O ihex
            $<TARGET_FILE:${MCUX_SDK_PROJECT_NAME}>
            $<TARGET_FILE_DIR:${MCUX_SDK_PROJECT_NAME}>/$<TARGET_FILE_BASE_NAME:${MCUX_SDK_PROJECT_NAME}>.hex

    # generate raw binary next to the ELF
    COMMAND ${CMAKE_OBJCOPY}
            -O binary
            $<TARGET_FILE:${MCUX_SDK_PROJECT_NAME}>
            $<TARGET_FILE_DIR:${MCUX_SDK_PROJECT_NAME}>/$<TARGET_FILE_BASE_NAME:${MCUX_SDK_PROJECT_NAME}>.bin

    COMMENT "Generating .hex and .bin from .elf"
)
