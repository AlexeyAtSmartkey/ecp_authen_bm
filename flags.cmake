if(${LIBRARY_TYPE} STREQUAL "REDLIB")
	set(SPECS "-specs=redlib.specs")
elseif(${LIBRARY_TYPE} STREQUAL "NEWLIB_NANO")
	set(SPECS "--specs=nano.specs")
endif()

if(NOT DEFINED DEBUG_CONSOLE_CONFIG)
	set(DEBUG_CONSOLE_CONFIG "-DSDK_DEBUGCONSOLE=0")
endif()

set(CMAKE_ASM_FLAGS_DEBUG " \
    ${CMAKE_ASM_FLAGS_DEBUG} \
    ${FPU} \
    -mcpu=cortex-m33+nodsp \
    -mthumb \
")

set(CMAKE_C_FLAGS_DEBUG " \
    ${CMAKE_C_FLAGS_DEBUG} \
    ${FPU} \
    ${DEBUG_CONSOLE_CONFIG} \
    -std=gnu99 \
    -DCPU_PN7642EV \
    -DCPU_PN7642EV_cm33_nodsp \
    -DPH_OSAL_ENABLE_TRUSTZONE \
    -D__PN76XX__=1 \
    -D__PN7642__=1 \
    -DNXPBUILD_CUSTOMER_HEADER_INCLUDED \
    -DMCUXPRESSO_SDK \
    -DconfigENABLE_TRUSTZONE=1 \
    -DSEGGER_RTT_SECTION=\\\"._SEGGER_RTT\\\" \
    -DSEGGER_RTT_BUFFER_SECTION=\\\"._SEGGER_RTT_BUFFER\\\" \
    -DCR_INTEGER_PRINTF \
    -DPRINTF_FLOAT_ENABLE=0 \
    -D__MCUXPRESSO \
    -D__USE_CMSIS \
    -DDEBUG \
    -DMBEDTLS_CONFIG_FILE=\\\"mbedtls_config_alt.h\\\" \
    -DMBEDTLS_ALLOW_PRIVATE_ACCESS \
    -DPHAPP_MAX_CT_SLOTS_SUPPORTED=0x01 \
    -DPHAPP_CT_SLOT_NUM=0x02 \
    -DNXPBUILD__PSP_SW_MODE_ENABLE \
    -DPH_OSAL_NULLOS \
    -O0 \
    -fno-common \
    -fmerge-constants \
    -g3 \
    -mcpu=cortex-m33+nodsp+nofp -ffunction-sections -fdata-sections -ffreestanding -fno-builtin \
    -fstack-usage \
    -mcpu=cortex-m33+nodsp \
    -mthumb \
")

set(CMAKE_CXX_FLAGS_DEBUG " \
    ${CMAKE_CXX_FLAGS_DEBUG} \
    ${FPU} \
    ${DEBUG_CONSOLE_CONFIG} \
    -O0 \
    -fno-common \
    -fmerge-constants \
    -g3 \
    -Wall \
    -fstack-usage \
    -mcpu=cortex-m33+nodsp \
    -mthumb \
")

set(CMAKE_EXE_LINKER_FLAGS_DEBUG " \
    ${CMAKE_EXE_LINKER_FLAGS_DEBUG} \
    ${FPU} \
    ${SPECS} \
    -nostdlib \
    -Xlinker \
    -no-warn-rwx-segments \
    -Xlinker \
    -Map=output.map \
    -Xlinker \
    --gc-sections \
    -Xlinker \
    -print-memory-usage \
    -Xlinker \
    --sort-section=alignment \
    -Xlinker \
    --cref \
    -mcpu=cortex-m33+nodsp \
    -mthumb \
    -T\"${ProjDirPath}/SmartphoneKey_bm_Debug.ld\" \
")
