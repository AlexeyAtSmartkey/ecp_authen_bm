# Defines SOURCES_COMPONENTS

set(SOURCES_COMPONENTS
    "${ProjDirPath}/components/CLIF/Clif_Reg.h"
    "${ProjDirPath}/components/CLIF/Clif.h"
    "${ProjDirPath}/components/CLIF/Clif.c"
    "${ProjDirPath}/components/phOsal/inc/phOsal_Config.h"
    "${ProjDirPath}/components/phOsal/inc/phOsal.h"
    "${ProjDirPath}/components/DAL/inc/phDriver_Timer.h"
    "${ProjDirPath}/components/DAL/inc/phDriver_Gpio.h"
    "${ProjDirPath}/components/DAL/inc/phDriver.h"
    "${ProjDirPath}/components/DAL/inc/phbalReg.h"
    "${ProjDirPath}/components/phOsal/src/NullOs/phOsal_NullOs.h"
    "${ProjDirPath}/components/phOsal/src/NullOs/phOsal_NullOs.c"
    "${ProjDirPath}/components/DAL/src/SAM/phbalReg_Sam_Int.h"
    "${ProjDirPath}/components/DAL/src/SAM/phbalReg_Sam_Int.c"
    "${ProjDirPath}/components/DAL/src/SAM/phbalReg_Sam.h"
    "${ProjDirPath}/components/DAL/src/SAM/phbalReg_Sam.c"
    "${ProjDirPath}/components/phOsal/src/NullOs/portable/phOsal_Port_PN76xx.c"
    "${ProjDirPath}/components/phOsal/src/NullOs/portable/phOsal_NullOs_Port.h"
    "${ProjDirPath}/components/phOsal/src/NullOs/portable/phOsal_Cortex_Port.h"
    "${ProjDirPath}/components/DAL/src/PN76xx/phDriver_PN76xx.c"
    "${ProjDirPath}/components/DAL/src/SAM/TDA/phbalReg_Sam_TDA.h"
    "${ProjDirPath}/components/DAL/src/SAM/TDA/phbalReg_Sam_TDA.c"
)

set(INCLUDE_COMPONENTS
	"${ProjDirPath}/components/DAL/inc"
	"${ProjDirPath}/components/DAL/src/SAM"
	"${ProjDirPath}/components/DAL/src/SAM/TDA"
	"${ProjDirPath}/components/phOsal/inc"
	"${ProjDirPath}/components/phOsal/src/Freertos"
	"${ProjDirPath}/components/CLIF"
	"${ProjDirPath}/components/phOsal/src/NullOs"
	"${ProjDirPath}/components/phOsal/src/NullOs/portable"
)
