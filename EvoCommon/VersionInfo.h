#pragma once

#define PRODUCT_VERSION (1,0)
#define FILE_VERSION    (1,0,0,1)

#ifdef _DEBUG
#define THE_FILE_FLAGS 0x1L
#else
#define THE_FILE_FLAGS 0x0L
#endif

#define VERSION_INFO_STUFF \
FILEVERSION 1,0,0,1 \
PRODUCTVERSION 1,0,0,1 \
FILEFLAGSMASK 0x3fL \
FILEFLAGS THE_FILE_FLAGS \
FILEOS 0x40004L \
FILETYPE 0x2L \
FILESUBTYPE 0x0L \

#define VERSION_COMPANY_NAME "Evo Security Technologies"
#define VERSION_COPYRIGHT "(c) Evo Security Technologies.  All rights reserved."
#define VERSION_FILE_VERSION "1.0.0.1"
#define VERSION_PRODUCT_VERSION "1.0"
#define VERSION_PRODUCT_NAME "Evo Secure Login"



