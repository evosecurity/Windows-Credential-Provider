

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 21:14:07 2038
 */
/* Compiler settings for EvoCredFilter.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __EvoCredFilter_i_h__
#define __EvoCredFilter_i_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __CredentialFilter_FWD_DEFINED__
#define __CredentialFilter_FWD_DEFINED__

#ifdef __cplusplus
typedef class CredentialFilter CredentialFilter;
#else
typedef struct CredentialFilter CredentialFilter;
#endif /* __cplusplus */

#endif 	/* __CredentialFilter_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"
#include "CredentialProvider.h"
#include "shobjidl.h"

#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __EvoCredFilterLib_LIBRARY_DEFINED__
#define __EvoCredFilterLib_LIBRARY_DEFINED__

/* library EvoCredFilterLib */
/* [version][uuid] */ 


EXTERN_C const IID LIBID_EvoCredFilterLib;

EXTERN_C const CLSID CLSID_CredentialFilter;

#ifdef __cplusplus

class DECLSPEC_UUID("a81f782e-cf30-439a-bad8-645d9862ea99")
CredentialFilter;
#endif
#endif /* __EvoCredFilterLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


