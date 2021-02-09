#pragma once

// 7880900-0X PRIVACYIDEA CODES
#define EVOSOL_TRANSACTION_SUCCESS						((HRESULT)0x78809004)
#define EVOSOL_TRANSACTION_FAILURE						((HRESULT)0x78809005)
#define EVOSOL_OFFLINE_OTP_SUCCESS						((HRESULT)0x78809006)
#define EVOSOL_OFFLINE_OTP_FAILURE						((HRESULT)0x78809007)
#define EVOSOL_NO_CHALLENGES							((HRESULT)0x78809009)

#define EVOSOL_ERROR_EMPTY_RESPONSE						((HRESULT)0x7880900E)
#define EVOSOL_STATUS_NOT_SET							((HRESULT)0x7880900F)

// 888090-1X VALIDATE CHECK RETURN CODES
#define EVOSOL_AUTH_SUCCESS								((HRESULT)0x88809010)
#define EVOSOL_AUTH_FAILURE								((HRESULT)0x88809011)

// This means there was an error specified in the response from Privacyidea
// The error can be retrieved by calling getLastError and getLastErrorMessage
#define EVOSOL_AUTH_ERROR								((HRESULT)0x88809012)
#define EVOSOL_TRIGGERED_CHALLENGE						((HRESULT)0x88809013)

// This means either the server is really unavailable while the user thought it would be available 
// OR
// The user meant to authenticate offline (and expects the server to be unavailable) but the entered OTP didn't match the offlineData
// NOTE this implies there was offlineData available for the user
#define EVOSOL_WRONG_OFFLINE_SERVER_UNAVAILABLE			((HRESULT)0x88809014)
#define EVOSOL_ENDPOINT_SETUP_ERROR						((HRESULT)0x88809015)


// 888090-2X OFFLINE CODES
#define EVOSOL_OFFLINE_DATA_NO_OTPS_LEFT				((HRESULT)0x88809020)
#define EVOSOL_OFFLINE_DATA_USER_NOT_FOUND				((HRESULT)0x88809021)
#define EVOSOL_OFFLINE_NO_OFFLINE_DATA					((HRESULT)0x88809022) 
#define EVOSOL_OFFLINE_FILE_DOES_NOT_EXIST				((HRESULT)0x88809023)
#define EVOSOL_OFFLINE_FILE_EMPTY						((HRESULT)0x88809024)
#define EVOSOL_OFFLINE_WRONG_OTP						((HRESULT)0x88809025)

// 888090-3X JSON ERRORS
#define EVOSOL_JSON_FORMAT_ERROR						((HRESULT)0x88809030)
#define EVOSOL_JSON_PARSE_ERROR							((HRESULT)0x88809031)
#define EVOSOL_JSON_ERROR_CONTAINED						((HRESULT)0x88809032)

// 888090-4X ENDPOINT ERRORS
// Use only those for now, since there is no need for the code to differentiate the error further
// The "real" cause is logged right after the error occurs in the endpoint
#define EVOSOL_ENDPOINT_SERVER_UNAVAILABLE				((HRESULT)0x88809041)


#define EVOSOL_SERVER_PREPOLL_FAILED                    ((HRESULT)0x88809051)