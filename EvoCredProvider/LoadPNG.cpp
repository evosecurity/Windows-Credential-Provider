#include "pch.h"

#include <wincodec.h>
#include <atlbase.h>
#include <comdef.h>
#include "resource.h"


using namespace ATL;
#pragma comment(lib, "windowscodecs.lib")




HRESULT CreateStreamOnResource(HINSTANCE hInstance, LPCTSTR lpName, LPCTSTR lpType, IStream** lplpStream)
{
    // initialize return value

    if (lplpStream == NULL)
        return E_POINTER;

    HRESULT hr = E_FAIL;
    *lplpStream = NULL;


    // find the resource

    HRSRC hrsrc = FindResource(hInstance, lpName, lpType);
    if (hrsrc == NULL)
        return hr;

    // load the resource

    DWORD dwResourceSize = SizeofResource(hInstance, hrsrc);
    HGLOBAL hglbImage = LoadResource(hInstance, hrsrc);
    if (hglbImage == NULL)
        return hr;

    // lock the resource, getting a pointer to its data

    LPVOID pvSourceResourceData = LockResource(hglbImage);
    if (pvSourceResourceData == NULL)
        return hr;

    // allocate memory to hold the resource data

    HGLOBAL hgblResourceData = GlobalAlloc(GMEM_MOVEABLE, dwResourceSize);
    if (hgblResourceData == NULL)
        return hr;

    // get a pointer to the allocated memory

    LPVOID pvResourceData = GlobalLock(hgblResourceData);
    if (pvResourceData == NULL)
        goto FreeData;

    // copy the data from the resource to the new memory block

    CopyMemory(pvResourceData, pvSourceResourceData, dwResourceSize);
    GlobalUnlock(hgblResourceData);

    // create a stream on the HGLOBAL containing the data

    if (SUCCEEDED(hr = CreateStreamOnHGlobal(hgblResourceData, TRUE, lplpStream)))
        goto Return;

FreeData:
    // couldn't create stream; free the memory

    GlobalFree(hgblResourceData);

Return:
    return hr;
}

// Loads a PNG image from the specified stream (using Windows Imaging Component).

HRESULT LoadBitmapFromStream(IStream* ipImageStream, IWICBitmapSource** lplpBitmapSource)
{
    // initialize return value

    if (!lplpBitmapSource)
        return E_POINTER;

    HRESULT hr = E_FAIL;
    *lplpBitmapSource = NULL;

    // load WIC's PNG decoder

    CComPtr<IWICBitmapDecoder> ipDecoder;
    if (FAILED(CoCreateInstance(CLSID_WICPngDecoder, NULL, CLSCTX_INPROC_SERVER, __uuidof(ipDecoder), reinterpret_cast<void**>(&ipDecoder))))
        return hr;

    // load the PNG

    if (FAILED(ipDecoder->Initialize(ipImageStream, WICDecodeMetadataCacheOnLoad)))
        return hr;

    // check for the presence of the first frame in the bitmap

    UINT nFrameCount = 0;
    if (FAILED(ipDecoder->GetFrameCount(&nFrameCount)) || nFrameCount != 1)
        return hr;

    // load the first frame (i.e., the image)

    CComPtr<IWICBitmapFrameDecode> ipFrame;
    if (FAILED(ipDecoder->GetFrame(0, &ipFrame)))
        return hr;

    // convert the image to 32bpp BGRA format with pre-multiplied alpha
    //   (it may not be stored in that format natively in the PNG resource,
    //   but we need this format to create the DIB to use on-screen)

    hr = WICConvertBitmapSource(GUID_WICPixelFormat32bppPBGRA, ipFrame, lplpBitmapSource);

    return hr;
}

HBITMAP CreateHBITMAP(IWICBitmapSource* ipBitmap)
{
    // initialize return value

    HBITMAP hbmp = NULL;

    // get image attributes and check for valid image

    UINT width = 0;
    UINT height = 0;
    if (FAILED(ipBitmap->GetSize(&width, &height)) || width == 0 || height == 0)
        return NULL;

    // prepare structure giving bitmap information (negative height indicates a top-down DIB)

    BITMAPINFO bminfo;
    ZeroMemory(&bminfo, sizeof(bminfo));
    bminfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bminfo.bmiHeader.biWidth = width;
    bminfo.bmiHeader.biHeight = -((LONG)height);
    bminfo.bmiHeader.biPlanes = 1;
    bminfo.bmiHeader.biBitCount = 32;
    bminfo.bmiHeader.biCompression = BI_RGB;

    // create a DIB section that can hold the image

    void* pvImageBits = NULL;
    HDC hdcScreen = GetDC(NULL);
    hbmp = CreateDIBSection(hdcScreen, &bminfo, DIB_RGB_COLORS, &pvImageBits, NULL, 0);
    ReleaseDC(NULL, hdcScreen);
    if (hbmp == NULL)
        return NULL;

    // extract the image into the HBITMAP

    const UINT cbStride = width * 4;
    const UINT cbImage = cbStride * height;
    if (FAILED(ipBitmap->CopyPixels(NULL, cbStride, cbImage, static_cast<BYTE*>(pvImageBits))))
    {
        // couldn't extract image; delete HBITMAP

        DeleteObject(hbmp);
        hbmp = NULL;
    }

    return hbmp;
}


HBITMAP LoadPNG(HINSTANCE hInstance, UINT id)
{
    CComPtr<IStream> lpStream;
    CreateStreamOnResource(hInstance, MAKEINTRESOURCE(id), L"PNG", &lpStream);
    if (lpStream)
    {
        CComPtr<IWICBitmapSource> pWicBitmap;
        LoadBitmapFromStream(lpStream, &pWicBitmap);
        if (pWicBitmap)
        {
            return CreateHBITMAP(pWicBitmap);
        }
    }
    return NULL;
}
