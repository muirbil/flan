#include <network/WinHTTP.hpp>
#include <string>
#include <urlmon.h>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma comment(lib, "urlmon.lib")

bool downloadFile(const std::string& url, const std::string& destination) {
	HRESULT hr = URLDownloadToFileA(
		NULL,
		url.c_str(),
		destination.c_str(),
		0,
		NULL
	);

	if (SUCCEEDED(hr)) {
		return true;
	} else {
		std::cerr << "Failed to download file! Error code: 0x\n" << std::hex << hr << destination << std::dec;
		return false;
	}
}