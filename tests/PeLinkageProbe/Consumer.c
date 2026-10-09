#include <windows.h>

__declspec(dllimport) int Add(int left, int right);
__declspec(dllimport) int OrdinalOnly(int value);

__declspec(dllexport) int Run(int value) {
    if (GetDesktopWindow() == NULL) {
        return -1;
    }

    return Add(value, 5) + OrdinalOnly(value);
}
