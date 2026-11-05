// Include the production operation so this probe tests the exact handle flags.
#define wmain sec_hub_safe_io_main
#include "../src/native/windows-safe-io.c"
#undef wmain

int wmain(int argc, WCHAR **argv)
{
    if (argc != 2) return 2;
    const WCHAR suffix[] = L".moved";
    size_t length = wcslen(argv[1]);
    if (length + _countof(suffix) > _countof(candidate)) return 2;
    memcpy(candidate, argv[1], length * sizeof(WCHAR));
    memcpy(candidate + length, suffix, sizeof(suffix));

    if (!CreateDirectoryW(argv[1], NULL)) {
        reject("could not create empty pin fixture", GetLastError());
        return 2;
    }
    HANDLE directory = open_directory(argv[1]);
    if (directory == INVALID_HANDLE_VALUE) {
        reject("could not open empty pin fixture", GetLastError());
        RemoveDirectoryW(argv[1]);
        return 2;
    }

    BOOL moved_while_open = MoveFileW(argv[1], candidate);
    DWORD blocked = moved_while_open ? ERROR_SUCCESS : GetLastError();
    CloseHandle(directory);
    if (moved_while_open) {
        RemoveDirectoryW(candidate);
        reject("empty directory moved while its native handle was open", ERROR_SUCCESS);
        return 2;
    }

    BOOL moved_after_close = MoveFileW(argv[1], candidate);
    DWORD move_error = moved_after_close ? ERROR_SUCCESS : GetLastError();
    if (!RemoveDirectoryW(moved_after_close ? candidate : argv[1])) {
        reject("could not clean empty pin fixture", GetLastError());
        return 2;
    }
    if (blocked != ERROR_SHARING_VIOLATION && blocked != ERROR_ACCESS_DENIED) {
        reject("unexpected failure while moving pinned empty directory", blocked);
        return 2;
    }
    if (!moved_after_close) {
        reject("could not move empty directory after native handle closed", move_error);
        return 2;
    }
    puts("Windows native empty directory pin passed");
    return 0;
}
