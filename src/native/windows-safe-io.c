#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PATH_CAP 32767
#define FRAME_CAP (64 * 1024)

typedef union {
    DWORD alignment;
    BYTE bytes[SECURITY_MAX_SID_SIZE];
} builtin_sid;

typedef struct {
    TOKEN_USER *user;
    builtin_sid system;
    builtin_sid admins;
} trusted_sids;

// Each invocation performs one operation. Native paths carry the verbatim
// prefix, which avoids a second round of Win32 dot/space/device normalization.
static WCHAR canonical[PATH_CAP];
static WCHAR candidate[PATH_CAP];
static WCHAR resolved[PATH_CAP];
static char utf8[4 * PATH_CAP];

static BOOL reject(const char *reason, DWORD code)
{
    fprintf(stderr, "%s (Win32 %lu)\n", reason, (unsigned long)code);
    return FALSE;
}

static BOOL read_token(trusted_sids *sids)
{
    HANDLE token;
    DWORD size = 0;
    DWORD system_size = sizeof(sids->system.bytes);
    DWORD admins_size = sizeof(sids->admins.bytes);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size) sids->user = malloc(size);
    BOOL success = sids->user &&
        GetTokenInformation(token, TokenUser, sids->user, size, &size) &&
        IsValidSid(sids->user->User.Sid) &&
        CreateWellKnownSid(WinLocalSystemSid, NULL, sids->system.bytes, &system_size) &&
        CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sids->admins.bytes, &admins_size);
    CloseHandle(token);
    return success;
}

static BOOL trusted_sid(PSID sid, const trusted_sids *sids)
{
    return EqualSid(sid, sids->user->User.Sid) ||
        EqualSid(sid, (PSID)sids->system.bytes) ||
        EqualSid(sid, (PSID)sids->admins.bytes);
}

static const char *principal_kind(PSID sid)
{
    if (IsWellKnownSid(sid, WinWorldSid)) return "Everyone (S-1-1-0)";
    if (IsWellKnownSid(sid, WinAuthenticatedUserSid)) return "Authenticated Users (S-1-5-11)";
    if (IsWellKnownSid(sid, WinBuiltinUsersSid)) return "Builtin Users (S-1-5-32-545)";
    if (IsWellKnownSid(sid, WinCreatorOwnerSid)) return "Creator Owner (S-1-3-0)";
    if (IsWellKnownSid(sid, WinCreatorGroupSid)) return "Creator Group (S-1-3-1)";
    return "other Windows principal";
}

static BOOL trusted_dacl(HANDLE handle, const WCHAR *path, const trusted_sids *sids, BOOL intermediate)
{
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &descriptor);
    char problem[256] = "";
    if (result != ERROR_SUCCESS) {
        snprintf(problem, sizeof(problem), "could not query directory ACL (Win32 %lu)", (unsigned long)result);
        goto done;
    }
    if (!owner || !IsValidSid(owner)) {
        strcpy_s(problem, sizeof(problem), "directory ACL has no valid owner SID");
        goto done;
    }
    if (!trusted_sid(owner, sids)) {
        snprintf(problem, sizeof(problem), "untrusted directory ACL owner: %s", principal_kind(owner));
        goto done;
    }
    if (!dacl || !IsValidAcl(dacl)) {
        strcpy_s(problem, sizeof(problem), "missing or invalid directory DACL");
        goto done;
    }

    // Appending subdirectories at an intermediate directory is safe because
    // the next entry is independently checked before use. FILE_ADD_FILE is
    // FILE_WRITE_DATA and could let an untrusted principal set a reparse point.
    DWORD permitted = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    if (intermediate) permitted |= FILE_ADD_SUBDIRECTORY;
    GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void *entry = NULL;
        if (!GetAce(dacl, index, &entry)) {
            snprintf(problem, sizeof(problem), "could not inspect directory ACL entry (Win32 %lu)", (unsigned long)GetLastError());
            goto done;
        }
        const ACE_HEADER *header = entry;
        // Intermediate children get their own check. The final directory
        // must not pass unsafe rights to later writes by the caller.
        if (intermediate && (header->AceFlags & INHERIT_ONLY_ACE)) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            snprintf(problem, sizeof(problem), "unsupported directory ACL entry (type %u, flags 0x%02x)",
                (unsigned int)header->AceType, (unsigned int)header->AceFlags);
            goto done;
        }

        const ACCESS_ALLOWED_ACE *ace = entry;
        PSID principal = (PSID)&ace->SidStart;
        const size_t sid_offset = offsetof(ACCESS_ALLOWED_ACE, SidStart);
        if (header->AceSize < sid_offset + offsetof(SID, SubAuthority) ||
            header->AceSize < sid_offset + GetSidLengthRequired(((SID *)principal)->SubAuthorityCount) ||
            !IsValidSid(principal)) {
            strcpy_s(problem, sizeof(problem), "invalid directory ACL principal SID");
            goto done;
        }
        DWORD granted = ace->Mask;
        MapGenericMask(&granted, &mapping);
        DWORD forbidden = granted & ~permitted;
        if (forbidden && !trusted_sid(principal, sids)) {
            snprintf(problem, sizeof(problem), "untrusted directory ACL grant to %s (granted 0x%08lx, forbidden 0x%08lx, flags 0x%02x)",
                principal_kind(principal), (unsigned long)granted, (unsigned long)forbidden, (unsigned int)header->AceFlags);
            goto done;
        }
    }

done:
    if (descriptor) LocalFree(descriptor);
    if (!problem[0]) return TRUE;
    int converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path + 4, -1,
        utf8, sizeof(utf8), NULL, NULL);
    fprintf(stderr, "%s at \"%s\"\n", problem, converted ? utf8 : "(directory path unavailable)");
    return FALSE;
}

static BOOL private_attributes(const trusted_sids *sids, BOOL directory, SECURITY_ATTRIBUTES *attributes)
{
    LPWSTR user = NULL;
    WCHAR sddl[256];
    const WCHAR *flags = directory ? L"OICI" : L"";
    if (!ConvertSidToStringSidW(sids->user->User.Sid, &user)) return FALSE;
    int count = swprintf(sddl, _countof(sddl), L"D:P(A;%ls;FA;;;SY)(A;%ls;FA;;;BA)(A;%ls;FA;;;%ls)",
        flags, flags, flags, user);
    LocalFree(user);
    if (count < 0) return FALSE;
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
        &attributes->lpSecurityDescriptor, NULL);
}

static BOOL valid_component(const WCHAR *name, size_t length)
{
    if (!length || length > 255 || name[length - 1] == L'.' || name[length - 1] == L' ') return FALSE;
    for (size_t i = 0; i < length; ++i) {
        if (name[i] < 32 || wcschr(L"<>:\"/\\|?*", name[i])) return FALSE;
    }
    return TRUE;
}

static BOOL append_component(const WCHAR *name, size_t length)
{
    size_t prefix = wcslen(canonical);
    BOOL separator = canonical[prefix - 1] != L'\\';
    if (prefix + (size_t)separator + length >= PATH_CAP) return FALSE;
    memcpy(candidate, canonical, prefix * sizeof(WCHAR));
    if (separator) candidate[prefix++] = L'\\';
    memcpy(candidate + prefix, name, length * sizeof(WCHAR));
    candidate[prefix + length] = L'\0';
    return TRUE;
}

static BOOL fixed_ntfs(HANDLE handle, const WCHAR *drive)
{
    DWORD flags;
    WCHAR filesystem[32];
    return GetDriveTypeW(drive) == DRIVE_FIXED &&
        GetVolumeInformationByHandleW(handle, NULL, 0, NULL, NULL, &flags, filesystem, _countof(filesystem)) &&
        (flags & FILE_PERSISTENT_ACLS) && wcscmp(filesystem, L"NTFS") == 0;
}

static HANDLE open_directory(const WCHAR *path)
{
    // Holding a non-delete-shared handle pins each checked ancestor throughout
    // this invocation. The ACL independently forbids foreign reparse changes.
    return CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}

static BOOL walk(const WCHAR *path, BOOL create, const trusted_sids *sids,
    SECURITY_ATTRIBUTES *directory_attributes, HANDLE *ancestors, size_t *opened)
{
    WCHAR drive[] = { path[0], L':', L'\\', L'\0' };
    memcpy(candidate, L"\\\\?\\", 4 * sizeof(WCHAR));
    memcpy(candidate + 4, drive, sizeof(drive));

    const WCHAR *name = path + 3;
    size_t parent_prefix = 0;
    for (;;) {
        HANDLE handle = open_directory(candidate);
        if (handle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (!create || !*opened || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)) {
                return reject("could not open directory", error);
            }
            if (!CreateDirectoryW(candidate, directory_attributes) && GetLastError() != ERROR_ALREADY_EXISTS) {
                return reject("could not create private directory", GetLastError());
            }
            handle = open_directory(candidate);
            if (handle == INVALID_HANDLE_VALUE) return reject("could not open created directory", GetLastError());
        }
        ancestors[(*opened)++] = handle;

        FILE_ATTRIBUTE_TAG_INFO attributes;
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes))) {
            return reject("could not inspect directory attributes", GetLastError());
        }
        if (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            return reject("directory reparse point", ERROR_ACCESS_DENIED);
        }
        if (!(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            return reject("path component is not a directory", ERROR_DIRECTORY);
        }
        DWORD length = GetFinalPathNameByHandleW(handle, resolved, _countof(resolved), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!length || length >= _countof(resolved)) return reject("could not canonicalize directory", GetLastError());

        if (parent_prefix == 0) {
            if (CompareStringOrdinal(candidate, -1, resolved, -1, TRUE) != CSTR_EQUAL || !fixed_ntfs(handle, drive)) {
                return reject("Windows ACL trust requires a local fixed NTFS drive root", ERROR_NOT_SUPPORTED);
            }
        } else if (length <= parent_prefix || wcsncmp(candidate, resolved, parent_prefix) != 0 ||
                   !valid_component(resolved + parent_prefix, (size_t)length - parent_prefix)) {
            return reject("directory resolved outside the checked ancestor", ERROR_ACCESS_DENIED);
        }
        if (!trusted_dacl(handle, resolved, sids, *name != L'\0')) return FALSE;
        memcpy(canonical, resolved, ((size_t)length + 1) * sizeof(WCHAR));

        if (!*name) return TRUE;
        const WCHAR *separator = wcschr(name, L'\\');
        size_t name_length = separator ? (size_t)(separator - name) : wcslen(name);
        if (!valid_component(name, name_length) || !append_component(name, name_length)) {
            return reject("unsafe directory component", ERROR_INVALID_NAME);
        }
        parent_prefix = (size_t)length + (canonical[length - 1] != L'\\' ? 1u : 0u);
        name = separator ? separator + 1 : name + name_length;
    }
}

static BOOL read_pipe(HANDLE pipe, BYTE *buffer, DWORD count)
{
    while (count) {
        DWORD received;
        if (!ReadFile(pipe, buffer, count, &received, NULL) || !received) return FALSE;
        buffer += received;
        count -= received;
    }
    return TRUE;
}

static BOOL write_frames(HANDLE file)
{
    HANDLE pipe = GetStdHandle(STD_INPUT_HANDLE);
    BYTE buffer[FRAME_CAP];
    for (;;) {
        BYTE frame[4];
        if (!read_pipe(pipe, frame, sizeof(frame))) return reject("incomplete input stream", ERROR_HANDLE_EOF);
        DWORD length = (DWORD)frame[0] | ((DWORD)frame[1] << 8) |
            ((DWORD)frame[2] << 16) | ((DWORD)frame[3] << 24);
        if (!length) return TRUE;
        if (length > sizeof(buffer) || !read_pipe(pipe, buffer, length)) {
            return reject("incomplete or invalid input frame", ERROR_INVALID_DATA);
        }
        DWORD written;
        if (!WriteFile(file, buffer, length, &written, NULL) || written != length) {
            return reject("could not write private temporary file", GetLastError());
        }
    }
}

static BOOL replace_file(const WCHAR *name, const WCHAR *temporary, HANDLE directory, SECURITY_ATTRIBUTES *attributes)
{
    size_t length = wcslen(name), temp_length = wcslen(temporary);
    if (!valid_component(name, length) || !valid_component(temporary, temp_length) ||
        !append_component(temporary, temp_length)) return reject("unsafe output filename", ERROR_INVALID_NAME);
    const DWORD info_size = (DWORD)(sizeof(FILE_RENAME_INFO) + length * sizeof(WCHAR));
    FILE_RENAME_INFO *info = calloc(1, info_size);
    if (!info) return reject("could not allocate rename information", ERROR_OUTOFMEMORY);
    info->ReplaceIfExists = TRUE;
    info->RootDirectory = directory;
    info->FileNameLength = (DWORD)(length * sizeof(WCHAR));
    memcpy(info->FileName, name, (length + 1) * sizeof(WCHAR));

    HANDLE file = CreateFileW(candidate, GENERIC_WRITE | DELETE, 0, attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BOOL success = FALSE;
    if (file == INVALID_HANDLE_VALUE) {
        reject("could not create private temporary file", GetLastError());
    } else {
        success = write_frames(file);
        if (success && !FlushFileBuffers(file)) success = reject("could not flush private temporary file", GetLastError());
        if (success && !SetFileInformationByHandle(file, FileRenameInfo, info, info_size)) {
            success = reject("could not replace report entry", GetLastError());
        }
        if (!success) {
            FILE_DISPOSITION_INFO cleanup = { TRUE };
            if (!SetFileInformationByHandle(file, FileDispositionInfo, &cleanup, sizeof(cleanup))) {
                reject("could not clean temporary file", GetLastError());
            }
        }
        CloseHandle(file);
    }
    free(info);
    return success;
}

int wmain(int argc, WCHAR **argv)
{
    if (argc < 3) return 2;
    BOOL create = wcscmp(argv[1], L"ensure") == 0;
    BOOL write = wcscmp(argv[1], L"write") == 0;
    if ((write && argc != 5) || (!write && (argc != 3 || (!create && wcscmp(argv[1], L"check") != 0)))) return 2;

    const WCHAR *path = argv[2];
    size_t length = wcslen(path);
    if (length < 3 || length >= PATH_CAP - 4 ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\' || (length > 3 && path[length - 1] == L'\\')) {
        reject("expected an absolute local drive path", ERROR_INVALID_NAME);
        return 2;
    }

    // CRT text output translates LF. Use byte output so Node can validate the protocol exactly.
    SECURITY_ATTRIBUTES attributes = { sizeof(attributes), NULL, FALSE };
    trusted_sids sids = {0};
    HANDLE *ancestors = calloc(length / 2 + 2, sizeof(HANDLE));
    size_t opened = 0;
    BOOL success = FALSE;
    if (!ancestors || !read_token(&sids) || ((create || write) && !private_attributes(&sids, create, &attributes))) {
        reject("could not initialize Windows ACL verification", GetLastError());
        goto done;
    }
    if (!walk(path, create, &sids, &attributes, ancestors, &opened)) goto done;
    if (write) {
        if (!replace_file(argv[3], argv[4], ancestors[opened - 1], &attributes)) goto done;
        const char message[] = "SEC_HUB_WRITE_OK\n";
        DWORD sent;
        success = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, sizeof(message) - 1, &sent, NULL) &&
            sent == sizeof(message) - 1;
    } else {
        const char marker[] = "SEC_HUB_PATH:";
        memcpy(utf8, marker, sizeof(marker) - 1);
        int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, canonical + 4, -1,
            utf8 + sizeof(marker) - 1, (int)(sizeof(utf8) - sizeof(marker)), NULL, NULL);
        if (!bytes) goto done;
        DWORD total = (DWORD)(sizeof(marker) - 1) + (DWORD)bytes;
        utf8[total - 1] = '\n';
        DWORD sent;
        success = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), utf8, total, &sent, NULL) && sent == total;
    }

done:
    while (opened) CloseHandle(ancestors[--opened]);
    free(ancestors);
    free(sids.user);
    if (attributes.lpSecurityDescriptor) LocalFree(attributes.lpSecurityDescriptor);
    return success ? 0 : 2;
}
