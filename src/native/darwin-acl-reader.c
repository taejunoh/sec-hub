/* Read-only macOS ACL policy check. Input: inherited directory descriptor 3.
 * No pathname lookup, environment configuration, file writes or subprocesses.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static int fail(const char *stage, int error) {
    fprintf(stderr, "sec-hub ACL: %s (errno=%d)\n", stage, error);
    return 2;
}

static int confirm_absent_acl(int fd, const struct stat *entry) {
    /* acl_get_fd_np reports ENOENT both when its filesec ACL property is absent
     * and on genuine failure. Never infer absence from that errno alone. */
    filesec_t security = filesec_init();
    if (security == NULL) return fail("security allocation failed", errno);
    struct stat observed;
    uid_t owner;
    mode_t mode;
    int present = -1, status = 0;
    if (fstatx_np(fd, &observed, security) != 0 ||
        filesec_get_property(security, FILESEC_OWNER, &owner) != 0 ||
        filesec_get_property(security, FILESEC_MODE, &mode) != 0 ||
        filesec_query_property(security, FILESEC_ACL, &present) != 0) {
        status = fail("native ACL absence query failed", errno);
    } else if (present != 0 || observed.st_dev != entry->st_dev ||
               observed.st_ino != entry->st_ino || owner != entry->st_uid ||
               mode != entry->st_mode) {
        status = fail("native ACL absence not established", EINVAL);
    }
    filesec_free(security);
    return status;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return fail("unexpected arguments", EINVAL);
    struct stat entry;
    if (fstat(3, &entry) != 0) return fail("directory fstat failed", errno);
    if (!S_ISDIR(entry.st_mode)) return fail("descriptor is not a directory", ENOTDIR);
    if ((entry.st_uid != 0 && entry.st_uid != geteuid()) || (entry.st_mode & 0022))
        return fail("untrusted directory owner or mode", EACCES);

    acl_t acl = acl_get_fd_np(3, ACL_TYPE_EXTENDED);
    int status = 0;
    if (acl == NULL) {
        if (errno != ENOENT) status = fail("native ACL query failed", errno);
        else status = confirm_absent_acl(3, &entry);
    } else if (acl_valid(acl) != 0) {
        status = fail("invalid native ACL", errno);
    } else {
        acl_entry_t ace;
        int cursor = ACL_FIRST_ENTRY;
        for (;;) {
            errno = 0;
            if (acl_get_entry(acl, cursor, &ace) != 0) {
                /* Darwin documents EINVAL for exhaustion of a validated ACL.
                 * This is an owned in-memory copy, not a live ACL iterator. */
                if (errno != EINVAL) status = fail("ACL iteration failed", errno);
                break;
            }
            acl_tag_t tag;
            if (acl_get_tag_type(ace, &tag) != 0) {
                status = fail("ACL tag query failed", errno);
                break;
            }
            if (tag != ACL_EXTENDED_DENY) {
                status = fail("allow or unknown ACL entry rejected", EACCES);
                break;
            }
            cursor = ACL_NEXT_ENTRY;
        }
    }
    if (acl != NULL && acl_free(acl) != 0 && status == 0) status = fail("ACL release failed", errno);
    if (close(3) != 0 && status == 0) status = fail("descriptor close failed", errno);
    if (status != 0) return status;
    if (fputs("SEC_HUB_ACL_OK\n", stdout) == EOF || fflush(stdout) != 0)
        return fail("attestation output failed", errno);
    return 0;
}
