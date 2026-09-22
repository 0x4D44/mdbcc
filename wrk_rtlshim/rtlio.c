/* wrk_rtlshim/rtlio.c — mdbcc-built C reimplementation of the Borland RTL
 * low-level POSIX file I/O layer (open/read/write/close/lseek) the iostream
 * filebuf calls. The Borland originals are 32-bit assembly / .CAS over an
 * internal fd→OS-handle table, which mdbcc cannot assemble. This is a plain-C
 * equivalent layered directly on the Win32 file APIs — i.e. "OS resolved as
 * imports" (the GOAL's explicit exception) while keeping every byte mdbcc-built.
 * NOT an edit of the Borland oracle tree — a separate self-host shim added to
 * mdcw32.lib. C linkage (bare symbols) matches the filebuf callers exactly.
 *
 * Text mode follows Borland's low-level read/write contract closely enough for
 * iostream/filebuf: reads remove '\r' bytes and writes expand '\n' to "\r\n".
 */

typedef unsigned int u32;

/* Win32 file APIs — recognised by mdbcc as imports (__stdcall, __imp_*). */
void *CreateFileA(const char *name, u32 access, u32 share, void *sec,
                  u32 disp, u32 flags, void *templ);
int ReadFile(void *h, void *buf, u32 n, u32 *got, void *ov);
int WriteFile(void *h, const void *buf, u32 n, u32 *put, void *ov);
u32 SetFilePointer(void *h, long dist, long *disthi, u32 method);
int CloseHandle(void *h);

/* Borland <fcntl.h> __FLAT__ values. */
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_ACCMODE 3
#define O_CREAT 0x0100
#define O_TRUNC 0x0200
#define O_EXCL 0x0400
#define O_APPEND 0x0800
#define O_TEXT 0x4000
#define O_BINARY 0x8000

#define GENERIC_READ 0x80000000U
#define GENERIC_WRITE 0x40000000U
#define FILE_SHARE_RW 3
#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5
#define FILE_ATTR_NORMAL 0x80
#define INVALID_HANDLE ((void *)-1)
/* SEEK_SET/CUR/END (0/1/2) coincide with FILE_BEGIN/CURRENT/END. */

#define MAXFD 64
static void *g_fd[MAXFD]; /* fd → HANDLE; 0 = free. fd 0..2 reserved. */
static int g_mode[MAXFD]; /* Borland O_* mode flags for text/binary/append. */

int open(const char *path, int oflag, ...)
{
    u32 access, disp;
    void *h;
    int fd;
    int acc = oflag & O_ACCMODE;
    if (acc == O_RDONLY)
        access = GENERIC_READ;
    else if (acc == O_WRONLY)
        access = GENERIC_WRITE;
    else
        access = GENERIC_READ | GENERIC_WRITE;
    if (oflag & O_CREAT) {
        if (oflag & O_EXCL)
            disp = CREATE_NEW;
        else if (oflag & O_TRUNC)
            disp = CREATE_ALWAYS;
        else
            disp = OPEN_ALWAYS;
    } else if (oflag & O_TRUNC) {
        disp = TRUNCATE_EXISTING;
    } else {
        disp = OPEN_EXISTING;
    }
    if ((oflag & (O_TEXT | O_BINARY)) == 0)
        oflag |= O_TEXT;
    if ((oflag & O_BINARY) == 0)
        oflag |= O_TEXT;
    h = CreateFileA(path, access, FILE_SHARE_RW, 0, disp, FILE_ATTR_NORMAL, 0);
    if (h == INVALID_HANDLE)
        return -1;
    for (fd = 3; fd < MAXFD; fd++) {
        if (g_fd[fd] == 0) {
            g_fd[fd] = h;
            g_mode[fd] = oflag;
            if (oflag & O_APPEND)
                SetFilePointer(h, 0, 0, 2);
            return fd;
        }
    }
    CloseHandle(h);
    return -1;
}

int read(int fd, void *buf, unsigned len)
{
    u32 got = 0;
    unsigned out = 0;
    unsigned i;
    char *bytes = (char *)buf;
    if (fd < 0 || fd >= MAXFD || g_fd[fd] == 0)
        return -1;
    if (len == 0)
        return 0;
    if (!ReadFile(g_fd[fd], buf, (u32)len, &got, 0))
        return -1;
    if ((g_mode[fd] & O_TEXT) == 0)
        return (int)got;

    if (got != 0 && bytes[got - 1] == '\r') {
        u32 extra = 0;
        char next = 0;
        if (!ReadFile(g_fd[fd], &next, 1, &extra, 0))
            return -1;
        if (extra != 0)
            bytes[got - 1] = next;
    }

    for (i = 0; i < got; i++) {
        if (bytes[i] != '\r')
            bytes[out++] = bytes[i];
    }
    return (int)out;
}

int write(int fd, const void *buf, unsigned len)
{
    u32 put = 0;
    const char *bytes = (const char *)buf;
    unsigned i;
    if (fd < 0 || fd >= MAXFD || g_fd[fd] == 0)
        return -1;
    if ((g_mode[fd] & O_TEXT) != 0) {
        for (i = 0; i < len; i++) {
            if (bytes[i] == '\n') {
                char cr = '\r';
                if (!WriteFile(g_fd[fd], &cr, 1, &put, 0) || put != 1)
                    return -1;
            }
            if (!WriteFile(g_fd[fd], &bytes[i], 1, &put, 0) || put != 1)
                return -1;
        }
        return (int)len;
    }
    if (!WriteFile(g_fd[fd], buf, (u32)len, &put, 0))
        return -1;
    return (int)put;
}

long lseek(int fd, long offset, int whence)
{
    u32 r;
    if (fd < 0 || fd >= MAXFD || g_fd[fd] == 0)
        return -1L;
    r = SetFilePointer(g_fd[fd], offset, 0, (u32)whence);
    if (r == 0xFFFFFFFFU)
        return -1L;
    return (long)r;
}

int close(int fd)
{
    int ok;
    if (fd < 0 || fd >= MAXFD || g_fd[fd] == 0)
        return -1;
    ok = CloseHandle(g_fd[fd]) ? 0 : -1;
    g_fd[fd] = 0;
    g_mode[fd] = 0;
    return ok;
}

/* Per-handle MT locks — no-ops in this single-threaded self-host (Borland's
 * own _IO.H #defines them away in the non-MT build). */
void _lock_handle(int fd) { (void)fd; }
void _unlock_handle(int fd) { (void)fd; }
