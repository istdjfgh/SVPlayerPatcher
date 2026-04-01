/*
 * memdump - Fast native memory dumper for x86_64 Android
 * Reads /proc/PID/mem regions into single output file.
 * Usage: memdump <PID> <output_file> [mode]
 *   mode=0 (default): 32-bit regions only (0x05000000-0x7F000000)
 *   mode=1: 64-bit regions only (>0x700000000000, anonymous rw-p >1MB)
 *   mode=2: both 32-bit and 64-bit regions
 * 
 * Compile: x86_64-linux-android21-clang -static -O2 -o memdump memdump.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#define MAX_REGIONS 2048
#define BUF_SIZE (256 * 1024)  /* 256KB read buffer */
#define MIN_SIZE  4096
#define MAX_SIZE  (512ULL * 1024 * 1024)
#define MERGE_GAP 65536  /* merge regions with gap <= 64KB */

/* Address ranges */
#define ADDR32_MIN  0x05000000ULL
#define ADDR32_MAX  0x7F000000ULL
#define ADDR64_MIN  0x700000000000ULL
#define ADDR64_MAX  0x800000000000ULL
#define ADDR64_MIN_SIZE (1024 * 1024)  /* Only 64-bit regions >= 1MB */

struct region {
    uint64_t start;
    uint64_t end;
};

static struct region regions[MAX_REGIONS];
static struct region merged[MAX_REGIONS];
static char buf[BUF_SIZE];

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: memdump <PID> <output_file> [mode]\n");
        fprintf(stderr, "  mode=0: 32-bit only (default)\n");
        fprintf(stderr, "  mode=1: 64-bit only (anonymous >1MB)\n");
        fprintf(stderr, "  mode=2: both\n");
        return 1;
    }

    int pid = atoi(argv[1]);
    const char *outfile = argv[2];
    int mode = (argc > 3) ? atoi(argv[3]) : 0;
    char idxfile[512];
    snprintf(idxfile, sizeof(idxfile), "%s.idx", outfile);

    /* Phase 1: Parse /proc/PID/maps */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
        return 1;
    }

    int nregions = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps) && nregions < MAX_REGIONS) {
        uint64_t start, end;
        char perms[8];
        char rest[256] = "";
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %*s %*s %*s %255[^\n]", 
                   &start, &end, perms, rest) < 3)
            continue;

        /* Only rw-p regions */
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;

        uint64_t size = end - start;
        if (size < MIN_SIZE || size > MAX_SIZE)
            continue;

        int is_32bit = (start >= ADDR32_MIN && start <= ADDR32_MAX);
        int is_64bit = (start >= ADDR64_MIN && start <= ADDR64_MAX && 
                       size >= ADDR64_MIN_SIZE);

        /* For 64-bit mode, prefer anonymous regions (no pathname or [anon]) */
        if (is_64bit) {
            /* Trim whitespace from rest */
            char *p = rest;
            while (*p == ' ' || *p == '\t') p++;
            /* Skip non-anonymous (has path like /data/..., /system/...) */
            if (*p == '/' && strstr(p, "[anon") == NULL) {
                is_64bit = 0;
            }
        }

        int include = 0;
        if (mode == 0 && is_32bit) include = 1;
        if (mode == 1 && is_64bit) include = 1;
        if (mode == 2 && (is_32bit || is_64bit)) include = 1;

        if (!include)
            continue;

        regions[nregions].start = start;
        regions[nregions].end = end;
        nregions++;
    }
    fclose(maps);

    /* Phase 2: Sort regions by start address */
    for (int i = 0; i < nregions - 1; i++) {
        for (int j = i + 1; j < nregions; j++) {
            if (regions[j].start < regions[i].start) {
                struct region tmp = regions[i];
                regions[i] = regions[j];
                regions[j] = tmp;
            }
        }
    }

    /* Phase 3: Merge adjacent regions */
    int nmerged = 0;
    if (nregions > 0) {
        merged[0] = regions[0];
        nmerged = 1;
        for (int i = 1; i < nregions; i++) {
            if (regions[i].start <= merged[nmerged-1].end + MERGE_GAP) {
                /* Extend */
                if (regions[i].end > merged[nmerged-1].end)
                    merged[nmerged-1].end = regions[i].end;
            } else {
                merged[nmerged++] = regions[i];
            }
        }
    }

    uint64_t total_size = 0;
    for (int i = 0; i < nmerged; i++)
        total_size += merged[i].end - merged[i].start;

    fprintf(stderr, "mode=%d: %d regions -> %d merged (%" PRIu64 "MB)\n", 
            mode, nregions, nmerged, total_size / (1024*1024));

    /* Phase 4: FREEZE */
    kill(pid, SIGSTOP);

    /* Phase 5: Open /proc/PID/mem and dump */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
        kill(pid, SIGCONT);
        return 1;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, "Cannot create %s: %s\n", outfile, strerror(errno));
        close(mem_fd);
        kill(pid, SIGCONT);
        return 1;
    }

    FILE *idx = fopen(idxfile, "w");
    if (!idx) {
        fprintf(stderr, "Cannot create %s\n", idxfile);
        fclose(out);
        close(mem_fd);
        kill(pid, SIGCONT);
        return 1;
    }

    uint64_t file_off = 0;

    for (int i = 0; i < nmerged; i++) {
        uint64_t rstart = merged[i].start;
        uint64_t rsize = merged[i].end - merged[i].start;

        fprintf(idx, "%" PRIx64 " %" PRIu64 " %" PRIu64 "\n", rstart, rsize, file_off);

        /* Seek to region start (64-bit safe) */
        if (lseek64(mem_fd, (off64_t)rstart, SEEK_SET) == (off64_t)-1) {
            /* Fill with zeros if seek fails */
            memset(buf, 0, BUF_SIZE);
            uint64_t remaining = rsize;
            while (remaining > 0) {
                uint64_t chunk = remaining < BUF_SIZE ? remaining : BUF_SIZE;
                fwrite(buf, 1, (size_t)chunk, out);
                remaining -= chunk;
            }
            file_off += rsize;
            continue;
        }

        uint64_t remaining = rsize;
        while (remaining > 0) {
            uint64_t toread = remaining < BUF_SIZE ? remaining : BUF_SIZE;
            ssize_t rd = read(mem_fd, buf, (size_t)toread);
            if (rd <= 0) {
                /* Fill rest with zeros */
                memset(buf, 0, (size_t)toread);
                fwrite(buf, 1, (size_t)toread, out);
                remaining -= toread;
                continue;
            }
            fwrite(buf, 1, rd, out);
            remaining -= rd;
        }
        file_off += rsize;
    }

    fclose(out);
    fclose(idx);
    close(mem_fd);

    /* Phase 6: UNFREEZE */
    kill(pid, SIGCONT);

    /* Fix permissions */
    chmod(outfile, 0644);
    chmod(idxfile, 0644);

    fprintf(stderr, "OK %" PRIu64 " (%" PRIu64 "MB)\n", file_off, file_off / (1024*1024));
    /* Print for stdout parsing */
    printf("OK %" PRIu64 "\n", file_off);

    return 0;
}
