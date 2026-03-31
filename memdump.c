/*
 * memdump - Fast native memory dumper for x86_64 Android
 * Reads /proc/PID/mem regions into single output file.
 * Usage: memdump <PID> <output_file>
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

#define MAX_REGIONS 1024
#define BUF_SIZE (256 * 1024)  /* 256KB read buffer */
#define MIN_ADDR  0x05000000UL
#define MAX_ADDR  0x7F000000UL
#define MIN_SIZE  4096
#define MAX_SIZE  (512 * 1024 * 1024)
#define MERGE_GAP 65536  /* merge regions with gap <= 64KB */

struct region {
    unsigned long start;
    unsigned long end;
};

static struct region regions[MAX_REGIONS];
static struct region merged[MAX_REGIONS];
static char buf[BUF_SIZE];

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: memdump <PID> <output_file>\n");
        return 1;
    }

    int pid = atoi(argv[1]);
    const char *outfile = argv[2];
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
        unsigned long start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        /* Only rw-p regions */
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;

        /* Skip 64-bit addresses (> 32-bit range) */
        if (start > 0xFFFFFFFF)
            continue;

        unsigned long size = end - start;
        if (size < MIN_SIZE || size > MAX_SIZE)
            continue;
        if (start < MIN_ADDR || start > MAX_ADDR)
            continue;

        regions[nregions].start = start;
        regions[nregions].end = end;
        nregions++;
    }
    fclose(maps);

    /* Phase 2: Merge adjacent regions */
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

    unsigned long total_size = 0;
    for (int i = 0; i < nmerged; i++)
        total_size += merged[i].end - merged[i].start;

    fprintf(stderr, "%d regions -> %d merged (%luMB)\n", 
            nregions, nmerged, total_size / (1024*1024));

    /* Phase 3: FREEZE */
    kill(pid, SIGSTOP);

    /* Phase 4: Open /proc/PID/mem and dump */
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

    unsigned long file_off = 0;

    for (int i = 0; i < nmerged; i++) {
        unsigned long rstart = merged[i].start;
        unsigned long rsize = merged[i].end - merged[i].start;

        fprintf(idx, "%lx %lu %lu\n", rstart, rsize, file_off);

        /* Seek to region start */
        if (lseek(mem_fd, (off_t)rstart, SEEK_SET) == (off_t)-1) {
            /* Fill with zeros if seek fails */
            memset(buf, 0, BUF_SIZE);
            unsigned long remaining = rsize;
            while (remaining > 0) {
                unsigned long chunk = remaining < BUF_SIZE ? remaining : BUF_SIZE;
                fwrite(buf, 1, chunk, out);
                remaining -= chunk;
            }
            file_off += rsize;
            continue;
        }

        unsigned long remaining = rsize;
        while (remaining > 0) {
            unsigned long toread = remaining < BUF_SIZE ? remaining : BUF_SIZE;
            ssize_t rd = read(mem_fd, buf, toread);
            if (rd <= 0) {
                /* Fill rest with zeros */
                memset(buf, 0, toread);
                fwrite(buf, 1, toread, out);
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

    /* Phase 5: UNFREEZE */
    kill(pid, SIGCONT);

    /* Fix permissions */
    chmod(outfile, 0644);
    chmod(idxfile, 0644);

    fprintf(stderr, "OK %lu (%luMB)\n", file_off, file_off / (1024*1024));
    /* Print for stdout parsing */
    printf("OK %lu\n", file_off);

    return 0;
}
