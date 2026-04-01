/*
 * memscan - On-device float pair scanner for x86_64 Android
 * Scans /proc/PID/mem directly without dumping to file.
 * 
 * Usage: memscan <PID> <mode> <command> [args...]
 * 
 * Modes:
 *   0 = 32-bit regions
 *   1 = 64-bit regions (anonymous rw-p >1MB)
 *   2 = both
 *
 * Commands:
 *   fpairs <minX> <maxX> <minY> <maxY>
 *     Find adjacent float32 pairs where X in [minX,maxX] and Y in [minY,maxY]
 *     Output: hex_address X Y (one per line)
 *
 *   snap <outfile>
 *     Take a snapshot (same as memdump) for later diffing
 *
 *   diff <snap1> <snap2>
 *     Compare two snapshots, output changed float pairs in coordinate range
 *     Reads .idx files to map file offsets to virtual addresses
 *
 *   newpairs <snap1> <snap2> <minX> <maxX> <minY> <maxY>
 *     Find float pairs that exist in snap2 but NOT in snap1
 *     (i.e., newly appeared coordinate pairs after an action like firing)
 *
 * Compile: x86_64-linux-android21-clang -static -O2 -o memscan memscan.c -lm
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
#include <math.h>

#define MAX_REGIONS 2048
#define BUF_SIZE (1024 * 1024)  /* 1MB read buffer for speed */
#define MIN_SIZE  4096
#define MAX_SIZE  (512ULL * 1024 * 1024)
#define MERGE_GAP 65536

#define ADDR32_MIN  0x05000000ULL
#define ADDR32_MAX  0x7F000000ULL
#define ADDR64_MIN  0x700000000000ULL
#define ADDR64_MAX  0x800000000000ULL
#define ADDR64_MIN_SIZE (1024 * 1024)

struct region {
    uint64_t start;
    uint64_t end;
};

static struct region regions[MAX_REGIONS];
static struct region merged[MAX_REGIONS];
static char buf[BUF_SIZE];

/* Parse /proc/PID/maps and return merged regions */
static int parse_maps(int pid, int mode, int *out_nmerged) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
        return -1;
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

        if (perms[0] != 'r' || perms[1] != 'w')
            continue;

        uint64_t size = end - start;
        if (size < MIN_SIZE || size > MAX_SIZE)
            continue;

        int is_32bit = (start >= ADDR32_MIN && start <= ADDR32_MAX);
        int is_64bit = (start >= ADDR64_MIN && start <= ADDR64_MAX &&
                       size >= ADDR64_MIN_SIZE);

        if (is_64bit) {
            char *p = rest;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '/' && strstr(p, "[anon") == NULL) {
                is_64bit = 0;
            }
        }

        int include = 0;
        if (mode == 0 && is_32bit) include = 1;
        if (mode == 1 && is_64bit) include = 1;
        if (mode == 2 && (is_32bit || is_64bit)) include = 1;

        if (!include) continue;

        regions[nregions].start = start;
        regions[nregions].end = end;
        nregions++;
    }
    fclose(maps);

    /* Sort */
    for (int i = 0; i < nregions - 1; i++) {
        for (int j = i + 1; j < nregions; j++) {
            if (regions[j].start < regions[i].start) {
                struct region tmp = regions[i];
                regions[i] = regions[j];
                regions[j] = tmp;
            }
        }
    }

    /* Merge */
    int nmerged = 0;
    if (nregions > 0) {
        merged[0] = regions[0];
        nmerged = 1;
        for (int i = 1; i < nregions; i++) {
            if (regions[i].start <= merged[nmerged-1].end + MERGE_GAP) {
                if (regions[i].end > merged[nmerged-1].end)
                    merged[nmerged-1].end = regions[i].end;
            } else {
                merged[nmerged++] = regions[i];
            }
        }
    }

    *out_nmerged = nmerged;

    uint64_t total = 0;
    for (int i = 0; i < nmerged; i++)
        total += merged[i].end - merged[i].start;
    fprintf(stderr, "mode=%d: %d regions -> %d merged (%" PRIu64 "MB)\n",
            mode, nregions, nmerged, total / (1024*1024));

    return 0;
}

/* Check if float is a valid coordinate */
static inline int is_coord(float val, float mn, float mx) {
    if (isnan(val) || isinf(val)) return 0;
    return (val >= mn && val <= mx);
}

/*
 * Command: fpairs - scan memory for float pairs in coordinate range
 */
static int cmd_fpairs(int pid, int nmerged, float minX, float maxX, float minY, float maxY) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    /* Freeze process */
    kill(pid, SIGSTOP);
    usleep(50000); /* 50ms settle */

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
        kill(pid, SIGCONT);
        return 1;
    }

    int found = 0;

    for (int i = 0; i < nmerged; i++) {
        uint64_t rstart = merged[i].start;
        uint64_t rsize = merged[i].end - merged[i].start;

        if (lseek64(mem_fd, (off64_t)rstart, SEEK_SET) == (off64_t)-1)
            continue;

        uint64_t offset = 0;
        /* Keep last 4 bytes from previous read for cross-boundary pairs */
        float prev_last = 0;
        int have_prev = 0;

        while (offset < rsize) {
            uint64_t toread = rsize - offset;
            if (toread > BUF_SIZE) toread = BUF_SIZE;

            ssize_t rd = read(mem_fd, buf, (size_t)toread);
            if (rd <= 0) break;

            /* Check cross-boundary pair */
            if (have_prev && rd >= 4) {
                float y;
                memcpy(&y, buf, 4);
                if (is_coord(prev_last, minX, maxX) && is_coord(y, minY, maxY)) {
                    uint64_t addr = rstart + offset - 4;
                    printf("%" PRIx64 " %.3f %.3f\n", addr, prev_last, y);
                    found++;
                }
            }

            /* Scan buffer for float pairs */
            int limit = (int)rd - 7; /* need at least 8 bytes for a pair */
            for (int j = 0; j <= limit; j += 4) {
                float x, y;
                memcpy(&x, buf + j, 4);
                memcpy(&y, buf + j + 4, 4);

                if (is_coord(x, minX, maxX) && is_coord(y, minY, maxY)) {
                    uint64_t addr = rstart + offset + j;
                    printf("%" PRIx64 " %.3f %.3f\n", addr, x, y);
                    found++;
                }
            }

            /* Save last float for cross-boundary check */
            if (rd >= 4) {
                memcpy(&prev_last, buf + rd - 4, 4);
                have_prev = 1;
            }

            offset += rd;
        }
    }

    close(mem_fd);
    kill(pid, SIGCONT);

    fprintf(stderr, "Found %d pairs\n", found);
    return 0;
}

/*
 * Command: snap - take a memory snapshot (freeze-dump-unfreeze)
 * Same as memdump but integrated
 */
static int cmd_snap(int pid, int nmerged, const char *outfile) {
    char idxfile[512];
    snprintf(idxfile, sizeof(idxfile), "%s.idx", outfile);

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    kill(pid, SIGSTOP);
    usleep(50000);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
        kill(pid, SIGCONT);
        return 1;
    }

    FILE *out = fopen(outfile, "wb");
    FILE *idx = fopen(idxfile, "w");
    if (!out || !idx) {
        fprintf(stderr, "Cannot create output files\n");
        if (out) fclose(out);
        if (idx) fclose(idx);
        close(mem_fd);
        kill(pid, SIGCONT);
        return 1;
    }

    uint64_t file_off = 0;
    for (int i = 0; i < nmerged; i++) {
        uint64_t rstart = merged[i].start;
        uint64_t rsize = merged[i].end - merged[i].start;

        fprintf(idx, "%" PRIx64 " %" PRIu64 " %" PRIu64 "\n", rstart, rsize, file_off);

        if (lseek64(mem_fd, (off64_t)rstart, SEEK_SET) == (off64_t)-1) {
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
    kill(pid, SIGCONT);

    chmod(outfile, 0644);
    chmod(idxfile, 0644);

    fprintf(stderr, "OK %" PRIu64 " (%" PRIu64 "MB)\n", file_off, file_off / (1024*1024));
    printf("OK %" PRIu64 "\n", file_off);
    return 0;
}

/*
 * Command: newpairs - find float pairs in snap2 that don't exist in snap1
 * Reads both snapshot files and their idx files
 */
static int cmd_newpairs(const char *snap1, const char *snap2,
                        float minX, float maxX, float minY, float maxY) {
    char idx1_path[512], idx2_path[512];
    snprintf(idx1_path, sizeof(idx1_path), "%s.idx", snap1);
    snprintf(idx2_path, sizeof(idx2_path), "%s.idx", snap2);

    /* We scan snap2 for float pairs in range, then check if the same
     * virtual address had the same values in snap1.
     * If different or new -> report as new pair.
     */

    /* Parse idx2 to get region mappings */
    FILE *idx2f = fopen(idx2_path, "r");
    if (!idx2f) {
        fprintf(stderr, "Cannot open %s\n", idx2_path);
        return 1;
    }

    struct { uint64_t vaddr; uint64_t size; uint64_t foff; } idx2[MAX_REGIONS];
    int nidx2 = 0;
    while (nidx2 < MAX_REGIONS) {
        uint64_t a, s, o;
        if (fscanf(idx2f, "%" SCNx64 " %" SCNu64 " %" SCNu64, &a, &s, &o) != 3)
            break;
        idx2[nidx2].vaddr = a;
        idx2[nidx2].size = s;
        idx2[nidx2].foff = o;
        nidx2++;
    }
    fclose(idx2f);

    /* Parse idx1 */
    FILE *idx1f = fopen(idx1_path, "r");
    if (!idx1f) {
        fprintf(stderr, "Cannot open %s\n", idx1_path);
        return 1;
    }

    struct { uint64_t vaddr; uint64_t size; uint64_t foff; } idx1[MAX_REGIONS];
    int nidx1 = 0;
    while (nidx1 < MAX_REGIONS) {
        uint64_t a, s, o;
        if (fscanf(idx1f, "%" SCNx64 " %" SCNu64 " %" SCNu64, &a, &s, &o) != 3)
            break;
        idx1[nidx1].vaddr = a;
        idx1[nidx1].size = s;
        idx1[nidx1].foff = o;
        nidx1++;
    }
    fclose(idx1f);

    /* Open both snapshot files */
    int fd1 = open(snap1, O_RDONLY);
    int fd2 = open(snap2, O_RDONLY);
    if (fd1 < 0 || fd2 < 0) {
        fprintf(stderr, "Cannot open snapshot files\n");
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        return 1;
    }

    /* For each region in snap2, scan for float pairs */
    int found = 0;
    static char buf2[BUF_SIZE];
    static char buf1_small[8]; /* Just need 8 bytes from snap1 for comparison */

    for (int r = 0; r < nidx2; r++) {
        uint64_t rvaddr = idx2[r].vaddr;
        uint64_t rsize = idx2[r].size;
        uint64_t rfoff = idx2[r].foff;

        /* Find corresponding region in snap1 */
        int r1_idx = -1;
        for (int k = 0; k < nidx1; k++) {
            if (idx1[k].vaddr == rvaddr) {
                r1_idx = k;
                break;
            }
        }

        /* Read snap2 region in chunks */
        if (lseek64(fd2, (off64_t)rfoff, SEEK_SET) == (off64_t)-1)
            continue;

        uint64_t offset = 0;
        while (offset < rsize) {
            uint64_t toread = rsize - offset;
            if (toread > BUF_SIZE) toread = BUF_SIZE;

            ssize_t rd = read(fd2, buf2, (size_t)toread);
            if (rd <= 0) break;

            int limit = (int)rd - 7;
            for (int j = 0; j <= limit; j += 4) {
                float x, y;
                memcpy(&x, buf2 + j, 4);
                memcpy(&y, buf2 + j + 4, 4);

                if (!is_coord(x, minX, maxX) || !is_coord(y, minY, maxY))
                    continue;

                /* This is a valid pair in snap2. Check snap1. */
                uint64_t vaddr = rvaddr + offset + j;
                int is_new = 1;

                if (r1_idx >= 0) {
                    /* Calculate file offset in snap1 */
                    uint64_t off_in_region = (vaddr - idx1[r1_idx].vaddr);
                    if (off_in_region + 8 <= idx1[r1_idx].size) {
                        uint64_t foff1 = idx1[r1_idx].foff + off_in_region;
                        if (lseek64(fd1, (off64_t)foff1, SEEK_SET) != (off64_t)-1) {
                            if (read(fd1, buf1_small, 8) == 8) {
                                float x1, y1;
                                memcpy(&x1, buf1_small, 4);
                                memcpy(&y1, buf1_small + 4, 4);
                                /* If same values in snap1, not new */
                                if (x1 == x && y1 == y) {
                                    is_new = 0;
                                }
                            }
                        }
                    }
                }

                if (is_new) {
                    printf("%" PRIx64 " %.3f %.3f\n", vaddr, x, y);
                    found++;
                }
            }

            offset += rd;
        }
    }

    close(fd1);
    close(fd2);

    fprintf(stderr, "Found %d new pairs\n", found);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: memscan <PID> <mode> <command> [args...]\n");
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  fpairs <minX> <maxX> <minY> <maxY>\n");
        fprintf(stderr, "  snap <outfile>\n");
        fprintf(stderr, "  newpairs <snap1> <snap2> <minX> <maxX> <minY> <maxY>\n");
        return 1;
    }

    int pid = atoi(argv[1]);
    int mode = atoi(argv[2]);
    const char *cmd = argv[3];

    /* Parse maps for fpairs and snap */
    if (strcmp(cmd, "fpairs") == 0) {
        if (argc < 8) {
            fprintf(stderr, "Usage: memscan <PID> <mode> fpairs <minX> <maxX> <minY> <maxY>\n");
            return 1;
        }
        int nmerged;
        if (parse_maps(pid, mode, &nmerged) < 0) return 1;
        float minX = atof(argv[4]);
        float maxX = atof(argv[5]);
        float minY = atof(argv[6]);
        float maxY = atof(argv[7]);
        return cmd_fpairs(pid, nmerged, minX, maxX, minY, maxY);
    }
    else if (strcmp(cmd, "snap") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: memscan <PID> <mode> snap <outfile>\n");
            return 1;
        }
        int nmerged;
        if (parse_maps(pid, mode, &nmerged) < 0) return 1;
        return cmd_snap(pid, nmerged, argv[4]);
    }
    else if (strcmp(cmd, "newpairs") == 0) {
        if (argc < 10) {
            fprintf(stderr, "Usage: memscan <PID> <mode> newpairs <snap1> <snap2> <minX> <maxX> <minY> <maxY>\n");
            return 1;
        }
        /* For newpairs we don't need to parse maps, we read from snapshot files */
        float minX = atof(argv[6]);
        float maxX = atof(argv[7]);
        float minY = atof(argv[8]);
        float maxY = atof(argv[9]);
        return cmd_newpairs(argv[4], argv[5], minX, maxX, minY, maxY);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }
}
