#!/system/bin/sh
# Fast heap dumper v3 - merges adjacent regions, fewer dd calls
# Usage: sh memdump.sh <PID> <output_file>

PID=$1
OUTFILE=$2

if [ -z "$PID" ] || [ -z "$OUTFILE" ]; then
    echo "Usage: sh memdump.sh <PID> <output_file>"
    exit 1
fi

IDXFILE="${OUTFILE}.idx"
TMPFILE="/data/local/tmp/_merge_regions.txt"

# Phase 1: collect all rw-p regions
RC=0
rm -f "$TMPFILE"
while IFS= read -r line; do
    PERMS=$(echo "$line" | awk '{print $2}')
    case "$PERMS" in *rw*) ;; *) continue ;; esac
    
    RANGE=$(echo "$line" | awk '{print $1}')
    START=$(echo "$RANGE" | cut -d- -f1)
    END=$(echo "$RANGE" | cut -d- -f2)
    
    [ ${#START} -gt 8 ] && continue
    
    START_DEC=$(printf "%d" "0x$START" 2>/dev/null)
    END_DEC=$(printf "%d" "0x$END" 2>/dev/null)
    SIZE=$((END_DEC - START_DEC))
    
    [ "$SIZE" -lt 4096 ] && continue
    [ "$SIZE" -gt 33554432 ] && continue
    [ "$START_DEC" -lt 83886080 ] && continue
    [ "$START_DEC" -gt 2130706432 ] && continue
    
    echo "$START_DEC $END_DEC" >> "$TMPFILE"
    RC=$((RC + 1))
done < "/proc/$PID/maps"

# Phase 2: merge adjacent regions (gap <= 64KB)
MERGED=""
MC=0
MSTART=0
MEND=0
while IFS= read -r line; do
    S=$(echo "$line" | awk '{print $1}')
    E=$(echo "$line" | awk '{print $2}')
    
    if [ "$MEND" -eq 0 ]; then
        MSTART=$S
        MEND=$E
    elif [ "$S" -le "$((MEND + 65536))" ]; then
        MEND=$E
    else
        MERGED="${MERGED}${MSTART}:${MEND} "
        MC=$((MC + 1))
        MSTART=$S
        MEND=$E
    fi
done < "$TMPFILE"
if [ "$MEND" -gt 0 ]; then
    MERGED="${MERGED}${MSTART}:${MEND} "
    MC=$((MC + 1))
fi
rm -f "$TMPFILE"

echo "$RC regions -> $MC merged"

# === FREEZE ===
kill -STOP "$PID"

# Phase 3: dump merged regions
rm -f "$OUTFILE" "$IDXFILE"
FILE_OFF=0
TOTAL=0
for R in $MERGED; do
    RSTART=$(echo "$R" | cut -d: -f1)
    REND=$(echo "$R" | cut -d: -f2)
    SIZE=$((REND - RSTART))
    SKIP=$((RSTART / 4096))
    PAGES=$((SIZE / 4096))
    
    ADDR=$(printf "%x" "$RSTART")
    dd if="/proc/$PID/mem" bs=4096 skip=$SKIP count=$PAGES 2>/dev/null >> "$OUTFILE"
    echo "$ADDR $SIZE $FILE_OFF" >> "$IDXFILE"
    FILE_OFF=$((FILE_OFF + SIZE))
    TOTAL=$((TOTAL + SIZE))
done

# === UNFREEZE ===
kill -CONT "$PID"

chmod 644 "$OUTFILE" "$IDXFILE" 2>/dev/null
echo "OK $FILE_OFF ($((TOTAL / 1048576))MB) freeze=$MC"
