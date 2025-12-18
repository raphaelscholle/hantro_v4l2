#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

die() {
        echo "[error] $*" >&2
        exit 1
}

find_debugfs() {
        local mount_point=${DEBUGFS_MOUNT:-/sys/kernel/debug}
        if mountpoint -q "$mount_point"; then
                echo "$mount_point"
                return
        fi

        local found
        found=$(awk '$3=="debugfs" {print $2; exit}' /proc/mounts || true)
        if [ -n "$found" ]; then
            echo "$found"
            return
        fi

        die "debugfs is not mounted; mount -t debugfs none /sys/kernel/debug"
}

sanitized_pattern() {
        echo "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/[[:space:]-]/_/g' -e 's/[^a-z0-9_]/_/g'
}

list_instances() {
        local base="$1"
        for path in "$base"/instance.*; do
                [ -e "$path" ] || continue
                echo "$(basename "$path"): $(head -n 5 "$path/stats" | tr '\n' '; ' )"
        done
}

stat_value() {
        local file="$1" key="$2"
        awk -F': ' -v k="$key" 'tolower($1)==tolower(k) {print $2}' "$file"
}

select_instance() {
        local base="$1" instance_id="$2" match_pid="$3" match_comm="$4"
        local chosen=""
        for path in "$base"/instance.*; do
                [ -e "$path" ] || continue
                local sid pid comm type
                sid=$(basename "$path" | sed 's/instance\.//')
                if [ -n "$instance_id" ] && [ "$sid" != "$instance_id" ]; then
                        continue
                fi
                pid=$(stat_value "$path/stats" "pid")
                comm=$(stat_value "$path/stats" "comm")
                type=$(stat_value "$path/stats" "type")
                if [ "$type" != "encoder" ]; then
                        continue
                fi
                if [ -n "$match_pid" ] && [ "$pid" != "$match_pid" ]; then
                        continue
                fi
                if [ -n "$match_comm" ] && [[ "$comm" != *"$match_comm"* ]]; then
                        continue
                fi
                chosen="$path"
                break
        done

        echo "$chosen"
}

ctrl_file_by_pattern() {
        local ctrl_dir="$1" pattern="$2"
        local target=""
        for ctrl in "$ctrl_dir"/*; do
                [ -f "$ctrl" ] || continue
                local name
                name=$(basename "$ctrl")
                if [[ "$name" == *_cid_* ]] && [[ "$name" == *"$pattern"* ]]; then
                        target="$ctrl"
                        break
                fi
        done
        echo "$target"
}

ctrl_cid_from_controls() {
        local controls_file="$1" pattern="$2"
        awk -v pat="$pattern" 'BEGIN{IGNORECASE=1} $0 ~ pat { if (match($0,/\(0x[0-9a-fA-F]+\)/)) { cid=substr($0,RSTART+1,RLENGTH-2); print cid; exit } }' "$controls_file"
}

write_ctrl() {
        local inst="$1" name_pattern="$2" value="$3"
        local ctrl_dir="$inst/ctrl"
        local controls_file="$inst/controls"
        local file
        file=$(ctrl_file_by_pattern "$ctrl_dir" "$name_pattern")
        if [ -n "$file" ]; then
                echo "$value" > "$file"
                echo "set $(basename "$file") -> $(cat "$file")"
                return 0
        fi

        local cid
        cid=$(ctrl_cid_from_controls "$controls_file" "$name_pattern")
        if [ -n "$cid" ]; then
                local cid_lc=${cid,,}
                echo "${cid}=${value}" > "$inst/set_ctrl"
                local final_file
                final_file=$(ctrl_file_by_pattern "$ctrl_dir" "_cid_${cid_lc#0x}")
                if [ -n "$final_file" ]; then
                        echo "set ${cid} -> $(cat "$final_file")"
                else
                        echo "set ${cid}"
                fi
                return 0
        fi

        echo "[warn] control matching '$name_pattern' not found" >&2
        return 1
}

set_rc_mode() {
        local inst="$1" mode="$2"
        local value
        case "$mode" in
                cbr) value=1 ;;
                vbr) value=0 ;;
                *) die "unknown rc mode $mode" ;;
        esac
        write_ctrl "$inst" "bitrate_mode" "$value"
}

set_bitrate() {
        local inst="$1" bitrate="$2"
        write_ctrl "$inst" "bitrate" "$bitrate"
}

set_gop() {
        local inst="$1" gop="$2"
        write_ctrl "$inst" "gop" "$gop"
}

set_fps() {
        local inst="$1" fps="$2"
        local pattern
        pattern=$(sanitized_pattern "fps")
        write_ctrl "$inst" "$pattern" "$fps" || echo "[warn] fps control not found" >&2
}

set_qp_bound() {
        local inst="$1" which="$2" value="$3"
        local pattern="qp"
        if [ -n "$which" ]; then
                pattern="${which}_qp"
        fi
        write_ctrl "$inst" "$pattern" "$value"
}

show_help() {
        cat <<'USAGE'
Usage: vsi_enc_debugfs_ctl.sh [options]

Options:
  --list                         List debugfs encoder instances
  --instance <id>                Select instance by numeric id
  --match-pid <pid>              Select instance by pid
  --match-comm <substr>          Select instance whose comm contains substring
  --bitrate <bps>                Set bitrate
  --rc <cbr|vbr>                 Set bitrate mode
  --gop <frames>                 Set GOP size
  --fps <fps>                    Set framerate control if present
  --qp <val>                     Set generic QP control if present
  --min-qp <val>                 Set minimum QP if present
  --max-qp <val>                 Set maximum QP if present
USAGE
}

main() {
        local mount base do_list=false inst_id="" match_pid="" match_comm=""
        local bitrate="" rc="" gop="" fps="" qp="" qp_min="" qp_max=""

        while [ $# -gt 0 ]; do
                case "$1" in
                        --list) do_list=true ;;
                        --instance) inst_id="$2"; shift ;;
                        --match-pid) match_pid="$2"; shift ;;
                        --match-comm) match_comm="$2"; shift ;;
                        --bitrate) bitrate="$2"; shift ;;
                        --rc) rc="$2"; shift ;;
                        --gop) gop="$2"; shift ;;
                        --fps) fps="$2"; shift ;;
                        --qp) qp="$2"; shift ;;
                        --min-qp) qp_min="$2"; shift ;;
                        --max-qp) qp_max="$2"; shift ;;
                        -h|--help) show_help; exit 0 ;;
                        *) die "unknown option $1" ;;
                esac
                shift
        done

        mount=$(find_debugfs)
        base="$mount/vsi_v4l2"

        if [ "$do_list" = true ]; then
                list_instances "$base"
                [ -z "$bitrate$rc$gop$fps$qp$qp_min$qp_max" ] && exit 0
        fi

        local inst
        inst=$(select_instance "$base" "$inst_id" "$match_pid" "$match_comm")
        [ -n "$inst" ] || die "no matching instance found"

        echo "using instance: $(basename "$inst")"

        [ -n "$bitrate" ] && set_bitrate "$inst" "$bitrate"
        [ -n "$rc" ] && set_rc_mode "$inst" "$rc"
        [ -n "$gop" ] && set_gop "$inst" "$gop"
        [ -n "$fps" ] && set_fps "$inst" "$fps"
        [ -n "$qp" ] && set_qp_bound "$inst" "" "$qp"
        [ -n "$qp_min" ] && set_qp_bound "$inst" "min" "$qp_min"
        [ -n "$qp_max" ] && set_qp_bound "$inst" "max" "$qp_max"
}

main "$@"
