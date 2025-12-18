# VSI V4L2 DebugFS controls

This driver exposes per-instance debugfs directories when `CONFIG_DEBUG_FS` is enabled. Mount debugfs if it is not already mounted:

```
mount -t debugfs none /sys/kernel/debug
```

Each active encoder/decoder context creates a directory under `/sys/kernel/debug/vsi_v4l2/` named `instance.<id>/`.

## Layout

* `stats` – read-only summary of context information (pid/tgid/comm, streaming state, flags, bitrate, rc mode, GOP size).
* `controls` – read-only dump of all V4L2 controls attached to the instance.
* `ctrl/` – directory containing one file per control. The filename is a sanitized control name with the control ID appended (e.g. `mpeg_video_bitrate_cid_009909b1`).
  * Reading a file shows the current value.
  * Writing a decimal or hexadecimal value updates the control live; encoder instances mark the configuration dirty so the backend is refreshed while streaming.
* `set_ctrl` – helper file to set a control by numeric ID. Write using `CID=VALUE` or `CID VALUE`.

Controls are handled through the V4L2 control framework, so all validation and clamping matches standard ioctl behaviour.

## Example usage

```
# List available instances
ls /sys/kernel/debug/vsi_v4l2

# Inspect stats for instance 1
cat /sys/kernel/debug/vsi_v4l2/instance.1/stats

# Show available controls
cat /sys/kernel/debug/vsi_v4l2/instance.1/controls

# Update bitrate while streaming
echo 8000000 > /sys/kernel/debug/vsi_v4l2/instance.1/ctrl/mpeg_video_bitrate_cid_009909b1

# Or by ID via set_ctrl (CID 0x009909b1 is V4L2_CID_MPEG_VIDEO_BITRATE)
echo 0x009909b1=8000000 > /sys/kernel/debug/vsi_v4l2/instance.1/set_ctrl
```

## Convenience script

`tools/vsi_enc_debugfs_ctl.sh` provides a simple CLI for common encoder parameters (bitrate, bitrate mode, GOP size, etc.). Run `--list` to see active instances and select one via `--instance <id>`, `--match-pid <pid>`, or `--match-comm <substring>`.
