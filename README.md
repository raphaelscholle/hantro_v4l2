# Runtime encoder control updates

This driver update allows live bitrate changes and on-demand IDR insertion to be
applied while the encoder is already streaming, avoiding STREAMOFF/STREAMON
cycles.

## Supported runtime controls
- `V4L2_CID_MPEG_VIDEO_BITRATE` – apply a new target bitrate during streaming.
- `V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME` – request an immediate IDR.
- `V4L2_CID_VSI_FORCE_IDR` – driver-private button that mirrors the standard
  force keyframe control.

## Example usage
```bash
# Update bitrate without restarting the pipeline
v4l2-ctl -d /dev/videoX --set-ctrl=video_bitrate=8000000

# Force an IDR while streaming
v4l2-ctl -d /dev/videoX --set-ctrl=video_force_key_frame=1
# Or using the private IDR button
v4l2-ctl -d /dev/videoX --set-ctrl=vsi_force_idr=1
```

GStreamer pipelines that keep streaming (e.g. using `v4l2src` or `v4l2h264enc`)
benefit automatically; the driver pushes updates to the firmware without
requiring a pipeline restart.

## Notes
- Runtime updates reuse the existing daemon/firmware UPDATE_INFO command path.
- Firmware is expected to honor bitrate and IDR updates mid-stream; no userspace
  changes are required.
