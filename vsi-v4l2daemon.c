/*
 *    VSI v4l2 message pipe manager.
 *
 *    Copyright (c) 2019, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/videodev2.h>
#include <linux/v4l2-dv-timings.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/io.h>
#include <linux/atomic.h>
#include <linux/lockdep.h>
#include <linux/sched.h>
#include <media/v4l2-device.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-dv-timings.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-event.h>
#include <media/videobuf2-v4l2.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-vmalloc.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include "vsi-v4l2-priv.h"

#define PIPE_DEVICE_NAME      "vsiv4l2daemon"

#if !defined(CONFIG_ANDROID)
#define CONFIG_INVOKE_VSIDAEMON		1
static bool invoke_vsidaemon = 1;
module_param(invoke_vsidaemon, bool, 0644);
#endif

static int loglevel;
module_param(loglevel, int, 0644);

static u64 g_seqid;
static struct idr *cmdarray, *retarray;
static atomic_t daemon_fn = ATOMIC_INIT(0);
static pid_t daemon_tgid = -1;
static DEFINE_MUTEX(daemon_lock);

static DECLARE_WAIT_QUEUE_HEAD(cmd_queue);
static struct mutex cmd_lock;
static DECLARE_WAIT_QUEUE_HEAD(ret_queue);
static DECLARE_WAIT_QUEUE_HEAD(instance_queue);
static struct mutex  ret_lock;
static s32 v4l2_fn;
static struct mutex instance_lock;

/*************************   for bandwith calc ***************************/
static u64 accubytes;
static struct timespec64 lasttime;
static u64 last_bandwidth;
/********************************************************************/

u64 vsi_v4l2_getbandwidth(void)
{
	struct timespec64 curtime;
	u64 gap, ret;

	if (v4l2_fn == 0)
		return last_bandwidth;

	ktime_get_real_ts64(&curtime);
	gap = curtime.tv_sec - lasttime.tv_sec;
	if (gap <= 0)
		gap = 1;
	ret = accubytes / gap;
	lasttime = curtime;
	accubytes = 0;
	return ret;
}

int vsi_v4l2_daemonalive(void)
{
	return (atomic_read(&daemon_fn) > 0);
}

void vsiv4l2_cleanupdaemon(void)
{
	int id;
	void *obj;

	if (mutex_lock_interruptible(&ret_lock))
		return;
	idr_for_each_entry(cmdarray, obj, id) {
		if (obj) {
			idr_remove(cmdarray, id);
			kfree(obj);
		}
	}
	idr_destroy(cmdarray);
	kfree(cmdarray);
	idr_for_each_entry(retarray, obj, id) {
		if (obj) {
			idr_remove(retarray, id);
			kfree(obj);
		}
	}
	idr_destroy(retarray);
	kfree(retarray);

	mutex_unlock(&ret_lock);

	unregister_chrdev(VSI_DAEMON_DEVMAJOR, PIPE_DEVICE_NAME);
}

int vsi_clear_daemonmsg(int instid)
{
	struct vsi_v4l2_msg *msg;
	void *obj;
	int id;

	if (mutex_lock_interruptible(&cmd_lock))
		return -EBUSY;
	idr_for_each_entry(cmdarray, obj, id) {
		if (obj) {
			msg = (struct vsi_v4l2_msg *)obj;
			if (msg->inst_id == instid) {
				v4l2_klog(LOGLVL_WARNING, "clear unused cmd %x:%lld:%d", instid, msg->seq_id, msg->cmd_id);
				idr_remove(cmdarray, id);
				kfree(obj);
			}
		}
	}
	mutex_unlock(&cmd_lock);
	if (mutex_lock_interruptible(&ret_lock))
		return -EBUSY;
	idr_for_each_entry(retarray, obj, id) {
		if (obj) {
			msg = (struct vsi_v4l2_msg *)obj;
			if (msg->inst_id == instid) {
				v4l2_klog(LOGLVL_WARNING, "clear unused msg %x:%lld:%d", instid, msg->seq_id, msg->cmd_id);
				idr_remove(retarray, id);
				kfree(obj);
			}
		}
	}
	mutex_unlock(&ret_lock);
	return 0;
}

static int getMsg(struct file *fh, char __user *buf, size_t size)
{
	int id, offset = 0;
	struct vsi_v4l2_msg *obj;

	if (mutex_lock_interruptible(&cmd_lock))
		return -EBUSY;
	idr_for_each_entry(cmdarray, obj, id) {
		if (offset >= size)
			break;
                if (obj) {
                        if (copy_to_user((void __user *)buf + offset, (void *)obj,
                                sizeof(struct vsi_v4l2_msg_hdr) + obj->size) != 0)
                                break;
                        v4l2_klog(LOGLVL_BRIEF, "%s: inst=%llx cmd=%d seq=%llx size=%d param=0x%x", __func__,
                                obj->inst_id, obj->cmd_id, obj->seq_id, obj->size, obj->param_type);
                        offset += sizeof(struct vsi_v4l2_msg_hdr) + obj->size;
			accubytes += sizeof(struct vsi_v4l2_msg_hdr) + obj->size;
			idr_remove(cmdarray, id);
			kfree(obj);
			break;
		}
	}
	mutex_unlock(&cmd_lock);
	return offset;
}

static int getRet(unsigned long seqid, int *error, s32 *retflag)
{
	int match = 0, id;
	struct vsi_v4l2_msg	*obj;

	if (atomic_read(&daemon_fn) <= 0) {
		*error = DAEMON_ERR_DAEMON_MISSING;
		return 1;
	}
	if (mutex_lock_interruptible(&ret_lock))
		return -EBUSY;
	idr_for_each_entry(retarray, obj, id) {
		if (obj) {
                        if (obj->seq_id == seqid) {
                                v4l2_klog(LOGLVL_BRIEF, "%s: inst=%llx cmd=%d seq=%llx err=%d param=0x%x", __func__,
                                        obj->inst_id, obj->cmd_id, obj->seq_id, obj->error, obj->param_type);
                                *error = obj->error;
                                *retflag = obj->param_type;
                                idr_remove(retarray, id);
                                kfree(obj);
                                match = 1;
                                break;
                        }
		}
	}
	mutex_unlock(&ret_lock);

	return match;
}

static int vsi_count_idr_entries(struct idr *idr, struct mutex *lock)
{
        int id, count = 0;
        void *obj;

        mutex_lock(lock);

        idr_for_each_entry(idr, obj, id) {
                if (obj)
                        count++;
        }
	mutex_unlock(lock);

	return count;
}

/* send msg from v4l2 driver to user space daemon */
static int vsi_v4l2_sendcmd(
        enum v4l2_daemon_cmd_id cmdid,
        unsigned long instid,
        int codecformat,
        void *msgcontent,
        s32 *retflag,
        int msgsize,
        u32 param_type)
{
        unsigned long mid;
        int error = 0;
        long wait_ret;
        struct vsi_v4l2_msg *pmsg;
        struct vsi_v4l2_msg_hdr *msghdr;

	if (atomic_read(&daemon_fn) <= 0)
		return DAEMON_ERR_DAEMON_MISSING;

	if (mutex_lock_interruptible(&cmd_lock))
		return -EBUSY;

        v4l2_klog(LOGLVL_FLOW, "%s enqueue inst=%lx cmd=%d param=0x%x size=%d", __func__, instid, cmdid,
                param_type, msgsize);
        if (msgsize == 0) {
                msghdr = kzalloc(sizeof(struct vsi_v4l2_msg_hdr), GFP_KERNEL);
                if (!msghdr) {
                        mutex_unlock(&cmd_lock);
                        return -ENOMEM;
		}
		msghdr->inst_id = instid;
		msghdr->cmd_id = cmdid;
		msghdr->codec_fmt = codecformat;
		msghdr->param_type = param_type;
                mid = msghdr->seq_id = g_seqid;
                if (idr_alloc(cmdarray, (void *)msghdr, 1, 0, GFP_KERNEL) < 0) {
                        kfree(msghdr);
                        mutex_unlock(&cmd_lock);
                        return -ENOMEM;
                }
        } else {
		pmsg = kzalloc(sizeof(struct vsi_v4l2_msg), GFP_KERNEL);
		if (!pmsg) {
			mutex_unlock(&cmd_lock);
			return -ENOMEM;
		}
		pmsg->inst_id = instid;
		pmsg->cmd_id = cmdid;
		pmsg->codec_fmt = codecformat;
		pmsg->param_type = param_type;
                mid = pmsg->seq_id = g_seqid;
                pmsg->size = msgsize;
                memcpy((void *)&pmsg->params, msgcontent, msgsize);
                if (idr_alloc(cmdarray, (void *)pmsg, 1, 0, GFP_KERNEL) < 0) {
                        kfree(pmsg);
                        mutex_unlock(&cmd_lock);
                        return -ENOMEM;
                }
        }
        v4l2_klog(LOGLVL_FLOW, "cmd queued inst=%lx cmd=%d seq=%llu codec=%d param=0x%x size=%d", instid, cmdid,
                (unsigned long long)mid, codecformat, param_type, msgsize);
        g_seqid++;
        if (g_seqid >= SEQID_UPLIMT)
                g_seqid = 1;
        mutex_unlock(&cmd_lock);
        wake_up_interruptible_all(&cmd_queue);

        if (cmdid != V4L2_DAEMON_VIDIOC_EXIT) {
                unsigned long timeout = msecs_to_jiffies(4000);
                unsigned long deadline = jiffies + timeout;

                do {
                        wait_ret = wait_event_interruptible_timeout(ret_queue,
                                        getRet(mid, &error, retflag) != 0, timeout);
                        if (wait_ret > 0)
                                break;

                        if (wait_ret == -ERESTARTSYS) {
                                v4l2_klog(LOGLVL_WARNING,
                                        "sendcmd interrupted cmd=%d inst=%lx seq=%llu pending_sig=%d",
                                        cmdid, instid, (unsigned long long)mid, signal_pending(current));
                                if (time_after(jiffies, deadline))
                                        break;
                                timeout = deadline - jiffies;
                                continue;
                        }

                        if (wait_ret == 0)
                                break;
                } while (timeout);

                if (wait_ret <= 0) {
                        int cmd_pending = vsi_count_idr_entries(cmdarray, &cmd_lock);
                        int ret_pending = vsi_count_idr_entries(retarray, &ret_lock);

                        v4l2_klog(LOGLVL_ERROR,
                                  "sendcmd wait failed cmd=%d inst=%lx seq=%llu ret=%ld daemon_fn=%d v4l2_fn=%d cmd_q=%d ret_q=%d",
                                  cmdid, instid, (unsigned long long)mid, wait_ret, atomic_read(&daemon_fn), v4l2_fn,
                                  cmd_pending, ret_pending);
                        return -ETIMEDOUT;
                }
        }
        return error;
}

/* ioctl handler from daemon dev */
static long vsi_v4l2_daemon_ioctl(
	struct file *filp,
	unsigned int cmd,
	unsigned long arg)
{
	int error = 0;
	struct vsi_v4l2_dev_info hwinfo;

	switch (_IOC_NR(cmd)) {
	case _IOC_NR(VSI_IOCTL_CMD_INITDEV):
		if (copy_from_user((void *)&hwinfo, (void __user *)arg, sizeof(hwinfo)) != 0) {
			v4l2_klog(LOGLVL_ERROR, "%s fail to get data", __func__);
			return -EINVAL;
		}
		vsiv4l2_set_hwinfo(&hwinfo);
		break;
	default:
		return -EINVAL;
	}
	return error;
}

static int getbusaddr(struct vsi_v4l2_ctx *ctx, dma_addr_t  *busaddr, struct vb2_buffer *buf)
{
	void *baseaddr[4], *p[4];
	struct vb2_queue *q;
	int planeno, i;

	if (binputqueue(buf->type)) {
		q = &ctx->input_que;
		planeno = ctx->mediacfg.srcplanes;
	} else {
		q = &ctx->output_que;
		planeno = ctx->mediacfg.dstplanes;
	}
	for (i = 0; i < planeno; i++) {
		baseaddr[i] = vb2_plane_vaddr(buf, i);	//actually used for cmodel
		p[i] = vb2_plane_cookie(buf, i);
		if (p[i] != NULL)
			busaddr[i] = *(dma_addr_t  *)p[i];
		else
			busaddr[i] = virt_to_phys(baseaddr[i]);
	}
        v4l2_klog(LOGLVL_VERBOSE, "%s:%d:%d:%lx:%lx:%lx", __func__, buf->type, planeno,
                (unsigned long)busaddr[0], (unsigned long)busaddr[1], (unsigned long)busaddr[2]);
        return planeno;
}

static void vsi_v4l2_sync_encparams(struct vsi_v4l2_ctx *ctx)
{
        struct v4l2_ctrl *ctrl;
        struct v4l2_daemon_enc_general_cmd *general = &ctx->mediacfg.encparams.general;
        struct v4l2_daemon_enc_h26x_cmd *h26x = &ctx->mediacfg.encparams.specific.enc_h26x_cmd;

        lockdep_assert_held(&ctx->ctxlock);

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_BITRATE);
        if (ctrl)
                general->bitPerSecond = v4l2_ctrl_g_ctrl(ctrl);

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_BITRATE_MODE);
        if (ctrl) {
                s32 val = v4l2_ctrl_g_ctrl(ctrl);

                if (val == V4L2_MPEG_VIDEO_BITRATE_MODE_VBR)
                        h26x->hrdConformance = 0;
                else
                        h26x->hrdConformance = 1;
        }

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_GOP_SIZE);
        if (ctrl)
                h26x->intraPicRate = v4l2_ctrl_g_ctrl(ctrl);

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_VPX_MAX_QP);
        if (ctrl)
                h26x->qpMax_vpx = v4l2_ctrl_g_ctrl(ctrl);

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_VPX_MIN_QP);
        if (ctrl)
                h26x->qpMin_vpx = v4l2_ctrl_g_ctrl(ctrl);

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_H264_MAX_QP);
        if (!ctrl)
                ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_HEVC_MAX_QP);
        if (ctrl) {
                s32 val = v4l2_ctrl_g_ctrl(ctrl);

                h26x->qpMax_h26x = val;
                h26x->qpMaxI = val;
        }

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_H264_MIN_QP);
        if (!ctrl)
                ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_HEVC_MIN_QP);
        if (ctrl) {
                s32 val = v4l2_ctrl_g_ctrl(ctrl);

                h26x->qpMin_h26x = val;
                h26x->qpMinI = val;
        }
}

static int vsi_v4l2_send_configupdate(struct vsi_v4l2_ctx *ctx)
{
        struct vsi_v4l2_msg msg;
        s32 retflag;
        u32 size;
        int ret;

        lockdep_assert_held(&ctx->ctxlock);

        if (!test_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag))
                return 0;

        vsi_v4l2_sync_encparams(ctx);

        memset(&msg, 0, sizeof(msg));
        size = sizeof(struct v4l2_daemon_enc_params);
        memcpy(&msg.params.enc_params, &ctx->mediacfg.encparams, sizeof(ctx->mediacfg.encparams));

        retflag = 0;
        ret = vsi_v4l2_sendcmd(V4L2_DAEMON_VIDIOC_BUF_RDY, ctx->ctxid,
                        ctx->mediacfg.encparams.general.codecFormat, &msg.params,
                        &retflag, size, UPDATE_INFO);
        if (!ret)
                clear_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag);

        return ret;
}

static u32 format_bufinfo_enc(struct vsi_v4l2_ctx *ctx, struct vsi_v4l2_msg *pmsg, struct vb2_buffer *buf, u32 *update)
{
	u32 planeno, size;
	struct v4l2_daemon_enc_buffers *encbufinfo;
	dma_addr_t  busaddr[4] = { 0 };

	vsi_convertROI(ctx);
	vsi_convertIPCM(ctx);
	if (binputqueue(buf->type) && ctx->srcvbufflag[buf->index] & FORCE_IDR)
		*update |= UPDATE_INFO;
	if (*update & UPDATE_INFO) {
		size = sizeof(struct v4l2_daemon_enc_params);
		memcpy((void *)&pmsg->params.enc_params, (void *)&ctx->mediacfg.encparams, sizeof(ctx->mediacfg.encparams));
	} else {
		size = sizeof(struct v4l2_daemon_enc_buffers) + sizeof(struct v4l2_daemon_enc_general_cmd);
		memcpy((void *)&pmsg->params.enc_params.io_buffer,
			(void *)&ctx->mediacfg.encparams.io_buffer, sizeof(struct v4l2_daemon_enc_buffers));
		memcpy((void *)&pmsg->params.enc_params.general,
			(void *)&ctx->mediacfg.encparams.general, sizeof(struct v4l2_daemon_enc_general_cmd));
	}
	if (ctx->mediacfg.multislice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_SINGLE)
		pmsg->params.enc_params.specific.enc_h26x_cmd.sliceSize = 0;
	if (binputqueue(buf->type)) {
		//msg.params.enc_params.general.lumWidthSrc = ctx->mediacfg.bytesperline;
		pmsg->params.enc_params.io_buffer.timestamp = buf->timestamp;
	}
	planeno = getbusaddr(ctx, busaddr, buf);
	encbufinfo = &pmsg->params.enc_params.io_buffer;
	if (binputqueue(buf->type)) {
		struct vsi_video_fmt *fmt = vsi_get_fmt_by_fourcc(ctx->mediacfg.infmt_fourcc);

		encbufinfo->busLumaOrig = encbufinfo->busLuma = busaddr[0] + buf->planes[0].data_offset;
		encbufinfo->busLumaSize = ctx->mediacfg.sizeimagesrc[0];
		encbufinfo->busChromaUOrig = encbufinfo->busChromaU = 0;
		encbufinfo->busChromaUSize = 0;
		encbufinfo->busChromaVOrig = encbufinfo->busChromaV = 0;
		encbufinfo->busChromaVSize = 0;
		if (fmt && fmt->comp_planes > 1) {
			if (planeno > 1)
				encbufinfo->busChromaUOrig = encbufinfo->busChromaU = busaddr[1] + buf->planes[1].data_offset;
			else
				encbufinfo->busChromaUOrig = encbufinfo->busLuma + ctx->mediacfg.sizeimagesrc[0];
			encbufinfo->busChromaUSize = ctx->mediacfg.sizeimagesrc[1];
		}
		if (fmt && fmt->comp_planes > 2) {
			if (planeno > 2)
				encbufinfo->busChromaVOrig = encbufinfo->busChromaV = busaddr[2] + buf->planes[2].data_offset;
			else
				encbufinfo->busChromaVOrig = encbufinfo->busChromaUOrig + ctx->mediacfg.sizeimagesrc[1];
			encbufinfo->busChromaVSize = ctx->mediacfg.sizeimagesrc[2];
		}
		encbufinfo->busOutBuf = 0;
		encbufinfo->outBufSize = 0;
		encbufinfo->inbufidx = buf->index;
		encbufinfo->outbufidx = -1;
		if (ctx->srcvbufflag[buf->index] & FORCE_IDR) {
			pmsg->params.enc_params.specific.enc_h26x_cmd.force_idr = 1;
			ctx->srcvbufflag[buf->index] &= ~FORCE_IDR;
		} else
			pmsg->params.enc_params.specific.enc_h26x_cmd.force_idr = 0;
	} else {
		encbufinfo->busLumaOrig = encbufinfo->busLuma = 0;
		encbufinfo->busChromaUOrig = encbufinfo->busChromaU = 0;
		encbufinfo->busChromaVOrig = encbufinfo->busChromaV = 0;
		encbufinfo->busOutBuf = busaddr[0] + buf->planes[0].data_offset;
		encbufinfo->outBufSize = ctx->mediacfg.sizeimagedst[0];
		encbufinfo->outbufidx = buf->index;
		encbufinfo->inbufidx = -1;
	}
	encbufinfo->bytesused = buf->planes[0].bytesused;
	return size;
}

static void format_bufinfo_dec(struct vsi_v4l2_ctx *ctx, struct vsi_v4l2_msg *pmsg, struct vb2_buffer *buf)
{
	struct v4l2_daemon_dec_buffers *decbufinfo;
	dma_addr_t  busaddr[4] = { 0 };

	memcpy((void *)&pmsg->params.dec_params.io_buffer, (void *)&ctx->mediacfg.decparams.io_buffer, sizeof(struct v4l2_daemon_dec_buffers));
	if (binputqueue(buf->type)) {
		if (test_and_clear_bit(BUF_FLAG_TIMESTAMP_INVALID, &ctx->srcvbufflag[buf->index]))
			pmsg->params.dec_params.dec_info.io_buffer.timestamp = -1;
		else
			pmsg->params.dec_params.dec_info.io_buffer.timestamp = buf->timestamp;
	}
	getbusaddr(ctx, busaddr, buf);
	decbufinfo = &pmsg->params.dec_params.io_buffer;
	if (!binputqueue(buf->type)) {
		decbufinfo->inbufidx = -1;
		decbufinfo->outbufidx = buf->index;
		decbufinfo->busInBuf = 0;
		decbufinfo->inBufSize = 0;
		decbufinfo->busOutBuf = busaddr[0] + buf->planes[0].data_offset;
		decbufinfo->OutBufSize = buf->planes[0].length - buf->planes[0].data_offset;
		decbufinfo->bytesused = buf->planes[0].bytesused;
		if (((ctx->mediacfg.src_pixeldepth == ctx->mediacfg.decparams.dec_info.io_buffer.outputPixelDepth)
			&& ctx->mediacfg.src_pixeldepth != 16)	//p010 can only set by user, not from ctrl sw
			|| !test_bit(CTX_FLAG_SRCCHANGED_BIT, &ctx->flag))
			pmsg->params.dec_params.io_buffer.outputPixelDepth = DEFAULT_PIXELDEPTH;
	} else {
		decbufinfo->inbufidx = buf->index;
		decbufinfo->outbufidx = -1;
		decbufinfo->busInBuf = busaddr[0] + buf->planes[0].data_offset;
		decbufinfo->inBufSize = ctx->inbuflen[buf->index];//ctx->mediacfg.sizeimagesrc[0];
		decbufinfo->bytesused = ctx->inbufbytes[buf->index];
		decbufinfo->busOutBuf = 0;
		decbufinfo->OutBufSize = 0;
	}
}

int vsiv4l2_execcmd(struct vsi_v4l2_ctx *ctx, enum v4l2_daemon_cmd_id id, void *args)
{
	int ret = 0;
	u32 param = 0;
	s32 retflag;
	struct vsi_v4l2_msg msg;

	if (atomic_read(&daemon_fn) <= 0) {
		ret = -DAEMON_ERR_DAEMON_MISSING;
		goto tail;
	}
	memset((void *)&msg, 0, sizeof(msg));
	switch (id) {
	case V4L2_DAEMON_VIDIOC_EXIT:
		ret = vsi_v4l2_sendcmd(id, 0, 0, NULL, &retflag, 0, 0);
		break;
	case V4L2_DAEMON_VIDIOC_DESTROY_ENC:
	case V4L2_DAEMON_VIDIOC_ENC_RESET:
		ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
			ctx->mediacfg.encparams.general.codecFormat, NULL, &retflag, 0, 0);
		break;
	case V4L2_DAEMON_VIDIOC_DESTROY_DEC:
		ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
			ctx->mediacfg.decparams.dec_info.io_buffer.outBufFormat, NULL, &retflag, 0, 0);
		break;
        case V4L2_DAEMON_VIDIOC_CMD_STOP:
                if (mutex_lock_interruptible(&ctx->ctxlock))
                        return -EBUSY;
                ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
                        ctx->mediacfg.encparams.general.codecFormat, NULL, &retflag, 0, 0);
                if (ret == 0) {
                        if ((retflag & LAST_BUFFER_FLAG) &&
                                ctx->status == ENC_STATUS_DRAINING)
                                ctx->status = ENC_STATUS_EOS;
                }
                mutex_unlock(&ctx->ctxlock);
                break;
        case V4L2_DAEMON_VIDIOC_STREAMON: {
                int codecformat;

                if (mutex_lock_interruptible(&ctx->ctxlock))
                        return -EBUSY;

                if (isencoder(ctx)) {
                        ret = vsi_v4l2_send_configupdate(ctx);
                        if (ret) {
                                mutex_unlock(&ctx->ctxlock);
                                goto tail;
                        }
                        codecformat = ctx->mediacfg.encparams.general.codecFormat;
                } else {
                        codecformat = ctx->mediacfg.decparams.dec_info.io_buffer.inputFormat;
                }

                if (test_and_clear_bit(CTX_FLAG_ENC_FLUSHBUF, &ctx->flag))
                        param = 1;
                mutex_unlock(&ctx->ctxlock);

                ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
                        codecformat, NULL, &retflag, 0, param);
                break; }
        case V4L2_DAEMON_VIDIOC_STREAMOFF_OUTPUT:
                if (isencoder(ctx))
                        ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
				ctx->mediacfg.encparams.general.inputFormat, NULL, &retflag, 0, 0);
		else
			ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
				ctx->mediacfg.decparams.dec_info.io_buffer.inputFormat, NULL, &retflag, 0, 0);
		break;
	case V4L2_DAEMON_VIDIOC_STREAMOFF_CAPTURE:
		if (isencoder(ctx))
			ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
				ctx->mediacfg.encparams.general.codecFormat, NULL, &retflag, 0, 0);
		else
			ret = vsi_v4l2_sendcmd(id, ctx->ctxid,
				ctx->mediacfg.decparams.dec_info.io_buffer.outBufFormat, NULL, &retflag, 0, 0);
		break;
	case V4L2_DAEMON_VIDIOC_STREAMON_OUTPUT:
		ret = vsi_v4l2_sendcmd(id, ctx->ctxid, ctx->mediacfg.decparams.dec_info.io_buffer.inputFormat,
				NULL, &retflag, 0, 0);
		break;
	case V4L2_DAEMON_VIDIOC_STREAMON_CAPTURE:
		ret = vsi_v4l2_sendcmd(id, ctx->ctxid, ctx->mediacfg.decparams.dec_info.io_buffer.outBufFormat,
				NULL, &retflag, 0, 0);
		break;
        case V4L2_DAEMON_VIDIOC_BUF_RDY:
                if (isencoder(ctx)) {
                        u32 size, update = 0;
                        bool configupdate;
                        int codecformat;

                        if (mutex_lock_interruptible(&ctx->ctxlock))
                                return -EBUSY;

                        configupdate = test_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag);
                        if (configupdate) {
                                vsi_v4l2_sync_encparams(ctx);
                                update |= UPDATE_INFO;
                        }

                        size = format_bufinfo_enc(ctx, &msg, args, &update);
                        codecformat = ctx->mediacfg.encparams.general.codecFormat;
                        mutex_unlock(&ctx->ctxlock);

                        ret = vsi_v4l2_sendcmd(id, ctx->ctxid, codecformat, &msg.params,
                                        &retflag, size, update);

                        if (!ret && configupdate) {
                                mutex_lock(&ctx->ctxlock);
                                clear_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag);
                                mutex_unlock(&ctx->ctxlock);
                        }
                } else {
                        format_bufinfo_dec(ctx, &msg, args);
                        ret = vsi_v4l2_sendcmd(id, ctx->ctxid, ctx->mediacfg.decparams.dec_info.io_buffer.inputFormat,
                                        &msg.params, &retflag, sizeof(struct v4l2_daemon_dec_buffers), 0);
                }
                break;
	default:
		v4l2_klog(LOGLVL_WARNING, "unexpected cmd id %d", id);
		return -1;
	}
tail:
	if (ctx) {
		if (ret < 0) {
			vsi_set_ctx_error(ctx, ret);
			v4l2_klog(LOGLVL_ERROR, "%llx fail to communicate with daemon, error=%d, cmd=%d", ctx->ctxid, ret, id);
		} else
			set_bit(CTX_FLAG_DAEMONLIVE_BIT, &ctx->flag);
	}
	return ret;
}

static int invoke_daemonapp(void)
{
	int ret = 0;

#if defined(CONFIG_INVOKE_VSIDAEMON)
	if (invoke_vsidaemon) {
		char loglvl[20] = {0};
		char *argv[] = {VSI_DAEMON_PATH, NULL};
		char *env[] = {"LD_LIBRARY_PATH=/usr/lib",
			"DAEMON_LOGPATH=/home/vsi/daemon.log",
			loglvl,
			NULL};

		memcpy(loglvl, "HANTRO_LOG_LEVEL=00", 20);
		loglvl[17] = loglevel/10 + 0x30;
		loglvl[18] = loglevel%10 + 0x30;
		ret = call_usermodehelper(argv[0], argv, env, UMH_WAIT_EXEC);
		if (ret < 0)
			return ret;

		ret = wait_event_interruptible_timeout(instance_queue,
				atomic_read(&daemon_fn) > 0, msecs_to_jiffies(10000));
		if (ret == -ERESTARTSYS || ret == 0)
			ret = -ERESTARTSYS;

		v4l2_klog(LOGLVL_BRIEF, "invoke daemon=%d\n", ret);
	} else {
		if (atomic_read(&daemon_fn) <= 0)
			ret = -ENODEV;
	}
#else
	if (atomic_read(&daemon_fn) <= 0)
		ret = -ENODEV;
#endif
	return ret;
}

static void quit_daemonapp(void)
{
#if defined(CONFIG_INVOKE_VSIDAEMON)
	if (!invoke_vsidaemon)
		return;

	vsiv4l2_execcmd(NULL, V4L2_DAEMON_VIDIOC_EXIT, NULL);
	wait_event_interruptible(instance_queue, atomic_read(&daemon_fn) <= 0);
#endif
}

int vsi_v4l2_addinstance(pid_t *ppid)
{
	int ret = 0;

	v4l2_klog(LOGLVL_BRIEF, "%s from inst num %d", __func__, v4l2_fn);

	if (mutex_lock_interruptible(&instance_lock))
		return -EBUSY;

	if (v4l2_fn >= MAX_STREAMS) {
		v4l2_klog(LOGLVL_WARNING, "opened instances more than max count:%d\n", v4l2_fn);
		ret = -EBUSY;
	} else {
		v4l2_fn++;
		if (v4l2_fn == 1) {
			ret = invoke_daemonapp();
			if (ret < 0) {
				v4l2_fn--;
			} else {
				ktime_get_real_ts64(&lasttime);
				accubytes = 0;
			}
		}
	}

	mutex_unlock(&instance_lock);
	return ret;
}

int vsi_v4l2_quitinstance(void)
{
	v4l2_klog(LOGLVL_BRIEF, "%s from instnum %d", __func__, v4l2_fn);
	if (mutex_lock_interruptible(&instance_lock))
		return -EBUSY;
	v4l2_fn--;
	if (v4l2_fn == 0) {
		struct timespec64 curtime;
		u64 gap;

		ktime_get_real_ts64(&curtime);
		gap = curtime.tv_sec - lasttime.tv_sec;
		if (gap <= 0)
			gap = 1;
		last_bandwidth = accubytes / gap;
		quit_daemonapp();
	}

	mutex_unlock(&instance_lock);
	return 0;
}

static ssize_t v4l2_msg_read(struct file *fh, char __user *buf, size_t size, loff_t *offest)
{
	int ret, r;

	ret = wait_event_interruptible_timeout(cmd_queue, ((r = getMsg(fh, buf, size)) != 0), msecs_to_jiffies(100));
	if (ret == -ERESTARTSYS)
		return -EIO;
	else if (ret == 0)
		return 0;
	return r;
}

static int vsi_handle_daemonmsg(struct vsi_v4l2_msg *pmsg)
{
	if (pmsg->error < 0)
		return vsi_v4l2_handleerror(pmsg->inst_id, pmsg->error);

	switch (pmsg->cmd_id) {
	case V4L2_DAEMON_VIDIOC_BUF_RDY:
		return vsi_v4l2_bufferdone(pmsg);
	case V4L2_DAEMON_VIDIOC_CHANGE_RES:
		return vsi_v4l2_notify_reschange(pmsg);
	case V4L2_DAEMON_VIDIOC_PICCONSUMED:
		return vsi_v4l2_handle_picconsumed(pmsg);
	case V4L2_DAEMON_VIDIOC_CROPCHANGE:
		return vsi_v4l2_handle_cropchange(pmsg);
	case V4L2_DAEMON_VIDIOC_WARNONOPTION:
		return vsi_v4l2_handle_warningmsg(pmsg);
	case V4L2_DAEMON_VIDIOC_STREAMOFF_CAPTURE_DONE:
	case V4L2_DAEMON_VIDIOC_STREAMOFF_OUTPUT_DONE:
		return vsi_v4l2_handle_streamoffdone(pmsg);
	default:
		return -EINVAL;
	}
}

static ssize_t v4l2_msg_write(struct file *fh, const char __user *buf, size_t size, loff_t *offset)
{
	int ret = -1, msgsize;
	struct vsi_v4l2_msg *pmsg;

	if (v4l2_fn == 0)
		return size;
	if (size < sizeof(struct vsi_v4l2_msg_hdr))
		return size;
	if (!access_ok((void __user *) buf, size)) {
		v4l2_klog(LOGLVL_ERROR, "input data unaccessable");
		return size;
	}
	pmsg = kzalloc(sizeof(struct vsi_v4l2_msg), GFP_KERNEL);
	if (!pmsg)
		goto error;
	if (copy_from_user((void *)pmsg,
		(void __user *)buf, sizeof(struct vsi_v4l2_msg_hdr)) != 0) {
		kfree(pmsg);
		goto error;
	}
	msgsize = pmsg->size;
	if (msgsize + sizeof(struct vsi_v4l2_msg_hdr) > size) {
		kfree(pmsg);
		goto error;
	}
	if (msgsize > 0) {
		if (copy_from_user((void *)pmsg + sizeof(struct vsi_v4l2_msg_hdr),
			(void __user *)buf + sizeof(struct vsi_v4l2_msg_hdr), msgsize) != 0) {
			kfree(pmsg);
			goto error;
		}
	}
        v4l2_klog(LOGLVL_BRIEF, "%s: recv cmd=%d seq=%llx err=%d size=%d param=0x%x", __func__, pmsg->cmd_id,
                pmsg->seq_id, pmsg->error, msgsize, pmsg->param_type);
        accubytes += sizeof(struct vsi_v4l2_msg_hdr) + msgsize;

        if (pmsg->seq_id == (u64)NO_RESPONSE_SEQID) {
                v4l2_klog(LOGLVL_BRIEF, "%s: async cmd handling cmd=%d seq=%llx", __func__, pmsg->cmd_id, pmsg->seq_id);
                vsi_handle_daemonmsg(pmsg);
                kfree(pmsg);
                return size;
        }
        if (mutex_lock_interruptible(&ret_lock)) {
                kfree(pmsg);
                return size;
        }
        ret = idr_alloc(retarray, (void *)pmsg, 1, 0, GFP_KERNEL);
        mutex_unlock(&ret_lock);
        if (ret < 0) {
                kfree(pmsg);
        } else {
                v4l2_klog(LOGLVL_BRIEF, "%s: queued response cmd=%d seq=%llx err=%d param=0x%x", __func__, pmsg->cmd_id,
                        pmsg->seq_id, pmsg->error, pmsg->param_type);
        }

error:
	if (ret >= 0)
		wake_up_interruptible_all(&ret_queue);

	return size;
}

static int v4l2_daemon_open(struct inode *inode,	struct file *filp)
{
        int ret = 0;
        int count;
        pid_t tgid = current->tgid;
        pid_t pid = current->pid;

        /*we need single daemon. Each deamon uses 2 handles for ioctl and mmap*/
        if (mutex_lock_interruptible(&daemon_lock))
                return -EBUSY;

        count = atomic_read(&daemon_fn);
        if (count == 0) {
                daemon_tgid = tgid;
                atomic_inc(&daemon_fn);
                count = 1;
                v4l2_klog(LOGLVL_BRIEF, "%s accepted first handle pid=%d tgid=%d count=%d", __func__, pid, tgid, count);
        } else if (count < 2 && daemon_tgid == tgid) {
                atomic_inc(&daemon_fn);
                count++;
                v4l2_klog(LOGLVL_BRIEF, "%s accepted second handle pid=%d tgid=%d count=%d", __func__, pid, tgid, count);
        } else {
                ret = -EBUSY;
                v4l2_klog(LOGLVL_WARNING, "%s deny open pid=%d tgid=%d owner=%d count=%d", __func__,
                        pid, tgid, daemon_tgid, count);
        }

        mutex_unlock(&daemon_lock);

        if (!ret)
                wake_up_interruptible_all(&instance_queue);

        return ret;
}

static int v4l2_daemon_release(struct inode *inode, struct file *filp)
{
        int count;
        bool wake = false;
        pid_t tgid = current->tgid;
        pid_t pid = current->pid;

        if (mutex_lock_interruptible(&daemon_lock))
                return -EBUSY;

        if (atomic_read(&daemon_fn) <= 0) {
                v4l2_klog(LOGLVL_WARNING, "%s unexpected release pid=%d tgid=%d count=%d", __func__, pid, tgid,
                        atomic_read(&daemon_fn));
                mutex_unlock(&daemon_lock);
                return 0;
        }

        count = atomic_dec_return(&daemon_fn);
        if (count == 0)
                daemon_tgid = -1;

        v4l2_klog(LOGLVL_BRIEF, "%s: pid=%d tgid=%d count=%d wake=%d", __func__, pid, tgid, count, count == 0);
        wake = (count == 0);

        mutex_unlock(&daemon_lock);

        if (wake) {
                wakeup_ctxqueues();
                wake_up_interruptible_all(&ret_queue);
                wake_up_interruptible_all(&instance_queue);
        }
        return 0;
}

static int vsi_v4l2_mmap(
	struct file *filp,
	struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;

	/* Does it even fit in phys_addr_t? */
	if (offset >> PAGE_SHIFT != vma->vm_pgoff)
		return -EINVAL;

	/* It's illegal to wrap around the end of the physical address space. */
	if (offset + (phys_addr_t)size - 1 < offset)
		return -EINVAL;

	//if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
	//	return -EINVAL;

	if (!(vma->vm_flags & VM_MAYSHARE))
		return -EPERM;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot) ? -EAGAIN : 0;
}


static const struct file_operations daemon_fops = {
	.owner = THIS_MODULE,
	.open = v4l2_daemon_open,
	.release = v4l2_daemon_release,
	.unlocked_ioctl = vsi_v4l2_daemon_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
	.read = v4l2_msg_read,
	.write = v4l2_msg_write,
	.mmap = vsi_v4l2_mmap,
};


int vsiv4l2_initdaemon(void)
{
	int result;

	cmdarray = NULL;
	retarray = NULL;
	v4l2_fn = 0;
	accubytes = 0;
	last_bandwidth = 0;
	loglevel = 0;
	accubytes = 0;
	result = register_chrdev(VSI_DAEMON_DEVMAJOR, PIPE_DEVICE_NAME, &daemon_fops);
	if (result < 0)
		return result;

	cmdarray = kzalloc(sizeof(struct idr), GFP_KERNEL);
	if (cmdarray == NULL) {
		unregister_chrdev(VSI_DAEMON_DEVMAJOR, PIPE_DEVICE_NAME);
		return -ENOMEM;
	}
	idr_init(cmdarray);

	retarray = kzalloc(sizeof(struct idr), GFP_KERNEL);
	if (retarray == NULL) {
		unregister_chrdev(VSI_DAEMON_DEVMAJOR, PIPE_DEVICE_NAME);
		kfree(cmdarray);
		return -ENOMEM;
	}
	idr_init(retarray);

	mutex_init(&cmd_lock);
	mutex_init(&ret_lock);
	mutex_init(&instance_lock);
	g_seqid = 1;
	if (loglevel < 0)
		loglevel = 0;
	else if (loglevel > 10)
		loglevel = 10;

	return result;
}

