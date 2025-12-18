/*
 *    VSI V4L2 kernel driver main entrance.
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
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/lockdep.h>
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
#include <linux/version.h>
#include "vsi-v4l2-priv.h"

#define DRIVER_NAME	"vsiv4l2"

int vsi_kloglvl = LOGLVL_ERROR;
module_param(vsi_kloglvl, int, 0644);

static struct platform_device *gvsidev;
static struct idr vsi_inst_array;
static struct device *vsidaemondev;
static struct mutex vsi_ctx_array_lock;		//it only protect ctx between release from app and msg from daemon
static u64 ctx_seqid;

static ssize_t BandWidth_show(struct device *kdev,
				     struct device_attribute *attr, char *buf)
{
	/*
	 * sys/bus/platform/drivers/vsiv4l2/xxxxx.vpu/BandWidth
	 * used to show bandwidth info to user space
	 */
	u64 bandwidth;

	bandwidth = vsi_v4l2_getbandwidth();
	return snprintf(buf, PAGE_SIZE, "%lld\n", bandwidth);
}

static DEVICE_ATTR_RO(BandWidth);

static struct attribute *vsi_v4l2_attrs[] = {
	&dev_attr_BandWidth.attr,
	NULL,
};

static const struct attribute_group vsi_v4l2_attr_group = {
	.attrs = vsi_v4l2_attrs,
};

#define VSI_V4L2_DEBUGFS_DIR    "vsi_v4l2"

#if IS_ENABLED(CONFIG_DEBUG_FS)
static bool vsi_v4l2_debugfs_active(struct vsi_v4l2_ctx *ctx)
{
        return ctx && ctx->debugfs_active;
}

static const char *vsi_v4l2_ctrl_type_name(enum v4l2_ctrl_type type)
{
        switch (type) {
        case V4L2_CTRL_TYPE_INTEGER:
                return "int";
        case V4L2_CTRL_TYPE_BOOLEAN:
                return "bool";
        case V4L2_CTRL_TYPE_MENU:
                return "menu";
        case V4L2_CTRL_TYPE_BUTTON:
                return "button";
        case V4L2_CTRL_TYPE_INTEGER64:
                return "int64";
        default:
                return "other";
        }
}

static void vsi_v4l2_sanitize_ctrl_name(const char *ctrl_name, u32 id,
                                       char *sanitized, size_t len)
{
        char cid_suffix[12];
        size_t i, j = 0;

        sanitized[0] = '\0';

        for (i = 0; ctrl_name[i] && j < len - 1; i++) {
                char c = ctrl_name[i];

                if (c >= 'A' && c <= 'Z')
                        c = c - 'A' + 'a';

                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                        sanitized[j++] = c;
                        continue;
                }

                if (c == ' ' || c == '-' || c == '\t') {
                        sanitized[j++] = '_';
                        continue;
                }
        }

        if (j == 0)
                sanitized[j++] = 'c';

        sanitized[j] = '\0';
        snprintf(cid_suffix, sizeof(cid_suffix), "_cid_%08x", id);
        strlcat(sanitized, cid_suffix, len);
}

static s64 vsi_v4l2_ctrl_get_value_locked(struct vsi_v4l2_ctx *ctx,
                                         struct v4l2_ctrl *ctrl)
{
        lockdep_assert_held(&ctx->ctxlock);

        if (ctrl->type == V4L2_CTRL_TYPE_INTEGER64)
                return v4l2_ctrl_g_ctrl_int64(ctrl);

        return v4l2_ctrl_g_ctrl(ctrl);
}

static int vsi_v4l2_dbg_stats(struct seq_file *s, void *data)
{
        struct vsi_v4l2_ctx *ctx = s->private;
        struct vb2_queue *vq;
        struct v4l2_format format;
        struct v4l2_ctrl *ctrl;
        s64 bitrate = -1;
        s64 gop = -1;
        int rc_mode = -1;
        int ret;

        if (!vsi_v4l2_debugfs_active(ctx))
                return -ENODEV;

        if (mutex_lock_interruptible(&ctx->ctxlock))
                return -ERESTARTSYS;

        seq_printf(s, "id: %llu\n", ctx->ctxid);
        seq_printf(s, "type: %s\n", isdecoder(ctx) ? "decoder" : "encoder");
        seq_printf(s, "pid: %d\n", ctx->pid);
        seq_printf(s, "tgid: %d\n", ctx->tgid);
        seq_printf(s, "comm: %s\n", ctx->comm);
        seq_printf(s, "status: %d\n", ctx->status);
        seq_printf(s, "error: %d\n", ctx->error);
        seq_printf(s, "flags: 0x%lx\n", ctx->flag);

        vq = &ctx->input_que;
        format.type = vq->type;
        ret = vsiv4l2_getfmt(ctx, &format);
        if (!ret) {
                seq_printf(s, "output: %c%c%c%c %dx%d streaming=%d buffers=%d\n",
                           format.fmt.pix_mp.pixelformat,
                           format.fmt.pix_mp.pixelformat >> 8,
                           format.fmt.pix_mp.pixelformat >> 16,
                           format.fmt.pix_mp.pixelformat >> 24,
                           format.fmt.pix_mp.width,
                           format.fmt.pix_mp.height,
                           vb2_is_streaming(vq), vq->num_buffers);
        }

        vq = &ctx->output_que;
        format.type = vq->type;
        ret = vsiv4l2_getfmt(ctx, &format);
        if (!ret) {
                seq_printf(s, "capture: %c%c%c%c %dx%d streaming=%d buffers=%d\n",
                           format.fmt.pix_mp.pixelformat,
                           format.fmt.pix_mp.pixelformat >> 8,
                           format.fmt.pix_mp.pixelformat >> 16,
                           format.fmt.pix_mp.pixelformat >> 24,
                           format.fmt.pix_mp.width,
                           format.fmt.pix_mp.height,
                           vb2_is_streaming(vq), vq->num_buffers);
        }

        if (!isdecoder(ctx)) {
                ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_BITRATE);
                if (ctrl)
                        bitrate = vsi_v4l2_ctrl_get_value_locked(ctx, ctrl);

                ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_GOP_SIZE);
                if (ctrl)
                        gop = vsi_v4l2_ctrl_get_value_locked(ctx, ctrl);

                ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, V4L2_CID_MPEG_VIDEO_BITRATE_MODE);
                if (ctrl)
                        rc_mode = vsi_v4l2_ctrl_get_value_locked(ctx, ctrl);

                seq_printf(s, "bitrate: %lld\n", bitrate);
                seq_printf(s, "rc_mode: %d\n", rc_mode);
                seq_printf(s, "gop: %lld\n", gop);
        }

        seq_printf(s, "input_processed: %llu\n", ctx->performance.input_buf_num);
        seq_printf(s, "output_done: %llu\n", ctx->performance.processed_buf_num);

        mutex_unlock(&ctx->ctxlock);
        return 0;
}

static int vsi_v4l2_dbg_stats_open(struct inode *inode, struct file *filp)
{
        return single_open(filp, vsi_v4l2_dbg_stats, inode->i_private);
}

static const struct file_operations vsi_v4l2_dbg_stats_fops = {
        .owner = THIS_MODULE,
        .open = vsi_v4l2_dbg_stats_open,
        .release = single_release,
        .read = seq_read,
};

static int vsi_v4l2_dbg_controls(struct seq_file *s, void *data)
{
        struct vsi_v4l2_ctx *ctx = s->private;
        unsigned int i;

        if (!vsi_v4l2_debugfs_active(ctx))
                return -ENODEV;

        if (mutex_lock_interruptible(&ctx->ctxlock))
                return -ERESTARTSYS;

        for (i = 0; i < ctx->ctrlhdl.nctrls; i++) {
                struct v4l2_ctrl *ctrl = ctx->ctrlhdl.ctrls[i];
                s64 cur = 0;

                if (!ctrl)
                        continue;

                cur = vsi_v4l2_ctrl_get_value_locked(ctx, ctrl);

                seq_printf(s,
                           "%s (0x%08x) type=%s min=%lld max=%lld step=%lld def=%lld cur=%lld flags=0x%x\n",
                           ctrl->name, ctrl->id, vsi_v4l2_ctrl_type_name(ctrl->type),
                           ctrl->minimum, ctrl->maximum, ctrl->step, ctrl->default_value,
                           cur, ctrl->flags);
        }

        mutex_unlock(&ctx->ctxlock);
        return 0;
}

static int vsi_v4l2_dbg_controls_open(struct inode *inode, struct file *filp)
{
        return single_open(filp, vsi_v4l2_dbg_controls, inode->i_private);
}

static const struct file_operations vsi_v4l2_dbg_controls_fops = {
        .owner = THIS_MODULE,
        .open = vsi_v4l2_dbg_controls_open,
        .release = single_release,
        .read = seq_read,
};

static ssize_t vsi_v4l2_dbg_ctrl_read(struct file *file, char __user *user_buf,
                                     size_t count, loff_t *ppos)
{
        struct v4l2_ctrl *ctrl = file->private_data;
        struct vsi_v4l2_ctx *ctx = container_of(ctrl->handler,
                                               struct vsi_v4l2_ctx, ctrlhdl);
        char buf[64];
        int len;
        s64 val;

        if (!vsi_v4l2_debugfs_active(ctx))
                return -ENODEV;

        if (mutex_lock_interruptible(&ctx->ctxlock))
                return -ERESTARTSYS;
        val = vsi_v4l2_ctrl_get_value_locked(ctx, ctrl);

        mutex_unlock(&ctx->ctxlock);

        len = scnprintf(buf, sizeof(buf), "%lld\n", val);
        return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static int vsi_v4l2_ctrl_apply_value(struct vsi_v4l2_ctx *ctx,
                                    struct v4l2_ctrl *ctrl, s64 val)
{
        int ret;

        lockdep_assert_held(&ctx->ctxlock);

        if (ctrl->type == V4L2_CTRL_TYPE_INTEGER64)
                ret = v4l2_ctrl_s_ctrl_int64(ctrl, val);
        else
                ret = v4l2_ctrl_s_ctrl(ctrl, val);

        if (!ret && !isdecoder(ctx))
                set_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag);

        return ret;
}

static ssize_t vsi_v4l2_dbg_ctrl_write(struct file *file, const char __user *user_buf,
                                      size_t count, loff_t *ppos)
{
        struct v4l2_ctrl *ctrl = file->private_data;
        struct vsi_v4l2_ctx *ctx = container_of(ctrl->handler,
                                               struct vsi_v4l2_ctx, ctrlhdl);
        char buf[64];
        size_t len;
        s64 val;
        int ret;

        if (!vsi_v4l2_debugfs_active(ctx))
                return -ENODEV;

        len = min(count, sizeof(buf) - 1);
        if (copy_from_user(buf, user_buf, len))
                return -EFAULT;
        buf[len] = '\0';
        strim(buf);

        ret = kstrtoll(buf, 0, &val);
        if (ret)
                return ret;

        if (mutex_lock_interruptible(&ctx->ctxlock))
                return -ERESTARTSYS;

        ret = vsi_v4l2_ctrl_apply_value(ctx, ctrl, val);
        mutex_unlock(&ctx->ctxlock);

        if (ret)
                return ret;

        return count;
}

static const struct file_operations vsi_v4l2_dbg_ctrl_fops = {
        .owner = THIS_MODULE,
        .read = vsi_v4l2_dbg_ctrl_read,
        .write = vsi_v4l2_dbg_ctrl_write,
        .open = simple_open,
        .llseek = generic_file_llseek,
};

static ssize_t vsi_v4l2_dbg_set_ctrl_write(struct file *file,
                                          const char __user *user_buf,
                                          size_t count, loff_t *ppos)
{
        struct vsi_v4l2_ctx *ctx = file->private_data;
        char buf[128];
        size_t len;
        char *val_str;
        char *cid_str;
        unsigned long cid;
        s64 val;
        struct v4l2_ctrl *ctrl;
        int ret;

        if (!vsi_v4l2_debugfs_active(ctx))
                return -ENODEV;

        len = min(count, sizeof(buf) - 1);
        if (copy_from_user(buf, user_buf, len))
                return -EFAULT;
        buf[len] = '\0';
        strim(buf);

        val_str = strchr(buf, '=');
        if (val_str) {
                *val_str = '\0';
                val_str++;
        } else {
                val_str = strpbrk(buf, " \t");
                if (!val_str)
                        return -EINVAL;
                *val_str = '\0';
                val_str++;
        }

        cid_str = buf;
        val_str = strim(val_str);
        cid_str = strim(cid_str);

        ret = kstrtoul(cid_str, 0, &cid);
        if (ret)
                return ret;

        ret = kstrtoll(val_str, 0, &val);
        if (ret)
                return ret;

        ctrl = v4l2_ctrl_find(&ctx->ctrlhdl, cid);
        if (!ctrl)
                return -EINVAL;

        if (mutex_lock_interruptible(&ctx->ctxlock))
                return -ERESTARTSYS;

        ret = vsi_v4l2_ctrl_apply_value(ctx, ctrl, val);
        mutex_unlock(&ctx->ctxlock);

        if (ret)
                return ret;

        return count;
}

static const struct file_operations vsi_v4l2_dbg_set_ctrl_fops = {
        .owner = THIS_MODULE,
        .write = vsi_v4l2_dbg_set_ctrl_write,
        .open = simple_open,
        .llseek = generic_file_llseek,
};

static int vsi_v4l2_create_dbgfs_ctrls(struct vsi_v4l2_ctx *ctx,
                                      struct dentry *parent)
{
        struct dentry *ctrl_dir;
        unsigned int i;

        ctrl_dir = debugfs_create_dir("ctrl", parent);
        if (IS_ERR_OR_NULL(ctrl_dir))
                return -ENOMEM;

        for (i = 0; i < ctx->ctrlhdl.nctrls; i++) {
                struct v4l2_ctrl *ctrl = ctx->ctrlhdl.ctrls[i];
                struct dentry *file;
                char name[64];

                if (!ctrl)
                        continue;

                vsi_v4l2_sanitize_ctrl_name(ctrl->name, ctrl->id,
                                            name, sizeof(name));
                file = debugfs_create_file(name,
                                           VERIFY_OCTAL_PERMISSIONS(0644),
                                           ctrl_dir, ctrl,
                                           &vsi_v4l2_dbg_ctrl_fops);
                if (IS_ERR_OR_NULL(file))
                        return -ENOMEM;
        }

        debugfs_create_file("set_ctrl",
                            VERIFY_OCTAL_PERMISSIONS(0200),
                            parent, ctx, &vsi_v4l2_dbg_set_ctrl_fops);
        return 0;
}

int vsi_v4l2_create_dbgfs_file(struct vsi_v4l2_ctx *ctx)
{
        char name[64];
        struct dentry *dir;

        if (!ctx || !ctx->dev || !ctx->dev->debugfs)
                return -EINVAL;

        scnprintf(name, sizeof(name), "instance.%d", (int)(ctx->ctxid & 0xFFFFFFFF));
        dir = debugfs_create_dir(name, ctx->dev->debugfs);
        if (IS_ERR_OR_NULL(dir))
                return -ENOMEM;

        ctx->debugfs = dir;
        ctx->debugfs_active = true;

        debugfs_create_file("stats", VERIFY_OCTAL_PERMISSIONS(0444), dir,
                            ctx, &vsi_v4l2_dbg_stats_fops);
        debugfs_create_file("controls", VERIFY_OCTAL_PERMISSIONS(0444), dir,
                            ctx, &vsi_v4l2_dbg_controls_fops);

        return vsi_v4l2_create_dbgfs_ctrls(ctx, dir);
}

void vsi_v4l2_remove_dbgfs_file(struct vsi_v4l2_ctx *ctx)
{
        if (!ctx || !ctx->debugfs)
                return;

        ctx->debugfs_active = false;
        debugfs_remove_recursive(ctx->debugfs);
        ctx->debugfs = NULL;
}
#else
int vsi_v4l2_create_dbgfs_file(struct vsi_v4l2_ctx *ctx)
{
        return 0;
}

void vsi_v4l2_remove_dbgfs_file(struct vsi_v4l2_ctx *ctx)
{
}
#endif

static struct vsi_v4l2_ctx *get_ctx(unsigned long ctxid)
{
	unsigned long id = CTX_ARRAY_ID(ctxid);
	unsigned long seq = CTX_SEQ_ID(ctxid);
	struct vsi_v4l2_ctx *ctx;

	if (mutex_lock_interruptible(&vsi_ctx_array_lock))
		return NULL;

	ctx  = (struct vsi_v4l2_ctx *)idr_find(&vsi_inst_array, id);
	if (ctx && (CTX_SEQ_ID(ctx->ctxid)  == seq)) {
		atomic_inc(&ctx->refcnt);
		mutex_unlock(&vsi_ctx_array_lock);
		return ctx;
	}

	mutex_unlock(&vsi_ctx_array_lock);
	return NULL;
}

static void put_ctx(struct vsi_v4l2_ctx *ctx)
{
	if (atomic_dec_return(&ctx->refcnt) == 0) {
		v4l2_klog(LOGLVL_BRIEF, "free ctx %llx", ctx->ctxid);
		kfree(ctx);
	}
}

static void release_ctx(struct vsi_v4l2_ctx *ctx, int notifydaemon)
{
	int ret = 0;

	if (notifydaemon == 1 && test_bit(CTX_FLAG_DAEMONLIVE_BIT, &ctx->flag)) {
		if (isdecoder(ctx))
			ret = vsiv4l2_execcmd(ctx, V4L2_DAEMON_VIDIOC_DESTROY_DEC, NULL);
		else
			ret = vsiv4l2_execcmd(ctx, V4L2_DAEMON_VIDIOC_DESTROY_ENC, NULL);
	}

	if (mutex_lock_interruptible(&vsi_ctx_array_lock))
		return;
	idr_remove(&vsi_inst_array, CTX_ARRAY_ID(ctx->ctxid));
	mutex_unlock(&vsi_ctx_array_lock);

	/*vsi_vpu_buf obj is freed here, together with all buffer memory */
	if (mutex_lock_interruptible(&ctx->ctxlock))
		return;
	return_all_buffers(&ctx->input_que, VB2_BUF_STATE_DONE, 0);
	return_all_buffers(&ctx->output_que, VB2_BUF_STATE_DONE, 0);
	removeallcropinfo(ctx);

	vb2_queue_release(&ctx->input_que);
	vb2_queue_release(&ctx->output_que);
	v4l2_ctrl_handler_free(&ctx->ctrlhdl);
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	mutex_unlock(&ctx->ctxlock);

	put_ctx(ctx);
}

void vsi_remove_ctx(struct vsi_v4l2_ctx *ctx)
{
	if (mutex_lock_interruptible(&vsi_ctx_array_lock))
		return;
	idr_remove(&vsi_inst_array, CTX_ARRAY_ID(ctx->ctxid));
	mutex_unlock(&vsi_ctx_array_lock);
}

struct vsi_v4l2_ctx *vsi_create_ctx(void)
{
	struct vsi_v4l2_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return NULL;
	if (mutex_lock_interruptible(&vsi_ctx_array_lock)) {
		kfree(ctx);
		return NULL;
	}
	ctx->ctxid = idr_alloc(&vsi_inst_array, (void *)ctx, 1, 0, GFP_KERNEL);
	if ((int)ctx->ctxid < 0) {
		kfree(ctx);
		ctx = NULL;
	} else {
		ctx_seqid++;
		if (ctx_seqid >= CTX_SEQID_UPLIMT)
			ctx_seqid = 1;
		ctx->ctxid |= (ctx_seqid << 32);
		v4l2_klog(LOGLVL_BRIEF, "create ctx with %llx", ctx->ctxid);
	}
	atomic_set(&ctx->refcnt, 1);
	mutex_unlock(&vsi_ctx_array_lock);
	init_waitqueue_head(&ctx->retbuf_queue);
	init_waitqueue_head(&ctx->capoffdone_queue);

	return ctx;
}

void vsi_set_ctx_error(struct vsi_v4l2_ctx *ctx, s32 error)
{
	ctx->error = error;
	if (error < 0) {
		struct v4l2_event event;

		memset(&event, 0, sizeof(struct v4l2_event));
		event.type = V4L2_EVENT_CODEC_ERROR,
		v4l2_event_queue_fh(&ctx->fh, &event);
	}
}
void wakeup_ctxqueues(void)
{
	struct vsi_v4l2_ctx *ctx;
	int id;

	idr_for_each_entry(&vsi_inst_array, ctx, id) {
		if (ctx) {
			vsi_set_ctx_error(ctx, DAEMON_ERR_DAEMON_MISSING);
			wake_up_interruptible_all(&ctx->input_que.done_wq);
			wake_up_interruptible_all(&ctx->output_que.done_wq);
			wake_up_interruptible_all(&ctx->retbuf_queue);
			wake_up_interruptible_all(&ctx->capoffdone_queue);
			wake_up_interruptible_all(&ctx->fh.wait);
		}
	}
}

static void vsi_v4l2_clear_event(struct vsi_v4l2_ctx *ctx)
{
	struct v4l2_event event;
	int ret;

	if (v4l2_event_pending(&ctx->fh)) {
		while (v4l2_event_pending(&ctx->fh)) {
			ret = v4l2_event_dequeue(&ctx->fh, &event, 1);
			if (ret)
				return;
		};
	}
}

int vsi_v4l2_reset_ctx(struct vsi_v4l2_ctx *ctx)
{
	int ret = 0;

	if (ctx->status != VSI_STATUS_INIT) {
		v4l2_klog(LOGLVL_BRIEF, "reset ctx %llx", ctx->ctxid);
		ctx->queued_srcnum = ctx->buffed_capnum = ctx->buffed_cropcapnum = 0;
		vsi_v4l2_clear_event(ctx);
		if (isdecoder(ctx)) {
			ret = vsiv4l2_execcmd(ctx, V4L2_DAEMON_VIDIOC_DESTROY_DEC, NULL);
			ctx->flag = CTX_FLAG_DEC;
		} else {
			ret = vsiv4l2_execcmd(ctx, V4L2_DAEMON_VIDIOC_DESTROY_ENC, NULL);
			ctx->flag = CTX_FLAG_ENC;
			set_bit(CTX_FLAG_ENC_FLUSHBUF, &ctx->flag);
		}
		set_bit(CTX_FLAG_CONFIGUPDATE_BIT, &ctx->flag);
		return_all_buffers(&ctx->input_que, VB2_BUF_STATE_DONE, 0);
		return_all_buffers(&ctx->output_que, VB2_BUF_STATE_DONE, 0);
		removeallcropinfo(ctx);
		ctx->status = VSI_STATUS_INIT;
		ctx->reschange_cnt = 0;
		vsi_set_ctx_error(ctx, 0);
		if (isdecoder(ctx)) {
			wake_up_interruptible_all(&ctx->retbuf_queue);
			wake_up_interruptible_all(&ctx->capoffdone_queue);
		}
	}
	return ret;
}

int vsi_v4l2_release(struct file *filp)
{
	struct vsi_v4l2_ctx *ctx = fh_to_ctx(filp->private_data);

	vsi_v4l2_remove_dbgfs_file(ctx);
	/*normal streaming end should fall here*/
	v4l2_klog(LOGLVL_BRIEF, "%s ctx %llx", __func__, ctx->ctxid);
	vsi_clear_daemonmsg(CTX_ARRAY_ID(ctx->ctxid));
	release_ctx(ctx, 1);
	vsi_v4l2_quitinstance();
	return 0;
}

/*orphan error msg from daemon write, should not call daemon back*/
int vsi_v4l2_handle_picconsumed(struct vsi_v4l2_msg *pmsg)
{
	unsigned long ctxid = pmsg->inst_id;
	struct vsi_v4l2_ctx *ctx;
	struct v4l2_event event;

	v4l2_klog(LOGLVL_WARNING, "%lx got picconsumed event", ctxid);
	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -1;

	memset((void *)&event, 0, sizeof(struct v4l2_event));
	event.type = V4L2_EVENT_SKIP;
	if (isdecoder(ctx))
		event.u.data[0] = pmsg->params.dec_params.io_buffer.inbufidx;

	v4l2_event_queue_fh(&ctx->fh, &event);

	/*
	 * Invalid inbufidx means we don't know ctrlsw drop which frame.
	 * So, increase capture sequence to notify user.
	 */
	if (pmsg->params.dec_params.io_buffer.inbufidx < 0) {
		if (mutex_lock_interruptible(&ctx->ctxlock)) {
			put_ctx(ctx);
			return -EBUSY;
		}
		ctx->cap_sequence++;
		mutex_unlock(&ctx->ctxlock);
	}

	put_ctx(ctx);
	return 0;
}

void vsi_v4l2_sendeos(struct vsi_v4l2_ctx *ctx)
{
	struct v4l2_event event;

	memset((void *)&event, 0, sizeof(struct v4l2_event));
	event.type = V4L2_EVENT_EOS;
	v4l2_event_queue_fh(&ctx->fh, &event);
}

int vsi_v4l2_handleerror(unsigned long ctxid, int error)
{
	struct vsi_v4l2_ctx *ctx;

	v4l2_klog(LOGLVL_ERROR, "%lx got error %d", ctxid, error);
	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -1;

	if (error == DAEMON_ERR_DEC_METADATA_ONLY) {
		struct vb2_queue *q = &ctx->output_que;

		if (!q->last_buffer_dequeued) {
			q->last_buffer_dequeued = true;
			wake_up(&q->done_wq);
		}
		vsi_v4l2_sendeos(ctx);
	} else {
		vsi_set_ctx_error(ctx, error > 0 ? -error:error);
		wake_up_interruptible_all(&ctx->retbuf_queue);
		wake_up_interruptible_all(&ctx->capoffdone_queue);
		wake_up_interruptible_all(&ctx->input_que.done_wq);
		wake_up_interruptible_all(&ctx->output_que.done_wq);
		wake_up_interruptible_all(&ctx->fh.wait);
	}
	put_ctx(ctx);
	return 0;
}

int vsi_v4l2_send_reschange(struct vsi_v4l2_ctx *ctx)
{
	struct v4l2_event event;

	if (!ctx->reschanged_need_notify) {
		if (ctx->need_capture_on)
			vsi_dec_capture_on(ctx);
		return 0;
	}

	vsi_v4l2_update_decfmt(ctx);

	memset((void *)&event, 0, sizeof(struct v4l2_event));
	event.type = V4L2_EVENT_SOURCE_CHANGE,
	event.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION,
	v4l2_event_queue_fh(&ctx->fh, &event);
	ctx->reschanged_need_notify = false;
	ctx->reschange_notified = true;

	if (ctx->need_capture_on) {
		int ret;

		ret = vb2_streamon(&ctx->output_que, V4L2_BUF_TYPE_VIDEO_CAPTURE);
		if (!ret) {
			ctx->output_que.last_buffer_dequeued = true;
			wake_up(&ctx->output_que.done_wq);
		}
	}

	return 0;
}

int vsi_v4l2_notify_reschange(struct vsi_v4l2_msg *pmsg)
{
	u64 ctxid = pmsg->inst_id;
	struct vsi_v4l2_ctx *ctx;

	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -ESRCH;

	if (isdecoder(ctx)) {
		struct vsi_v4l2_mediacfg *pcfg = &ctx->mediacfg;
		struct v4l2_daemon_dec_info *decinfo = &pmsg->params.dec_params.dec_info.dec_info;

		if (mutex_lock_interruptible(&ctx->ctxlock)) {
			put_ctx(ctx);
			return -EBUSY;
		}
		v4l2_klog(LOGLVL_BRIEF, "%llx sending event res change:%d, delay=%d", ctx->ctxid, ctx->status,
			(ctx->status == DEC_STATUS_DECODING || ctx->status == DEC_STATUS_DRAINING) && !list_empty(&ctx->output_que.done_list));
		v4l2_klog(LOGLVL_BRIEF, "reso=%d:%d,bitdepth=%d,stride=%d,dpb=%d:%d,orig yuvfmt=%d",
			decinfo->frame_width, decinfo->frame_height, decinfo->bit_depth, pmsg->params.dec_params.io_buffer.output_wstride,
			decinfo->needed_dpb_nums, decinfo->dpb_buffer_size, decinfo->src_pix_fmt);
		ctx->reschange_cnt++;
		pcfg->decparams_bkup.dec_info = pmsg->params.dec_params.dec_info;
		pcfg->decparams_bkup.io_buffer.srcwidth = pmsg->params.dec_params.io_buffer.srcwidth;
		pcfg->decparams_bkup.io_buffer.srcheight = pmsg->params.dec_params.io_buffer.srcheight;
		pcfg->decparams_bkup.io_buffer.output_width = pmsg->params.dec_params.io_buffer.output_width;
		pcfg->decparams_bkup.io_buffer.output_height = pmsg->params.dec_params.io_buffer.output_height;
		pcfg->decparams_bkup.io_buffer.output_wstride = pmsg->params.dec_params.io_buffer.output_wstride;
		pcfg->minbuf_4output_bkup = pmsg->params.dec_params.dec_info.dec_info.needed_dpb_nums;
		pcfg->sizeimagedst_bkup = pmsg->params.dec_params.io_buffer.OutBufSize;
		set_bit(CTX_FLAG_SRCCHANGED_BIT, &ctx->flag);
		if ((ctx->status == DEC_STATUS_DECODING || ctx->status == DEC_STATUS_DRAINING)
			&& !list_empty(&ctx->output_que.done_list)) {
			set_bit(CTX_FLAG_DELAY_SRCCHANGED_BIT, &ctx->flag);
		} else {
			vsi_dec_update_reso(ctx);
			vsi_v4l2_send_reschange(ctx);
		}
		if (pmsg->params.dec_params.dec_info.dec_info.colour_description_present_flag)
			vsi_dec_updatevui(&pmsg->params.dec_params.dec_info.dec_info, &pcfg->decparams.dec_info.dec_info);
		mutex_unlock(&ctx->ctxlock);
	}
	put_ctx(ctx);
	return 0;
}

static int convert_daemonwarning_to_appwarning(int daemon_warnmsg)
{
	switch (daemon_warnmsg) {
	case WARN_ROIREGION:
		return RIOREGION_NOTALLOW;
	case WARN_IPCMREGION:
		return IPCMREGION_NOTALLOW;
	case WARN_LEVEL:
		return LEVEL_UPDATED;
	default:
		return UNKONW_WARNING;
	}
}

int vsi_v4l2_handle_warningmsg(struct vsi_v4l2_msg *pmsg)
{
	unsigned long ctxid = pmsg->inst_id;
	struct vsi_v4l2_ctx *ctx;
	struct v4l2_event event;

	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -ESRCH;
	memset((void *)&event, 0, sizeof(struct v4l2_event));
	event.type = V4L2_EVENT_INVALID_OPTION,
	event.id = convert_daemonwarning_to_appwarning(pmsg->error);
	v4l2_klog(LOGLVL_WARNING, "%lx got warning msg %d", ctxid, pmsg->error);
	v4l2_event_queue_fh(&ctx->fh, &event);
	put_ctx(ctx);
	return 0;
}

int vsi_v4l2_handle_streamoffdone(struct vsi_v4l2_msg *pmsg)
{
	unsigned long ctxid = pmsg->inst_id;
	struct vsi_v4l2_ctx *ctx;

	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -ESRCH;
	if (pmsg->cmd_id == V4L2_DAEMON_VIDIOC_STREAMOFF_CAPTURE_DONE)
		set_bit(CTX_FLAG_CAPTUREOFFDONE, &ctx->flag);
	else
		set_bit(CTX_FLAG_OUTPUTOFFDONE, &ctx->flag);
	wake_up_interruptible_all(&ctx->capoffdone_queue);
	v4l2_klog(LOGLVL_FLOW, "%lx got cap streamoff done", ctxid);
	put_ctx(ctx);
	return 0;
}

int vsi_v4l2_handle_cropchange(struct vsi_v4l2_msg *pmsg)
{
	unsigned long ctxid = pmsg->inst_id;
	struct vsi_v4l2_ctx *ctx;

	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -ESRCH;

	if (isdecoder(ctx)) {
		struct vsi_v4l2_mediacfg *pcfg = &ctx->mediacfg;
		struct v4l2_event event;

		if (mutex_lock_interruptible(&ctx->ctxlock)) {
			put_ctx(ctx);
			return -EBUSY;
		}
		v4l2_klog(LOGLVL_BRIEF, "%llx sending crop change:%d:%d:%d",
			  ctx->ctxid, ctx->status, ctx->buffed_cropcapnum, ctx->lastcapbuffer_idx);
		v4l2_klog(LOGLVL_BRIEF, "crop info:%d:%d:%d:%d:%d:%d:%d",
			pmsg->params.dec_params.pic_info.pic_info.width,
			pmsg->params.dec_params.pic_info.pic_info.height,
			pmsg->params.dec_params.pic_info.pic_info.pic_wstride,
			pmsg->params.dec_params.pic_info.pic_info.crop_left,
			pmsg->params.dec_params.pic_info.pic_info.crop_top,
			pmsg->params.dec_params.pic_info.pic_info.crop_width,
			pmsg->params.dec_params.pic_info.pic_info.crop_height);
		if ((ctx->status == DEC_STATUS_DECODING || ctx->status == DEC_STATUS_DRAINING)
			&& ctx->buffed_cropcapnum > 0) {
			if (addcropmsg(ctx, pmsg) != 0) {
				vsi_set_ctx_error(ctx, DAEMON_ERR_NO_MEM);
				v4l2_klog(LOGLVL_ERROR, "driver out of mem");
			} else
				set_bit(BUF_FLAG_CROPCHANGE, &ctx->vbufflag[ctx->lastcapbuffer_idx]);
		} else {
			pcfg->decparams.dec_info.io_buffer.output_width = pmsg->params.dec_params.pic_info.pic_info.width;
			pcfg->decparams.dec_info.io_buffer.output_height = pmsg->params.dec_params.pic_info.pic_info.height;
			pcfg->decparams.dec_info.io_buffer.output_wstride = pmsg->params.dec_params.pic_info.pic_info.pic_wstride;
			pcfg->decparams.dec_info.dec_info.frame_width = pmsg->params.dec_params.pic_info.pic_info.width;
			pcfg->bytesperline = pmsg->params.dec_params.pic_info.pic_info.pic_wstride;
			pcfg->decparams.dec_info.dec_info.frame_height = pmsg->params.dec_params.pic_info.pic_info.height;
			pcfg->decparams.dec_info.dec_info.visible_rect.left = pmsg->params.dec_params.pic_info.pic_info.crop_left;
			pcfg->decparams.dec_info.dec_info.visible_rect.top = pmsg->params.dec_params.pic_info.pic_info.crop_top;
			pcfg->decparams.dec_info.dec_info.visible_rect.width = pmsg->params.dec_params.pic_info.pic_info.crop_width;
			pcfg->decparams.dec_info.dec_info.visible_rect.height = pmsg->params.dec_params.pic_info.pic_info.crop_height;
			memset((void *)&event, 0, sizeof(struct v4l2_event));
			event.type = V4L2_EVENT_CROPCHANGE,
			v4l2_event_queue_fh(&ctx->fh, &event);
		}
		mutex_unlock(&ctx->ctxlock);
	}
	put_ctx(ctx);
	return 0;
}

bool vsi_v4l2_dec_in_source_change(struct vsi_v4l2_ctx *ctx)
{
	if (test_bit(CTX_FLAG_DELAY_SRCCHANGED_BIT, &ctx->flag))
		return true;
	if (ctx->reschanged_need_notify)
		return true;
	if (ctx->reschange_notified)
		return true;

	return false;
}

void vsi_v4l2_dec_handle_last_empty_buffer(struct vsi_v4l2_ctx *ctx)
{
	if (vsi_v4l2_dec_in_source_change(ctx))
		return;
	if (ctx->status == DEC_STATUS_DRAINING ||
	    test_bit(CTX_FLAG_PRE_DRAINING_BIT, &ctx->flag)) {
		ctx->status = DEC_STATUS_ENDSTREAM;
		set_bit(CTX_FLAG_ENDOFSTRM_BIT, &ctx->flag);
		clear_bit(CTX_FLAG_PRE_DRAINING_BIT, &ctx->flag);
	}
}

int vsi_v4l2_bufferdone(struct vsi_v4l2_msg *pmsg)
{
	unsigned long ctxid = pmsg->inst_id;
	int inbufidx, outbufidx, bytesused[4] = {0};
	struct vsi_v4l2_ctx *ctx;
	struct vb2_queue *vq = NULL;
	struct vb2_buffer	*vb;
	struct vb2_v4l2_buffer *vbuf;
	struct vsi_vpu_performance_info *info;
	int ret = 0;

	ctx = get_ctx(ctxid);
	if (ctx == NULL)
		return -1;

	info = &ctx->performance;
	if (isencoder(ctx)) {
		inbufidx = pmsg->params.enc_params.io_buffer.inbufidx;
		outbufidx = pmsg->params.enc_params.io_buffer.outbufidx;
		bytesused[0] = pmsg->params.enc_params.io_buffer.bytesused;
	} else {
		inbufidx = pmsg->params.dec_params.io_buffer.inbufidx;
		outbufidx = pmsg->params.dec_params.io_buffer.outbufidx;
		bytesused[0] = pmsg->params.dec_params.io_buffer.bytesused;
	}
	v4l2_klog(LOGLVL_FLOW, "%llx:%s:%lx:%d:%d",
		ctx->ctxid, __func__, ctx->flag, inbufidx, outbufidx);
	//write comes over once, so avoid this problem.
	if (inbufidx >= 0 && inbufidx < ctx->input_que.num_buffers) {
		if (mutex_lock_interruptible(&ctx->ctxlock)) {
			ret = -EBUSY;
			goto out;
		}
		vq = &ctx->input_que;
		vb = vq->bufs[inbufidx];
		if (!vb) {
			v4l2_klog(LOGLVL_ERROR, "%llx:%s:%lx:%d:%d, input vb is NULL pointer\n",
				  ctx->ctxid, __func__, ctx->flag, inbufidx,
				  ctx->input_que.num_buffers);
			mutex_unlock(&ctx->ctxlock);
			goto out;
		}
		atomic_inc(&ctx->srcframen);
		if (ctx->input_que.streaming && vb->state == VB2_BUF_STATE_ACTIVE) {
			vbuf = to_vb2_v4l2_buffer(vb);
			vbuf->sequence = ctx->out_sequence++;
			if (pmsg->param_type & ERROR_BUFFER_FLAG) {
				v4l2_klog(LOGLVL_BRIEF, "got error srcbuf %d\n", inbufidx);
				vb2_buffer_done(vb, VB2_BUF_STATE_ERROR);
			} else {
				vb2_buffer_done(vb, VB2_BUF_STATE_DONE);
			}
		}
		if (isdecoder(ctx)) {
			ctx->queued_srcnum--;
			if (!test_bit(BUF_FLAG_QUEUED, &ctx->srcvbufflag[inbufidx])) {
				v4l2_klog(LOGLVL_WARNING, "got unqueued srcbuf %d", inbufidx);
			} else {
				clear_bit(BUF_FLAG_QUEUED, &ctx->srcvbufflag[inbufidx]);
				set_bit(BUF_FLAG_DONE, &ctx->srcvbufflag[inbufidx]);
			}
		}

		info->processed_buf_num++;
		info->ts_last = ktime_get_raw();
		if (isdecoder(ctx))
			info->total_time += pmsg->params.dec_params.io_buffer.process_time;
		else
			info->total_time += pmsg->params.enc_params.io_buffer.process_time;

		mutex_unlock(&ctx->ctxlock);
	}
	if (outbufidx >= 0 && outbufidx < ctx->output_que.num_buffers) {
		if (mutex_lock_interruptible(&ctx->ctxlock)) {
			ret = -EBUSY;
			goto out;
		}
		if (!inst_isactive(ctx)) {
			if (!vb2_is_streaming(&ctx->output_que))
				v4l2_klog(LOGLVL_ERROR, "%llx ignore dst buffer %d in state %d", ctx->ctxid, outbufidx, ctx->status);
			mutex_unlock(&ctx->ctxlock);
			goto out;
		}
		if (bytesused[0] > 0)
			ctx->frameidx++;
		vq = &ctx->output_que;
		vb = vq->bufs[outbufidx];
		if (!vb) {
			v4l2_klog(LOGLVL_ERROR, "%llx:%s:%lx:%d:%d, output vb is NULL pointer\n",
				  ctx->ctxid, __func__, ctx->flag, outbufidx,
				  ctx->output_que.num_buffers);
			mutex_unlock(&ctx->ctxlock);
			goto out;
		}
		vbuf = to_vb2_v4l2_buffer(vb);

		atomic_inc(&ctx->dstframen);
		if (vb->state == VB2_BUF_STATE_ACTIVE) {
			vb->planes[0].bytesused = bytesused[0];
			if (isencoder(ctx)) {
				struct vsi_vpu_buf *vsibuf = vb_to_vsibuf(vb);

				vsibuf->average_qp = pmsg->params.enc_params.io_buffer.average_qp;
				vb->timestamp = pmsg->params.enc_params.io_buffer.timestamp;
				ctx->vbufflag[outbufidx] = pmsg->param_type;
				v4l2_klog(LOGLVL_FLOW,  "enc output framed %d size = %d,flag=%lx, timestamp=%lld",
						outbufidx, vb->planes[0].bytesused, ctx->vbufflag[outbufidx], vb->timestamp);
				if (vb->planes[0].bytesused == 0 || (pmsg->param_type & LAST_BUFFER_FLAG)) {
					vbuf->flags |= V4L2_BUF_FLAG_LAST;
					ctx->vbufflag[outbufidx] |= LAST_BUFFER_FLAG;
					v4l2_klog(LOGLVL_BRIEF, "%llx encoder got eos buffer", ctx->ctxid);
				}
			} else {
				ctx->lastcapbuffer_idx = outbufidx;
				if (!test_bit(BUF_FLAG_QUEUED, &ctx->vbufflag[outbufidx])) {
					v4l2_klog(LOGLVL_WARNING, "got unqueued dstbuf %d", outbufidx);
				} else {
					clear_bit(BUF_FLAG_QUEUED, &ctx->vbufflag[outbufidx]);
					set_bit(BUF_FLAG_DONE, &ctx->vbufflag[outbufidx]);
				}
				ctx->rfc_luma_offset[outbufidx] = pmsg->params.dec_params.io_buffer.rfc_luma_offset;
				ctx->rfc_chroma_offset[outbufidx] = pmsg->params.dec_params.io_buffer.rfc_chroma_offset;
				if (bytesused[0] == 0) {
					vbuf->flags |= V4L2_BUF_FLAG_LAST;
					v4l2_klog(LOGLVL_BRIEF, "%llx decoder got zero buffer in state %d", ctx->ctxid, ctx->status);
					vsi_v4l2_dec_handle_last_empty_buffer(ctx);
				} else {
					vb->timestamp = pmsg->params.dec_params.io_buffer.timestamp;
					ctx->buffed_capnum++;
					ctx->buffed_cropcapnum++;
				}
				v4l2_klog(LOGLVL_FLOW, "dec output framed %d size = %d", outbufidx, vb->planes[0].bytesused);
			}
			if (bytesused[0] > 0) {
				if (!info->ts_disp_first)
					info->ts_disp_first = ktime_get_raw();
				info->ts_disp_last = ktime_get_raw();
				info->display_frame_num++;
			}
			vbuf->sequence = ctx->cap_sequence++;
			vb2_buffer_done(vb, VB2_BUF_STATE_DONE);
		} else {
			v4l2_klog(LOGLVL_WARNING, "dstbuf %d is not active\n", outbufidx);
		}
		mutex_unlock(&ctx->ctxlock);
	}
	if (ctx->queued_srcnum == 0)
		wake_up_interruptible_all(&ctx->retbuf_queue);
out:
	put_ctx(ctx);
	return ret;
}

void vsi_v4l2_reset_performance(struct vsi_v4l2_ctx *ctx)
{
	struct vsi_vpu_performance_info *info;
	u64 fps_dec = 0, fps_dsp = 0, fps_sw = 0;
	u64 timems;
	u64 latency;
	u64 temp;

	if (!ctx)
		return;

	info = &ctx->performance;
	if (!info->processed_buf_num)
		goto exit;

	temp = MSEC_PER_SEC * info->processed_buf_num;
	timems = (info->ts_last - info->ts_start) / NSEC_PER_MSEC;
	fps_dec = DIV_ROUND_CLOSEST(temp, timems);
	if (info->total_time)
		fps_sw = DIV_ROUND_CLOSEST(temp, info->total_time / NSEC_PER_MSEC);
	if (info->display_frame_num > 1) {
		temp = MSEC_PER_SEC * (info->display_frame_num - 1);
		timems = (info->ts_disp_last - info->ts_disp_first) / NSEC_PER_MSEC;
		fps_dsp = DIV_ROUND_CLOSEST(temp, timems);
	}
	latency = info->ts_disp_first - info->ts_start;

	v4l2_klog(LOGLVL_FLOW,
		  "[%llx]fps actual: %llu, disp: %llu, ideal: %llu, latency(ms) %llu.%06llu\n",
		  ctx->ctxid, fps_dec, fps_dsp, fps_sw,
		  latency / NSEC_PER_MSEC, latency % NSEC_PER_MSEC);
exit:
	memset(info, 0, sizeof(*info));
}

static void vsi_daemonsdevice_release(struct device *dev)
{
}

static int v4l2_probe(struct platform_device *pdev)
{
	struct vsi_v4l2_device *vpu = NULL;
	struct video_device *venc, *vdec;
	int ret = 0;

	v4l2_klog(LOGLVL_BRIEF, "%s", __func__);
	if (gvsidev != NULL)
		return 0;
	vpu = kzalloc(sizeof(*vpu), GFP_KERNEL);
	if (!vpu)
		return -ENOMEM;

	vpu->dev = &pdev->dev;
	vpu->pdev = pdev;
	mutex_init(&vpu->lock);
	mutex_init(&vpu->irqlock);

	ret = v4l2_device_register(&pdev->dev, &vpu->v4l2_dev);
	if (ret) {
		v4l2_klog(LOGLVL_ERROR, "Failed to register v4l2 device\n");
		kfree(vpu);
		return ret;
	}
	platform_set_drvdata(pdev, vpu);

	vpu->venc = NULL;
	vpu->vdec = NULL;
	venc = vsi_v4l2_probe_enc(pdev, vpu);
	if (venc == NULL)
		goto err;
	vpu->venc = venc;

        vdec = vsi_v4l2_probe_dec(pdev, vpu);
        if (vdec == NULL)
                goto err;
        vpu->vdec = vdec;

        ret = vsiv4l2_initdaemon();
        if (ret < 0)
                goto err;

	vsidaemondev = kzalloc(sizeof(struct device), GFP_KERNEL);
	vsidaemondev->class = class_create("vsi_class");
	vsidaemondev->parent = NULL;
	vsidaemondev->devt = MKDEV(VSI_DAEMON_DEVMAJOR, 0);
	dev_set_name(vsidaemondev, "%s", VSI_DAEMON_FNAME);
	vsidaemondev->release = vsi_daemonsdevice_release;
	ret = device_register(vsidaemondev);
	if (ret < 0) {
		kfree(vsidaemondev);
		vsidaemondev = NULL;
                vsiv4l2_cleanupdaemon();
                goto err;
        }
        idr_init(&vsi_inst_array);
#if IS_ENABLED(CONFIG_DEBUG_FS)
        vpu->debugfs = debugfs_create_dir(VSI_V4L2_DEBUGFS_DIR, NULL);
        if (IS_ERR_OR_NULL(vpu->debugfs))
                vpu->debugfs = NULL;
#else
        vpu->debugfs = NULL;
#endif

        gvsidev = pdev;
        mutex_init(&vsi_ctx_array_lock);
        ctx_seqid = 0;
	if (devm_device_add_group(&gvsidev->dev, &vsi_v4l2_attr_group))
		v4l2_klog(LOGLVL_ERROR, "fail to create sysfs API");

	v4l2_klog(LOGLVL_BRIEF, "vpu v4l2: module inserted. Major = %d\n", VSI_DAEMON_DEVMAJOR);
	return 0;

err:
	v4l2_klog(LOGLVL_ERROR, "vsi v4l2 dev probe fail with errno %d", ret);
	if (vpu->venc) {
		vsi_v4l2_release_enc(vpu->venc);
		video_device_release(vpu->venc);
	}
	if (vpu->vdec) {
		vsi_v4l2_release_dec(vpu->vdec);
		video_device_release(vpu->vdec);
	}
	v4l2_device_unregister(&vpu->v4l2_dev);
	kfree(vpu);

	return ret;
}

static int v4l2_remove(struct platform_device *pdev)
{
	void *obj;
	int id;
	struct vsi_v4l2_device *vpu = platform_get_drvdata(pdev);

	idr_for_each_entry(&vsi_inst_array, obj, id) {
		if (obj) {
			release_ctx(obj, 0);
			vsi_v4l2_quitinstance();
		}
	}

	debugfs_remove_recursive(vpu->debugfs);
	vpu->debugfs = NULL;
	vsi_v4l2_release_dec(vpu->vdec);
	vsi_v4l2_release_enc(vpu->venc);
	v4l2_device_unregister(&vpu->v4l2_dev);
	platform_set_drvdata(pdev, NULL);
	kfree(vpu);

	device_unregister(vsidaemondev);
	class_destroy(vsidaemondev->class);
	kfree(vsidaemondev);
	vsiv4l2_cleanupdaemon();
	gvsidev = NULL;
	return 0;
}

static const struct platform_device_id v4l2_platform_ids[] = {
	{
		.name            = DRIVER_NAME,
	},
	{ },
};

static const struct of_device_id v4l2_of_match[] = {
	{ .compatible = "nxp,imx8m-vsiv4l2", },
	{/* sentinel */}
};

static struct platform_driver v4l2_drm_platform_driver = {
	.probe      = v4l2_probe,
	.remove      = v4l2_remove,
	.driver      = {
		.name      = DRIVER_NAME,
		.owner		= THIS_MODULE,
		.of_match_table = v4l2_of_match,
	},
	.id_table = v4l2_platform_ids,
};

module_platform_driver(v4l2_drm_platform_driver);

/* module description */
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Verisilicon");
MODULE_DESCRIPTION("VSI v4l2 manager");

