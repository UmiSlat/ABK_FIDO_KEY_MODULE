/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ABK_FIDO_KEY_H
#define _LINUX_ABK_FIDO_KEY_H

#include <linux/list.h>
#include <linux/usb/composite.h>

#if IS_ENABLED(CONFIG_ABK_FIDO_KEY)
int abk_fido_key_prepare_config(struct usb_composite_dev *cdev,
				struct usb_configuration *cfg,
				struct list_head *func_list);
int abk_fido_key_add_config_function(struct usb_configuration *cfg,
				     struct usb_function *f);
void abk_fido_key_release_config(struct list_head *func_list);
#else
static inline int abk_fido_key_prepare_config(struct usb_composite_dev *cdev,
					      struct usb_configuration *cfg,
					      struct list_head *func_list)
{
	return 0;
}

static inline int abk_fido_key_add_config_function(struct usb_configuration *cfg,
						   struct usb_function *f)
{
	return usb_add_function(cfg, f);
}

static inline void abk_fido_key_release_config(struct list_head *func_list)
{
}
#endif

#endif
