#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}

/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	/*
	 * Add your code here
	 * ...
	 */

    	// Get the dentry of the binary file for the new process
	struct dentry *de = bprm->file.f_path->dentry;
	// Get the inode
	struct inode *in = bprm->file->f_inode;
	// Credential context - the extended attribute value
	char * cred_ctx;
	struct cred* cur_cred;
	int ret, len, sid;

	// Assign the default length of the xattr value for security.mp4
	len = XATTR_NAME_MP4_LEN;
	// Allocate a certain buffer
	cred_ctx = kmalloc(len, GFP_NOFS);
	if (!cred_ctx) {
	    return -ENOMEM;
	}
	// Clean the momory 
	memset(cred_ctx, 0, len);
	// Get the extended attribute of namespace in XATTR_NAME_MP4
	ret = in->i_op->getxattr(de, XATTR_NAME_MP4, cred_ctx, len);

	// If the length of current label out of range
	if (ret == -ERANGE) {
	    kfree(context);
	    // We need a larger buffer, query it
	    ret = in->i_op->getxattr(de, XATTR_NAME_MP4, NULL, 0);
	    if (ret < 0) {
		dput(de);
		pr_err("Query the correct size of xattr failed")
		return ret;
	    }

	    len = ret;
	    cred_ctx = kmalloc(len + 1, GFP_NOFS);
	    if (!cred_ctx) {
		dput(de);
		return -ENOMEM;
	    }
	    cred_ctx[len] = 0;
	    // Get the xattr again with right size
	    ret = in->i_op->getxattr(de, XATTR_NAME_MP4, cred_ctx, len);
	}

	dput(de);

	if (ret < 0) {
	    // If there is this label but some errors exists
	    // just return
	    if (ret != -ENODATA) {
		pr_err("Get the xattr failed");
		kfree(cred_ctx);
		return ret;
	    }
	    ret = 0;
	} else {
	    sid = __cred_ctx_to_sid(cred_ctx);
	    if (sid == MP4_TARGET_SID) {
		cur_cred = current_cred();
		(struct mp4_security *)(cur_cred->security)->mp4_flags = sid;
	    }
	    (struct mp4_security *)(bprm->cred->security)->mp4_flags = sid;
	}
	kfree(cred_ctx)
	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/*
	 * Add your code here
	 * ...
	 */
    	struct mp4_security *ctx = kzalloc(sizeof(struct mp4_security), gfp);
	ctx->mp4_flags = MP4_NO_ACCESS;
    	cred->security = ctx;
	return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	/*
	 * Add your code here
	 * ...
	 */
    	kfree(cred->security);
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
    	struct mp4_security *ctx = old->security;
	new->security = ctx;
	return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");
	mp4_init_msg();

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
