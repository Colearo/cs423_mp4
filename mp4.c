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

	char * cred_ctx;
	struct dentry *de = d_find_alias(inode);
	int ret, sid, len;

	if (!de) {
		pr_err("%s, NULL dentry\n", __func__);
		return -EFAULT;
	}

	// Assign the default length of the xattr value for security.mp4
	len = XATTR_NAME_MP4_LEN;
	// Allocate a certain buffer
	cred_ctx = kmalloc(len, GFP_NOFS);
	if (!cred_ctx) {
		dput(de);
		pr_err("%s, could not allocate mem\n", __func__);
		return -ENOMEM;
	}
	// Clean the momory 
	memset(cred_ctx, 0, len);

	// If there are no getxattr handlers, just return zero
	if (!inode->i_op->getxattr) {
		dput(de);
		kfree(cred_ctx);
		return 0;
	}

	// Get the extended attribute of namespace in XATTR_NAME_MP4
	ret = inode->i_op->getxattr(de, XATTR_NAME_MP4, cred_ctx, len);

	// If the length of current label out of range
	if (ret == -ERANGE) {
	    kfree(cred_ctx);
	    // We need a larger buffer, query it
	    ret = inode->i_op->getxattr(de, XATTR_NAME_MP4, NULL, 0);
	    if (ret < 0) {
		dput(de);
		pr_err("%s, query the correct size of xattr failed", __func__);
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
	    ret = inode->i_op->getxattr(de, XATTR_NAME_MP4, cred_ctx, len);
	}

	dput(de);

	if (ret < 0) {
	    // If there is this label but some errors exists
	    // just return the error code
	    if (ret != -ENODATA) {
		pr_err("%s, get the xattr failed\n", __func__);
		kfree(cred_ctx);
		return ret;
	    }

	} else {
	    /*pr_info("cred_ctx: %s\n", cred_ctx);*/
	    sid = __cred_ctx_to_sid(cred_ctx);
	    ret = sid;
	}

	kfree(cred_ctx);
	return ret;
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

	// Get the inode of the binary file for the new process
	struct inode *in;
	struct mp4_security * mp4_ctx;
	int sid;

	// If the NULL pointers in these fields, just return
	if (!bprm->cred || !bprm->cred->security || !bprm->file || !bprm->file->f_inode) {
	    pr_err("%s, bprm credential or security context or inode is NULL\n", __func__);
	    return 0;
	}

	in = bprm->file->f_inode;
	sid = get_inode_sid(in);

	if (sid == MP4_TARGET_SID) {
		mp4_ctx = bprm->cred->security;
		mp4_ctx->mp4_flags = sid;
		pr_info("%s, set the binary credential done\n", __func__);
	}
	
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
	if (ctx == NULL) 
		return -ENOMEM;

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
    	struct mp4_security *ctx = old->security, *new_ctx;
	// Create the security field for new
	mp4_cred_alloc_blank(new, gfp);
	// If old credential has security context
	if (ctx) {
	    new_ctx = new->security;
	    new_ctx->mp4_flags = ctx->mp4_flags;
	}
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
    	struct mp4_security *mp4_ctx;
	char *xattr_value;
	size_t size;
    	
    	// If the inode or directiory is NULL
    	if (!inode || !dir) 
	    return -EOPNOTSUPP;

	// If the current task credential or its security context is NULL
	if (!current_cred() || !current_cred()->security) 
	    return -EOPNOTSUPP;

	mp4_ctx = current_cred()->security;

	// If not created by target task, skip it
	if (mp4_ctx->mp4_flags != MP4_TARGET_SID) 
	    return -EOPNOTSUPP;

	// If the memory name pointing to is not NULL, assign it the xattr
	// name
	if (name) {
	    *name = kstrndup(XATTR_MP4_SUFFIX, XATTR_NAME_MP4_LEN, GFP_NOFS);
	    if (!*name)
		return -ENOMEM;
	}

	// Set the value to read-write for these tasks with target label
	if (value && len) {
	    xattr_value = kmalloc(XATTR_NAME_MP4_LEN, GFP_NOFS);
	    if (!xattr_value)
		return -ENOMEM;

	    if (S_ISDIR(inode->i_mode))
		size = sprintf(xattr_value, "dir");
	    else 
		size = sprintf(xattr_value, "read-write");

	    xattr_value[size] = 0;
	    *value = (void *)xattr_value;
	    *len = size;
	}

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
    	
    	// If there are no masks about the MAY_READ/MAY_WRITE/MAY_ACCESS/MAY_EXEC
	// pass the permission control to the Linux default access control
	mask &= (MAY_READ|MAY_WRITE|MAY_ACCESS|MAY_EXEC);
	if (!mask)
	    return 0;
    	
    	switch(osid) {
	    // May not be accessed by target, but may be any others
	    // So if the ssid is target, just deny
	    case MP4_NO_ACCESS:
		if (ssid == MP4_TARGET_SID)
		    goto DENY;
		else 
		    goto PERMIT;
	    // May only be read by anyone
	    case MP4_READ_OBJ:
		if ((mask & (MAY_READ)) == mask)
		    goto PERMIT;
		else 
		    goto DENY;
	    // May be read/write/append by target 
	    // and read by others
	    case MP4_READ_WRITE:
		if (ssid == MP4_TARGET_SID)
		    if ((mask & (MAY_READ | MAY_WRITE | MAY_APPEND)) == mask)
			goto PERMIT;
		    else
			goto DENY;
		else 
		    if ((mask & (MAY_READ)) == mask)
			goto PERMIT;
		    else 
			goto DENY;
	    // May be written/appended by target
	    // and only read by others
	    case MP4_WRITE_OBJ:
		if (ssid == MP4_TARGET_SID)
		    if ((mask & (MAY_WRITE | MAY_APPEND)) == mask)
			goto PERMIT;
		    else 
			goto DENY;
		else
		    if ((mask & (MAY_READ)) == mask)
			goto PERMIT;
		    else 
			goto DENY;
	    // May be read/executed by all
	    case MP4_EXEC_OBJ:
		if ((mask & (MAY_READ | MAY_EXEC)) == mask)
		    goto PERMIT;
		else
		    goto DENY;
	    // May be read/exec/access by all
	    case MP4_READ_DIR:
		if (ssid == MP4_TARGET_SID)
		    if ((mask & (MAY_READ | MAY_EXEC | MAY_ACCESS)) == mask)
			goto PERMIT;
		    else 
			goto DENY;
		else 
		    goto PERMIT;
	    // May be read/access by all
	    case MP4_RW_DIR:
		if (ssid == MP4_TARGET_SID)
		    if ((mask & (MAY_READ | MAY_ACCESS)) == mask)
			goto PERMIT;
		    else 
			goto DENY;
		else 
		    goto PERMIT;
	}
PERMIT:
	return 0;
DENY:
	return -EACCES;
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
    	struct dentry *de;
	const struct cred *cur_cred = current_cred();
	struct mp4_security *mp4_ctx;
	char *res, *buf;
	int osid, ssid;

    	if (!inode)
	    return 0;

	// Find the dentry from inode
	de = d_find_alias(inode);
	if (!de)
	    return 0;

	buf = kzalloc(PATH_LEN * sizeof(char), GFP_KERNEL);
	if (!buf) {
	    dput(de);
	    return 0;
	}

	// Get the dentry corresponding path
	res = dentry_path_raw(de, buf, PATH_LEN);
	if (IS_ERR(res)) {
	    pr_err("%s, could not find path\n", __func__);
	    kfree(buf);
	    dput(de);
	    return 0;
	}

	// Skip the pathes which has the prefixes described in helper func
	if (mp4_should_skip_path(res)) {
	    kfree(buf);
	    dput(de);
	    return 0;
	}

	// Get the object sid
	osid = get_inode_sid(inode);
	if (osid < 0) {
	    /*pr_err("%s, could not get osid\n", __func__);*/
	    osid = MP4_NO_ACCESS;
	}

	kfree(buf);
	dput(de);

	// Check the current task credential
	if (!cur_cred) 
	    return 0;

	// Get the sid of the current task
	ssid = MP4_NO_ACCESS;
	mp4_ctx = cur_cred->security;
	if (mp4_ctx) 
	    ssid = mp4_ctx->mp4_flags;

	/*pr_info("%s, ssid %d, osid %d\n", res, ssid, osid);*/

	// Check the permissions
	if (mp4_has_permission(ssid, osid, mask)) {
	    pr_info("%s, DENY: ssid %d, osid %d\n", res, ssid, osid);
	    return -EACCES;
	}

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
