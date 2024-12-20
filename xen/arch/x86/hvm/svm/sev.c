#include <xen/lib.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/page-size.h>
#include <xen/pfn.h>
#include <asm/hvm/svm/sev.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/psp-sev.h>
#include "svm.h"

uint64_t __read_mostly pte_c_bit_mask;
unsigned int __read_mostly min_sev_asid;
unsigned int __read_mostly max_sev_asid;

static long add_memory(struct domain *d, domid_t domid, gfn_t gfn, uint64_t pages)
{
    long rc = 0;
    int psp_ret;
    struct sev_data_launch_update_data sd_lud;

    for (size_t i = 0; i < pages; i++)
    {
        p2m_type_t p2mt;

        mfn_t mfn = get_gfn_unshare(d, gfn + i, &p2mt);
        if ( p2m_is_shared(p2mt) || !p2m_is_valid(p2mt) )
            // Do not try to encrypt shared pages.
            mfn = INVALID_MFN;

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(mfn)) )
        {
            printk("%s: Invalid GFN (%"PRI_xen_pfn")", __FUNCTION__, gfn);
            rc = -ENOENT;
            put_gfn(d, mfn);
            break;
        }

        sd_lud.reserved = 0;
        sd_lud.handle = d->arch.hvm.svm.asp_handle;
        sd_lud.address = PFN_UP(mfn);
        sd_lud.len = PAGE_SIZE;
        rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_DATA, (void *)(&sd_lud), &psp_ret,
                        true);
        if (rc)
        {
            printk("%s: failed to LAUNCH_UPDATE_DATA to domain(%d): psp_ret %d (gfn=%" PRI_xen_pfn "\n",
                    __FUNCTION__, domid, psp_ret, gfn + i);
            break;
        }
    }
    
    return rc;
}

long svm_dom_coco_op(unsigned int cmd, domid_t domid, uint64_t gfn, uint64_t pages)
{
    struct domain *d;
    int psp_ret;
    long rc = 0;

    if (!is_control_domain(current->domain))
        return -EPERM;

    d = rcu_lock_domain_by_id(domid);
    if (!d) {
        printk(XENLOG_INFO "Domain lookup failed for domid: %u\n", domid);
        return -ENOENT;
    }

    printk(XENLOG_INFO "Domain id in svm_dom_coco_op is : %u\n", domid);
    if (!is_sev_domain(d))
        return -EOPNOTSUPP;

    printk(XENLOG_INFO "Handling command: %u\n", cmd);
    switch (cmd) {
        case COCO_DOM_ADD_MEM:
            add_memory(d, domid, gfn, pages);
            break;
        default:
            printk ("%s: unsupported command called (%u)\n", __FUNCTION__, cmd);
            rc = -EINVAL;

    }
    printk(XENLOG_INFO "reached the end of svm_dom_coco_op called\n");

    rcu_unlock_domain(d);
    return rc;
}

int  sev_domain_initialize(struct domain *d)
{
    struct sev_data_launch_start sd_ls;
    struct sev_data_activate sd_a;
    int psp_ret;
    long rc = 0;

    printk(XENLOG_INFO "sev_domain_initialise called\n");

    sd_ls.handle = 0;          /* generate new one */
    sd_ls.policy = 0;          /* NOKS policy */
    sd_ls.dh_cert_address = 0; /* do not DH stuff */

    rc = sev_do_cmd(SEV_CMD_LAUNCH_START, (void *)(&sd_ls), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_START domain(%d): psp_ret %d\n",
             __FUNCTION__, d->domain_id, psp_ret);
      return rc;
    }

    sd_a.handle = sd_ls.handle;
    sd_a.asid = d->arch.hvm.n1asid.asid;

    rc = sev_do_cmd(SEV_CMD_ACTIVATE, (void *)(&sd_a), &psp_ret, true);
    if (rc) {
      printk("%s: failed to ACTIVATE domain(%d): psp_ret %d\n", __FUNCTION__,
             d->domain_id, psp_ret);
      return rc;
    }

    d->arch.hvm.svm.asp_handle = sd_ls.handle;
    d->arch.hvm.svm.asp_policy = 0;

    /* AVIC isn't supported for SEV guests */
    svm_avic_disable(d);

    return 0;
}

int sev_domain_creation_finished(struct domain *d)
{
    struct sev_data_launch_measure sd_lm;
    struct sev_data_launch_finish sd_lf;
    int psp_ret;
    long rc = 0;

    printk(XENLOG_INFO "sev_domain_creation_finished called\n");

    sd_lm.handle = d->arch.hvm.svm.asp_handle;
    sd_lm.address = __pa(d->arch.hvm.svm.measure);
    sd_lm.len = 32;


    rc = sev_do_cmd(SEV_CMD_LAUNCH_MEASURE, (void *)(&sd_lm), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_MEASURE domain(%d): psp_ret %d\n",
             __FUNCTION__, d->domain_id, psp_ret);
      return rc;
    }

    sd_lf.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_FINISH, (void *)(&sd_lf), &psp_ret, true);
    if (rc) {
      printk("%s: failed to LAUNCH_FINISH domain(%d): psp_ret %d\n",
             __FUNCTION__, d->domain_id, psp_ret);
      return rc;
    }

    return 0;
}

void sev_domain_destroy(struct domain *d)
{
    struct sev_data_deactivate sd_da;
    struct sev_data_decommission sd_de;
    int psp_ret;
    long rc = 0;

    sd_da.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DEACTIVATE, (void *)(&sd_da), &psp_ret, true);
    if (rc) {
      printk("%s: failed to DEACTIVATE domain(%d): psp_ret %d\n", __FUNCTION__,
             d->domain_id, psp_ret);
      return;
    }

    sd_de.handle = d->arch.hvm.svm.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DECOMMISSION, (void *)(&sd_de), &psp_ret, true);
    if (rc) {
      printk("%s: failed to DECOMMISSION domain(%d): psp_ret %d\n",
             __FUNCTION__, d->domain_id, psp_ret);
      return;
    }

    d->arch.hvm.svm.asp_handle = 0;
}

int  sev_vcpu_initialize(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    u32 bitmap = vmcb_get_exception_intercepts(vmcb);

    vmcb_set_np_ctrl(vmcb, vmcb_get_np_ctrl(vmcb) | NPCTRL_SEV_ENABLE);

    bitmap &= ~((1U << X86_EXC_UD) | (1U << X86_EXC_GP));
    vmcb_set_exception_intercepts(vmcb, bitmap);

    return 0;
}

void sev_vcpu_destroy(struct vcpu *v)
{
    /* Nothing to do here for instance */
}

int  sev_create_vmcb(struct vcpu *v)
{
    /* VMSA related (nothing to do for instance) */
    return 0;
}

void sev_destroy_vmcb(struct vcpu *v)
{
    /* VMSA related (nothing to do for instance) */
}
