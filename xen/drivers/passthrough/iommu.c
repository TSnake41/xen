/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/atomic.h>
#include <xen/errno.h>
#include <xen/xmalloc.h>
#include <xen/pci.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/iommu.h>
#include <xen/param.h>
#include <xen/keyhandler.h>
#include <asm/arena.h>
#include <asm/iommu.h>
#include <asm/bitops.h>

#ifdef CONFIG_X86
#include <asm/e820.h>
#endif

unsigned int __read_mostly iommu_dev_iotlb_timeout = 1000;
integer_param("iommu_dev_iotlb_timeout", iommu_dev_iotlb_timeout);

bool __initdata iommu_enable = 1;
bool __read_mostly iommu_enabled;
bool __read_mostly force_iommu;
bool __read_mostly iommu_verbose;
static bool __read_mostly iommu_crash_disable;

static bool __hwdom_initdata iommu_hwdom_none;
bool __hwdom_initdata iommu_hwdom_strict;
bool __read_mostly iommu_hwdom_passthrough;
bool __hwdom_initdata iommu_hwdom_inclusive;
bool __read_mostly iommu_hwdom_no_dma = false;
int8_t __hwdom_initdata iommu_hwdom_reserved = -1;

#ifndef iommu_hap_pt_share
bool __read_mostly iommu_hap_pt_share = true;
#endif

bool __read_mostly iommu_debug;

DEFINE_PER_CPU(bool, iommu_dont_flush_iotlb);

static int __init cf_check parse_iommu_param(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            iommu_enable = val;
        else if ( (val = parse_boolean("force", s, ss)) >= 0 ||
                  (val = parse_boolean("required", s, ss)) >= 0 )
            force_iommu = val;
#ifdef CONFIG_HAS_PCI
        else if ( (val = parse_boolean("quarantine", s, ss)) >= 0 )
            iommu_quarantine = val;
        else if ( ss == s + 23 && !strncmp(s, "quarantine=scratch-page", 23) )
            iommu_quarantine = IOMMU_quarantine_scratch_page;
#endif
        else if ( (val = parse_boolean("igfx", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_igfx = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("qinval", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_qinval = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
#ifdef CONFIG_X86
        else if ( (val = parse_boolean("superpages", s, ss)) >= 0 )
            iommu_superpages = val;
#endif
        else if ( (val = parse_boolean("verbose", s, ss)) >= 0 )
            iommu_verbose = val;
#ifndef iommu_snoop
        else if ( (val = parse_boolean("snoop", s, ss)) >= 0 )
            iommu_snoop = val;
#endif
#ifndef iommu_intremap
        else if ( (val = parse_boolean("intremap", s, ss)) >= 0 )
            iommu_intremap = val ? iommu_intremap_full : iommu_intremap_off;
#endif
#ifndef iommu_intpost
        else if ( (val = parse_boolean("intpost", s, ss)) >= 0 )
            iommu_intpost = val;
#endif
#ifdef CONFIG_KEXEC
        else if ( (val = parse_boolean("crash-disable", s, ss)) >= 0 )
            iommu_crash_disable = val;
#endif
        else if ( (val = parse_boolean("debug", s, ss)) >= 0 )
        {
            iommu_debug = val;
            if ( val )
                iommu_verbose = 1;
        }
        else if ( (val = parse_boolean("amd-iommu-perdev-intremap", s, ss)) >= 0 )
#ifdef CONFIG_AMD_IOMMU
            amd_iommu_perdev_intremap = val;
#else
            no_config_param("AMD_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("dom0-passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("dom0-strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
#ifndef iommu_hap_pt_share
        else if ( (val = parse_boolean("sharept", s, ss)) >= 0 )
            iommu_hap_pt_share = val;
#endif
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("iommu", parse_iommu_param);

static int __init cf_check parse_dom0_iommu_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        int val;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
        else if ( (val = parse_boolean("map-inclusive", s, ss)) >= 0 )
            iommu_hwdom_inclusive = val;
        else if ( (val = parse_boolean("map-reserved", s, ss)) >= 0 )
            iommu_hwdom_reserved = val;
        else if ( !cmdline_strcmp(s, "none") )
            iommu_hwdom_none = true;
        else if ( (val = parse_boolean("dma", s, ss)) >= 0 )
            iommu_hwdom_no_dma = !val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0-iommu", parse_dom0_iommu_param);

static void __hwdom_init check_hwdom_reqs(struct domain *d)
{
    if ( iommu_hwdom_none || !is_hvm_domain(d) )
        return;

    iommu_hwdom_passthrough = false;
    iommu_hwdom_strict = true;

    arch_iommu_check_autotranslated_hwdom(d);
}

int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx, uint32_t arena_order)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    BUG_ON(nb_ctx == 0); /* sanity check (prevent underflow) */

    /*
     * hd->other_contexts.count is always reported as 0 during initialization
     * preventing misuse of partially initialized IOMMU contexts.
     */

    if ( atomic_cmpxchg(&hd->other_contexts.initialized, 0, 1) == 1 )
        return -EACCES;

    if ( (nb_ctx - 1) > 0 ) {
        /* Initialize context bitmap */
        size_t i;

        hd->other_contexts.bitmap = xzalloc_array(unsigned long,
                                                  BITS_TO_LONGS(nb_ctx - 1));

        if (!hd->other_contexts.bitmap)
        {
            rc = -ENOMEM;
            goto cleanup;
        }

        hd->other_contexts.map = xzalloc_array(struct iommu_context, nb_ctx - 1);

        if (!hd->other_contexts.map)
        {
            rc = -ENOMEM;
            goto cleanup;
        }

        for (i = 0; i < (nb_ctx - 1); i++)
            rspin_lock_init(&hd->other_contexts.map[i].lock);
    }

    rc = arch_iommu_pviommu_init(d, nb_ctx, arena_order);

    if ( rc )
        goto cleanup;

    /* Make sure initialization is complete before making it visible to other CPUs. */
    smp_wmb();

    hd->other_contexts.count = nb_ctx - 1;

    printk(XENLOG_INFO "Dom%d uses %lu IOMMU contexts (%llu pages arena)\n",
           d->domain_id, (unsigned long)nb_ctx, 1llu << arena_order);

    return 0;

cleanup:
    /* TODO: Reset hd->other_contexts.initialized */
    if ( hd->other_contexts.bitmap )
    {
        xfree(hd->other_contexts.bitmap);
        hd->other_contexts.bitmap = NULL;
    }

    if ( hd->other_contexts.map )
    {
        xfree(hd->other_contexts.map);
        hd->other_contexts.bitmap = NULL;
    }

    return rc;
}

int iommu_domain_pviommu_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    int i;
    /* FIXME: Potential race condition with remote_op ? */

    for (i = 0; i < hd->other_contexts.count; i++)
        WARN_ON(iommu_context_free(d, i, IOMMU_TEARDOWN_REATTACH_DEFAULT) != ENOENT);

    hd->other_contexts.count = 0;

    if ( hd->other_contexts.bitmap )
        xfree(hd->other_contexts.bitmap);

    if ( hd->other_contexts.map )
        xfree(hd->other_contexts.map);

    return 0;
}

int iommu_domain_init(struct domain *d, unsigned int opts)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret = 0;

    if ( is_hardware_domain(d) )
        check_hwdom_reqs(d); /* may modify iommu_hwdom_strict */

    if ( !is_iommu_enabled(d) )
        return 0;

#ifdef CONFIG_NUMA
    hd->node = NUMA_NO_NODE;
#endif

    rspin_lock_init(&hd->default_ctx.lock);

    ret = arch_iommu_domain_init(d);
    if ( ret )
        return ret;

    hd->platform_ops = iommu_get_ops();
    ret = iommu_call(hd->platform_ops, init, d);
    if ( ret || (is_system_domain(d) && d != dom_io) )
        return ret;

    /*
     * Use shared page tables for HAP and IOMMU if the global option
     * is enabled (from which we can infer the h/w is capable) and
     * the domain options do not disallow it. HAP must, of course, also
     * be enabled.
     */
    hd->hap_pt_share = hap_enabled(d) && iommu_hap_pt_share &&
        !(opts & XEN_DOMCTL_IOMMU_no_sharept);

    /*
     * NB: 'relaxed' h/w domains don't need the IOMMU mappings to be kept
     *     in-sync with their assigned pages because all host RAM will be
     *     mapped during hwdom_init().
     */
    if ( !is_hardware_domain(d) || iommu_hwdom_strict )
        hd->need_sync = !iommu_use_hap_pt(d);

    ASSERT(!(hd->need_sync && hd->hap_pt_share));

    if ( hd->no_dma )
    {
        /* No-DMA mode is exclusive with HAP and sync_pt. */
        hd->hap_pt_share = false;
        hd->need_sync = false;
    }

    hd->allow_pv_iommu = true;

    iommu_context_init(d, &hd->default_ctx, 0, IOMMU_CONTEXT_INIT_default);

    rwlock_init(&hd->other_contexts.lock);
    hd->other_contexts.initialized = (atomic_t)ATOMIC_INIT(0);
    hd->other_contexts.count = 0;
    hd->other_contexts.bitmap = NULL;
    hd->other_contexts.map = NULL;

    return 0;
}

static void cf_check iommu_dump_page_tables(unsigned char key)
{
    struct domain *d;

    ASSERT(iommu_enabled);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
    {
        if ( !is_iommu_enabled(d) )
            continue;

        if ( iommu_use_hap_pt(d) )
            printk("%pd sharing page tables\n", d);

        iommu_vcall(dom_iommu(d)->platform_ops, dump_page_tables, d);
    }

    rcu_read_unlock(&domlist_read_lock);
}

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) )
        return;

    register_keyhandler('o', &iommu_dump_page_tables, "dump iommu page tables", 0);

    iommu_vcall(hd->platform_ops, hwdom_init, d);
}

void cf_check iommu_domain_destroy(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct pci_dev *pdev;

    if ( !is_iommu_enabled(d) )
        return;

    /*
     * During early domain creation failure, we may reach here with the
     * ops not yet initialized.
     */
    if ( !hd->platform_ops )
        return;

    /* Move all devices back to quarantine */
    /* TODO: Is it needed ? */
    for_each_pdev(d, pdev)
    {
        int rc = iommu_reattach_context(d, dom_io, pdev, 0);

        if ( rc )
        {
            printk(XENLOG_WARNING "Unable to quarantine device %pp (%d)\n", &pdev->sbdf, rc);
            pdev->broken = true;
        }
        else
            pdev->domain = dom_io;
    }

    iommu_vcall(hd->platform_ops, teardown, d);

    iommu_domain_pviommu_teardown(d);
    arch_iommu_domain_destroy(d);
}

int __init iommu_setup(void)
{
    int rc = -ENODEV;
    bool force_intremap = force_iommu && iommu_intremap;

    if ( iommu_hwdom_strict )
        iommu_hwdom_passthrough = false;

    if ( iommu_enable )
    {
        const struct iommu_ops *ops = NULL;

        rc = iommu_hardware_setup();
        if ( !rc )
            ops = iommu_get_ops();
        if ( ops && (ISOLATE_LSB(ops->page_sizes)) != PAGE_SIZE )
        {
            printk(XENLOG_ERR "IOMMU: page size mask %lx unsupported\n",
                   ops->page_sizes);
            rc = ops->page_sizes ? -EPERM : -ENODATA;
        }
        iommu_enabled = (rc == 0);
    }

#ifndef iommu_intremap
    if ( !iommu_enabled )
        iommu_intremap = iommu_intremap_off;
#endif

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force\n",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

#ifndef iommu_intpost
    if ( !iommu_intremap )
        iommu_intpost = false;
#endif

    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( !iommu_enabled )
    {
        iommu_hwdom_passthrough = false;
        iommu_hwdom_strict = false;
    }
    else
    {
        if ( iommu_quarantine_init() )
            panic("Could not set up quarantine\n");

        printk(" - Dom0 mode: %s\n",
               iommu_hwdom_passthrough ? "Passthrough" :
               iommu_hwdom_strict ? "Strict" : "Relaxed");
#ifndef iommu_intremap
        printk("Interrupt remapping %sabled\n", iommu_intremap ? "en" : "dis");
#endif
    }

    return rc;
}

int iommu_suspend(void)
{
    if ( iommu_enabled )
        return iommu_call(iommu_get_ops(), suspend);

    return 0;
}

void iommu_resume(void)
{
    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), resume);
}

int iommu_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int ret = -ENODEV;

    if ( !(d ? is_iommu_enabled(d) : iommu_enabled) )
        return -EOPNOTSUPP;

#ifdef CONFIG_HAS_PCI
    ret = iommu_do_pci_domctl(domctl, d, u_domctl);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
    if ( ret == -ENODEV )
        ret = iommu_do_dt_domctl(domctl, d, u_domctl);
#endif

    return ret;
}

void iommu_crash_shutdown(void)
{
    if ( !iommu_crash_disable )
        return;

    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), crash_shutdown);

    iommu_enabled = false;
#ifndef iommu_intremap
    iommu_intremap = iommu_intremap_off;
#endif
#ifndef iommu_intpost
    iommu_intpost = false;
#endif
}

int iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return 0;

    ops = iommu_get_ops();
    if ( !ops->get_reserved_device_memory )
        return 0;

    return iommu_call(ops, get_reserved_device_memory, func, ctxt);
}

bool iommu_has_feature(struct domain *d, enum iommu_feature feature)
{
    return is_iommu_enabled(d) && test_bit(feature, dom_iommu(d)->features);
}

uint64_t iommu_get_max_iova(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->platform_ops->get_max_iova )
        return 0;

    return iommu_call(hd->platform_ops, get_max_iova, d);
}

#define MAX_EXTRA_RESERVED_RANGES 20
struct extra_reserved_range {
    unsigned long start;
    unsigned long nr;
    pci_sbdf_t sbdf;
    const char *name;
};
static unsigned int __initdata nr_extra_reserved_ranges;
static struct extra_reserved_range __initdata
    extra_reserved_ranges[MAX_EXTRA_RESERVED_RANGES];

int __init iommu_add_extra_reserved_device_memory(unsigned long start,
                                                  unsigned long nr,
                                                  pci_sbdf_t sbdf,
                                                  const char *name)
{
    unsigned int idx;

    if ( nr_extra_reserved_ranges >= MAX_EXTRA_RESERVED_RANGES )
        return -ENOMEM;

    idx = nr_extra_reserved_ranges++;
    extra_reserved_ranges[idx].start = start;
    extra_reserved_ranges[idx].nr = nr;
    extra_reserved_ranges[idx].sbdf = sbdf;
    extra_reserved_ranges[idx].name = name;

    return 0;
}

int __init iommu_get_extra_reserved_device_memory(iommu_grdm_t *func,
                                                  void *ctxt)
{
    unsigned int idx;
    int ret;

    for ( idx = 0; idx < nr_extra_reserved_ranges; idx++ )
    {
#ifdef CONFIG_X86
        paddr_t start = pfn_to_paddr(extra_reserved_ranges[idx].start);
        paddr_t end = pfn_to_paddr(extra_reserved_ranges[idx].start +
                                   extra_reserved_ranges[idx].nr);

        if ( !reserve_e820_ram(&e820, start, end) )
        {
            printk(XENLOG_ERR "Failed to reserve [%"PRIx64"-%"PRIx64") for %s, "
                   "skipping IOMMU mapping for it, some functionality may be broken\n",
                   start, end, extra_reserved_ranges[idx].name);
            continue;
        }
#endif
        ret = func(extra_reserved_ranges[idx].start,
                   extra_reserved_ranges[idx].nr,
                   extra_reserved_ranges[idx].sbdf.sbdf,
                   ctxt);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
