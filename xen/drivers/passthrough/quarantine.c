#include <xen/stdint.h>
#include <xen/iommu.h>
#include <xen/sched.h>

#ifdef CONFIG_HAS_PCI
uint8_t __read_mostly iommu_quarantine =
# if defined(CONFIG_IOMMU_QUARANTINE_NONE)
    IOMMU_quarantine_none;
# elif defined(CONFIG_IOMMU_QUARANTINE_BASIC)
    IOMMU_quarantine_basic;
# elif defined(CONFIG_IOMMU_QUARANTINE_SCRATCH_PAGE)
    IOMMU_quarantine_scratch_page;
# endif
#else
# define iommu_quarantine IOMMU_quarantine_none
#endif /* CONFIG_HAS_PCI */

int iommu_quarantine_dev_init(device_t *dev)
{
    int ret;
    u16 ctx_no;

    if ( !iommu_quarantine )
        return 0;

    ret = iommu_context_alloc(dom_io, &ctx_no, IOMMU_CONTEXT_INIT_quarantine);

    if ( ret )
        return ret;

    /** TODO: Setup scratch page, mappings... */

    ret = iommu_reattach_context(dev->domain, dom_io, dev, ctx_no);

    if ( ret )
    {
        ASSERT(!iommu_context_free(dom_io, ctx_no, 0));
        return ret;
    }

    return ret;
}

int __init iommu_quarantine_init(void)
{
    dom_io->options |= XEN_DOMCTL_CDF_iommu;

    return iommu_domain_init(dom_io, 0);
}
