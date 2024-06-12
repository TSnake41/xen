/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xen/common/pv_iommu.c
 *
 * PV-IOMMU hypercall interface.
 */

#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/iommu.h>
#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/guest_access.h>
#include <asm/p2m.h>
#include <asm/event.h>
#include <public/pv-iommu.h>

#define PVIOMMU_PREFIX "[PV-IOMMU] "

#define PVIOMMU_MAX_PAGES 256 /* Move to Kconfig ? */

/* Allowed masks for each sub-operation */
#define ALLOC_OP_FLAGS_MASK (0)
#define FREE_OP_FLAGS_MASK (IOMMU_TEARDOWN_REATTACH_DEFAULT)

static int get_paged_frame(struct domain *d, gfn_t gfn, mfn_t *mfn,
                           struct page_info **page, int readonly)
{
    p2m_type_t p2mt;

    *page = get_page_from_gfn(d, gfn_x(gfn), &p2mt,
                             (readonly) ? P2M_ALLOC : P2M_UNSHARE);

    if ( !(*page) )
    {
        *mfn = INVALID_MFN;
        if ( p2m_is_shared(p2mt) )
            return -EINVAL;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(d, gfn);
            return -EIO;
        }

        return -EPERM;
    }

    *mfn = page_to_mfn(*page);

    return 0;
}

static int can_use_iommu_check(struct domain *d)
{
    if ( !iommu_enabled )
    {
        printk(PVIOMMU_PREFIX "IOMMU is not enabled\n");
        return 0;
    }

    if ( !is_hardware_domain(d) )
    {
        printk(PVIOMMU_PREFIX "Non-hardware domain\n");
        return 0;
    }

    if ( !is_iommu_enabled(d) )
    {
        printk(PVIOMMU_PREFIX "IOMMU disabled for this domain\n");
        return 0;
    }

    return 1;
}

static long query_cap_op(struct pv_iommu_op *op, struct domain *d)
{
    op->cap.max_ctx_no = d->iommu.other_contexts.count;
    op->cap.max_nr_pages = PVIOMMU_MAX_PAGES;
    op->cap.max_iova_addr = (1LLU << 39) - 1; /* TODO: hardcoded 39-bits */

    return 0;
}

static long alloc_context_op(struct pv_iommu_op *op, struct domain *d)
{
    u16 ctx_no = 0;
    int status = 0;

    status = iommu_context_alloc(d, &ctx_no, op->flags & ALLOC_OP_FLAGS_MASK);

    if (status < 0)
        return status;

    printk("Created context %hu\n", ctx_no);

    op->ctx_no = ctx_no;
    return 0;
}

static long free_context_op(struct pv_iommu_op *op, struct domain *d)
{
    return iommu_context_free(d, op->ctx_no,
                              IOMMU_TEARDOWN_PREEMPT | (op->flags & FREE_OP_FLAGS_MASK));
}

static long reattach_device_op(struct pv_iommu_op *op, struct domain *d)
{
    struct physdev_pci_device dev = op->reattach_device.dev;
    device_t *pdev;

    pdev = pci_get_pdev(d, PCI_SBDF(dev.seg, dev.bus, dev.devfn));

    if ( !pdev )
        return -ENOENT;

    return iommu_reattach_context(d, d, pdev, op->ctx_no);
}

static long map_pages_op(struct pv_iommu_op *op, struct domain *d)
{
    int ret = 0, flush_ret;
    struct page_info *page = NULL;
    mfn_t mfn;
    unsigned int flags;
    unsigned int flush_flags = 0;
    size_t i = 0;

    if ( op->map_pages.nr_pages > PVIOMMU_MAX_PAGES )
        return -E2BIG;

    if ( !iommu_check_context(d, op->ctx_no) )
        return -EINVAL;

    //printk("Mapping gfn:%lx-%lx to dfn:%lx-%lx on %hu\n",
    //       op->map_pages.gfn, op->map_pages.gfn + op->map_pages.nr_pages - 1,
    //       op->map_pages.dfn, op->map_pages.dfn + op->map_pages.nr_pages - 1,
    //       op->ctx_no);

    flags = 0;

    if ( op->flags & IOMMU_OP_readable )
        flags |= IOMMUF_readable;

    if ( op->flags & IOMMU_OP_writeable )
        flags |= IOMMUF_writable;

    for (i = 0; i < op->map_pages.nr_pages; i++)
    {
        gfn_t gfn = _gfn(op->map_pages.gfn + i);
        dfn_t dfn = _dfn(op->map_pages.dfn + i);

        /* Lookup pages struct backing gfn */
        ret = get_paged_frame(d, gfn, &mfn, &page, 0);

        if ( ret )
            break;

        /* Check for conflict with existing mappings */
        if ( !iommu_lookup_page(d, dfn, &mfn, &flags, op->ctx_no) )
        {
            put_page(page);
            ret = -EADDRINUSE;
            break;
        }

        ret = iommu_map(d, dfn, mfn, 1, flags, &flush_flags, op->ctx_no);

        if ( ret )
            break;
    }

    op->map_pages.mapped = i;

    flush_ret = iommu_iotlb_flush(d, _dfn(op->map_pages.dfn),
                                  op->map_pages.nr_pages, flush_flags,
                                  op->ctx_no);

    if ( flush_ret )
        printk("Flush operation failed (%d)\n", flush_ret);

    return ret;
}

static long unmap_pages_op(struct pv_iommu_op *op, struct domain *d)
{
    mfn_t mfn;
    int ret = 0, flush_ret;
    unsigned int flags;
    unsigned int flush_flags = 0;
    size_t i = 0;

    if ( op->unmap_pages.nr_pages > PVIOMMU_MAX_PAGES )
        return -E2BIG;

    if ( !iommu_check_context(d, op->ctx_no) )
        return -EINVAL;

    //printk("Unmapping dfn:%lx-%lx on %hu\n",
    //       op->unmap_pages.dfn, op->unmap_pages.dfn + op->unmap_pages.nr_pages - 1,
    //       op->ctx_no);

    for (i = 0; i < op->unmap_pages.nr_pages; i++)
    {
        dfn_t dfn = _dfn(op->unmap_pages.dfn + i);

        /* Check if there is a valid mapping for this domain */
        if ( iommu_lookup_page(d, dfn, &mfn, &flags, op->ctx_no) ) {
            ret = -ENOENT;
            break;
        }

        ret = iommu_unmap(d, dfn, 1, 0, &flush_flags, op->ctx_no);

        if (ret)
            break;

        /* Decrement reference counter */
        put_page(mfn_to_page(mfn));
    }

    op->unmap_pages.unmapped = i;

    flush_ret = iommu_iotlb_flush(d, _dfn(op->unmap_pages.dfn),
                                  op->unmap_pages.nr_pages, flush_flags,
                                  op->ctx_no);

    if ( flush_ret )
        printk("Flush operation failed (%d)\n", flush_ret);

    return ret;
}

static long lookup_page_op(struct pv_iommu_op *op, struct domain *d)
{
    mfn_t mfn;
    gfn_t gfn;
    unsigned int flags = 0;

    if ( !iommu_check_context(d, op->ctx_no) )
        return -EINVAL;

    /* Check if there is a valid BFN mapping for this domain */
    if ( iommu_lookup_page(d, _dfn(op->lookup_page.dfn), &mfn, &flags, op->ctx_no) )
        return -ENOENT;

    gfn = mfn_to_gfn(d, mfn);
    BUG_ON(gfn_eq(gfn, INVALID_GFN));

    op->lookup_page.gfn = gfn_x(gfn);

    return 0;
}

long do_iommu_sub_op(struct pv_iommu_op *op)
{
    struct domain *d = current->domain;

    if ( !can_use_iommu_check(d) )
        return -EPERM;

    switch ( op->subop_id )
    {
        case 0:
            return 0;

        case IOMMUOP_query_capabilities:
            return query_cap_op(op, d);

        case IOMMUOP_alloc_context:
            return alloc_context_op(op, d);

        case IOMMUOP_free_context:
            return free_context_op(op, d);

        case IOMMUOP_reattach_device:
            return reattach_device_op(op, d);

        case IOMMUOP_map_pages:
            return map_pages_op(op, d);

        case IOMMUOP_unmap_pages:
            return unmap_pages_op(op, d);

        case IOMMUOP_lookup_page:
            return lookup_page_op(op, d);

        default:
            return -EINVAL;
    }
}

long do_iommu_op(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long ret = 0;
    struct pv_iommu_op op;

    if ( unlikely(copy_from_guest(&op, arg, 1)) )
        return -EFAULT;

    ret = do_iommu_sub_op(&op);

    if ( unlikely(copy_to_guest(arg, &op, 1)) )
        return -EFAULT;

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
