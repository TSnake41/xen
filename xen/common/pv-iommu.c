/******************************************************************************
 * common/pv_iommu.c
 * 
 * Paravirtualised IOMMU functionality
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
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

// HACK: Flush all IOMMUs
int iommu_flush_all(void);

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

int can_use_iommu_check(struct domain *d)
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

static long alloc_context_op(struct pv_iommu_op *op, struct domain *d)
{
    u16 ctx_no = 0;
    int status = 0;

    status = iommu_context_alloc(d, &ctx_no, op->flags);
    
    if (status < 0)
        return status;

    op->ctx_no = ctx_no;
    return 0;
}

static long free_context_op(struct pv_iommu_op *op, struct domain *d)
{
    return iommu_context_free(d, op->ctx_no, op->flags);
}

static long reattach_device_op(struct pv_iommu_op *op, struct domain *d)
{
    struct physdev_pci_device *dev = &op->reattach_device.dev;
    device_t *pdev;

    pdev = pci_get_pdev(d, PCI_SBDF(dev->seg, dev->bus, dev->devfn));

    if ( !pdev )
        return !ENOENT;

    return iommu_reattach_context(d, pdev->devfn, pdev, op->ctx_no);
}

static long map_page_op(struct pv_iommu_op *op, struct domain *d)
{
    int ret;
    struct page_info *page = NULL;
    mfn_t mfn;
    unsigned int flags;
    unsigned int flush_flags = 0;

    /* Lookup page struct backing gfn */
    ret = get_paged_frame(d, _gfn(op->map_page.gfn), &mfn, &page, 0);

    if (ret)
        return ret;

    /* Check for conflict with existing mappings */
    if ( !iommu_lookup_page(d, _dfn(op->map_page.dfn), &mfn, &flags, op->ctx_no) )
    {
        put_page(page);
        return -EADDRINUSE;
    }

    flags = 0;

    if ( op->flags & IOMMU_OP_readable )
        flags |= IOMMUF_readable;

    if ( op->flags & IOMMU_OP_writeable )
        flags |= IOMMUF_writable;

    ret = iommu_map(d, _dfn(op->map_page.dfn), mfn, 1,
        flags, &flush_flags, op->ctx_no);

    if ( ret )
    {
        put_page(page);
        return ret;
    }

    return 0;
}

static long unmap_page_op(struct pv_iommu_op *op, struct domain *d)
{
    mfn_t mfn;
    int ret;
    unsigned int flags;
    unsigned int flush_flags = 0;

    /* Check if there is a valid BFN mapping for this domain */
    if ( iommu_lookup_page(d, _dfn(op->unmap_page.dfn), &mfn, &flags, op->ctx_no) )
        return -ENOENT;

    ret = iommu_unmap(d, _dfn(op->unmap_page.dfn), 1, 0, &flush_flags, op->ctx_no);

    if (ret)
        return ret;

    /* Decrement reference counter */
    put_page(mfn_to_page(mfn));

    return 0;
}

static long lookup_page_op(struct pv_iommu_op *op, struct domain *d)
{
    mfn_t mfn;
    gfn_t gfn;
    unsigned int flags = 0;

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

        case IOMMUOP_alloc_context:
            return alloc_context_op(op, d);
        
        case IOMMUOP_free_context:
            return free_context_op(op, d);

        case IOMMUOP_reattach_device:
            return reattach_device_op(op, d);
        
        case IOMMUOP_map_page:
            return map_page_op(op, d);
        
        case IOMMUOP_unmap_page:
            return unmap_page_op(op, d);

        case IOMMUOP_lookup_page:
            return lookup_page_op(op, d);
        
        default:
            return -EINVAL;
    }
}

long do_iommu_op(XEN_GUEST_HANDLE_PARAM(void) arg, unsigned int count)
{
    long ret = 0;
    int i;
    struct pv_iommu_op op;
    struct domain *d = current->domain;
    
    if ( count == 0 )
        return -EINVAL;

    if ( count > 1 )
        this_cpu(iommu_dont_flush_iotlb) = 1;

    for ( i = 0; i < count; i++ )
    {
        if ( i && hypercall_preempt_check() )
        {
            ret =  i;
            goto flush_pages;
        }
        if ( unlikely(copy_from_guest_offset(&op, arg, i, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
        ret = do_iommu_sub_op(&op);
        if ( unlikely(copy_to_guest_offset(arg, i, &op, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
    }

flush_pages:
    iommu_flush_all(); // HACK

    if ( count > 1 )
    {
        int rc = 0;

        this_cpu(iommu_dont_flush_iotlb) = 0;
        if ( i )
            rc = iommu_iotlb_flush_all(d, IOMMU_FLUSHF_added |
                                       IOMMU_FLUSHF_modified);

        if ( rc < 0 )
            ret = rc;
    }
    if ( ret > 0 )
    {
        XEN_GUEST_HANDLE_PARAM(pv_iommu_op_t) op =
            guest_handle_cast(arg, pv_iommu_op_t);
        ASSERT(ret < count);
        guest_handle_add_offset(op, i);
        arg = guest_handle_cast(op, void);
        ret = hypercall_create_continuation(__HYPERVISOR_iommu_op,
                                           "hi", arg, count - i);
    }
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
