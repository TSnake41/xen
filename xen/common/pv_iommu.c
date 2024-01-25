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

#include <xen/lib.h>
#include <xen/iommu.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <asm/p2m.h>
#include <asm/event.h>
#include <public/pv-iommu.h>

#define PVIOMMU_PREFIX "[PV-IOMMU]"
 
#define ret_t long

#if 0
static int get_paged_frame(gfn_t gfn, mfn_t *mfn,
                           struct page_info **page, int readonly,
                           struct domain *rd)
{
    p2m_type_t p2mt;

    *page = get_page_from_gfn(rd, gfn.gfn, &p2mt,
                             (readonly) ? P2M_ALLOC : P2M_UNSHARE);
    if ( !(*page) )
    {
        *mfn = INVALID_MFN;
        if ( p2m_is_shared(p2mt) )
            return -EIO;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(rd, gfn);
            return -EIO;
        }
        return -EIO;
    }
    *mfn = page_to_mfn(*page);

    return 0;
}
#endif

int can_use_iommu_check(struct domain *d)
{
    if (!iommu_enabled) {
        printk(PVIOMMU_PREFIX " IOMMU is not enabled");
        return 0;
    }

    if (!is_hardware_domain(d)) {
        printk(PVIOMMU_PREFIX " Non-hardware domain");
        return 0;
    }

    if (!is_iommu_enabled(d)) {
        printk(PVIOMMU_PREFIX " IOMMU disabled for this domain.");
        return 0;
    }

    if (paging_mode_translate(d) ) {
        printk(PVIOMMU_PREFIX " translate paging mode is not supported");
        return 0;
    }

    return 1;
}

static void query_op(struct pv_iommu_op *op, struct domain_iommu *hd)
{
    if (op->flags | IOMMU_QUERY_context_exists) {
        // TODO: Make and use a dedicated IOMMU subsystem function.
        if (op->ctx_no >= IOMMU_MAX_CONTEXT) {
            op->status = -EINVAL;
            return;
        }

        op->status = hd->arch.contexts[op->ctx_no].initialized;
    }
}

static void create_context_op(struct pv_iommu_op *op, struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    u8 ctx_no = 0;
    int status = 0;

    if (op->flags | IOMMU_CREATE_derive) {
        printk(PVIOMMU_PREFIX " TODO: derive flag ignored");
    }

    if (!hd->platform_ops->context_new) {
        // Non-supported
        op->status = -ENOSYS;
        return;
    }

    status = hd->platform_ops->context_new(d, &ctx_no);

    if (status < 0) {
        op->status = status;
        return;
    }

    op->status = 0;
    op->ctx_no = ctx_no;
}

void do_iommu_sub_op(struct pv_iommu_op *op)
{
    struct domain *d = current->domain;
    struct domain_iommu *hd = dom_iommu(d);

    switch ( op->subop_id )
    {
        case IOMMUOP_query:
        {
            op->flags = 0;
            op->status = 0;
            query_op(op, hd);
            break;
        }
        case IOMMUOP_create_context:
        {
            op->flags = 0;
            op->status = 0;
            create_context_op(op, d);
            break;
        }
        #if 0
        case IOMMUOP_map_page:
        {
            mfn_t mfn, tmp;
            unsigned int flags;
            struct page_info *page = NULL;

            /* Check if calling domain can create IOMMU mappings */
            if ( !can_use_iommu_check(d) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Lookup page struct backing gfn */
            if ( (op->flags & IOMMU_MAP_OP_no_ref_cnt) )
            {
                mfn = _mfn(op->u.map_page.gfn);
                page = mfn_to_page(mfn);
                if (!page)
                {
                    op->status = -EPERM; // Should this be something else?
                    goto finish;
                }
            } else if ( get_paged_frame(op->u.map_page.gfn, &mfn, &page, 0, d) )
            {
                op->status = -EPERM; // Should this be something else?
                goto finish;
            }

            /* Check for conflict with existing BFN mappings */
            if ( !iommu_lookup_page(d, _dfn(op->u.map_page.bfn), &tmp, &flags) )
            {
                if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                    put_page(page);
                op->status = -EPERM;
                goto finish;
            }

            flags = 0;

            if ( op->flags & IOMMU_OP_readable )
                flags |= IOMMUF_readable;

            if ( op->flags & IOMMU_OP_writeable )
                flags |= IOMMUF_writable;

            if ( iommu_legacy_map(d, _dfn(op->u.map_page.bfn), mfn,
                                  PAGE_ORDER_4K, flags) )
            {
                if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                    put_page(page);
                op->status = -EIO;
                goto finish;
            }

            op->status = 0;
            break;
        }

        case IOMMUOP_unmap_page:
        {
            struct page_info *page;
            mfn_t mfn;
            unsigned int flags;

            /* Check if there is a valid BFN mapping for this domain */
            if ( iommu_lookup_page(d, _dfn(op->u.unmap_page.bfn), &mfn, &flags) )
            {
                op->status = -ENOENT;
                goto finish;
            }

            if ( iommu_legacy_unmap(d, _dfn(op->u.unmap_page.bfn),
                                    PAGE_ORDER_4K) )
            {
                op->status = -EIO;
                goto finish;
            }

            /* Use MFN from B2M mapping to lookup page */
            page = mfn_to_page(mfn);
            if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                put_page(page);

            op->status = 0;
            break;
        }
        #endif
        default:
            op->status = -ENODEV;
            break;
    }
}

ret_t do_iommu_op(XEN_GUEST_HANDLE_PARAM(void) arg, unsigned int count)
{
    ret_t ret = 0;
    int i;
    struct pv_iommu_op op;
    struct domain *d = current->domain;

    if ( !is_hardware_domain(d) )
        return -ENOSYS;

    if ( (int)count < 0 )
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
        if ( unlikely(__copy_from_guest_offset(&op, arg, i, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
        do_iommu_sub_op(&op);
        if ( unlikely(__copy_to_guest_offset(arg, i, &op, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
    }

flush_pages:
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