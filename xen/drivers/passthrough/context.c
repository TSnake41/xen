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

#include <xen/iommu.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/bitops.h>
#include <xen/bitmap.h>
#include <xen/event.h>

bool iommu_check_context(struct domain *d, u16 ctx_no) {
    struct domain_iommu *hd = dom_iommu(d);

    if (ctx_no == 0)
        return 1; /* Default context always exist. */

    if ((ctx_no - 1) >= hd->other_contexts.count)
        return 0; /* out of bounds */

    return test_bit(ctx_no - 1, hd->other_contexts.bitmap);
}

struct iommu_context *iommu_get_context(struct domain *d, u16 ctx_no) {
    struct domain_iommu *hd = dom_iommu(d);

    if (!iommu_check_context(d, ctx_no))
        return NULL;

    if (ctx_no == 0)
        return &hd->default_ctx;
    else
        return &hd->other_contexts.map[ctx_no - 1];
}

static unsigned int mapping_order(const struct domain_iommu *hd,
                                  dfn_t dfn, mfn_t mfn, unsigned long nr)
{
    unsigned long res = dfn_x(dfn) | mfn_x(mfn);
    unsigned long sizes = hd->platform_ops->page_sizes;
    unsigned int bit = find_first_set_bit(sizes), order = 0;

    ASSERT(bit == PAGE_SHIFT);

    while ( (sizes = (sizes >> bit) & ~1) )
    {
        unsigned long mask;

        bit = find_first_set_bit(sizes);
        mask = (1UL << bit) - 1;
        if ( nr <= mask || (res & mask) )
            break;
        order += bit;
        nr >>= bit;
        res >>= bit;
    }

    return order;
}

long _iommu_map(struct domain *d, dfn_t dfn0, mfn_t mfn0,
               unsigned long page_count, unsigned int flags,
               unsigned int *flush_flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    if (!iommu_check_context(d, ctx_no))
        return -ENOENT;

    ASSERT(!IOMMUF_order(flags));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        mfn_t mfn = mfn_add(mfn0, i);

        order = mapping_order(hd, dfn, mfn, page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        rc = iommu_call(hd->platform_ops, map_page, d, dfn, mfn,
                        flags | IOMMUF_order(order), flush_flags,
                        iommu_get_context(d, ctx_no));

        if ( likely(!rc) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), mfn_x(mfn), rc);

        /* while statement to satisfy __must_check */
        while ( _iommu_unmap(d, dfn0, i, 0, flush_flags, ctx_no) )
            break;

        if ( !ctx_no && !is_hardware_domain(d) )
            domain_crash(d);

        break;
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

long iommu_map(struct domain *d, dfn_t dfn0, mfn_t mfn0,
               unsigned long page_count, unsigned int flags,
               unsigned int *flush_flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    long ret;

    spin_lock(&hd->lock);
    ret = _iommu_map(d, dfn0, mfn0, page_count, flags, flush_flags, ctx_no);
    spin_unlock(&hd->lock);

    return ret;
}

int iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                     unsigned long page_count, unsigned int flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned int flush_flags = 0;
    int rc;

    ASSERT(!(flags & IOMMUF_preempt));

    spin_lock(&hd->lock);
    rc = _iommu_map(d, dfn, mfn, page_count, flags, &flush_flags, 0);

    if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
        rc = _iommu_iotlb_flush(d, dfn, page_count, flush_flags, 0);
    spin_unlock(&hd->lock);

    return rc;
}

long iommu_unmap(struct domain *d, dfn_t dfn0, unsigned long page_count,
                 unsigned int flags, unsigned int *flush_flags,
                 u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    long ret;

    spin_lock(&hd->lock);
    ret = _iommu_unmap(d, dfn0, page_count, flags, flush_flags, ctx_no);
    spin_unlock(&hd->lock);

    return ret;
}

long _iommu_unmap(struct domain *d, dfn_t dfn0, unsigned long page_count,
                  unsigned int flags, unsigned int *flush_flags,
                  u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    if ( !iommu_check_context(d, ctx_no) )
        return -ENOENT;

    ASSERT(!(flags & ~IOMMUF_preempt));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        int err;

        order = mapping_order(hd, dfn, _mfn(0), page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        err = iommu_call(hd->platform_ops, unmap_page, d, dfn,
                         flags | IOMMUF_order(order), flush_flags,
                         iommu_get_context(d, ctx_no));

        if ( likely(!err) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), err);

        if ( !rc )
            rc = err;

        if ( !is_hardware_domain(d) )
        {
            domain_crash(d);
            break;
        }
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

int iommu_legacy_unmap(struct domain *d, dfn_t dfn, unsigned long page_count)
{
    unsigned int flush_flags = 0;
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    spin_lock(&hd->lock);
    rc = _iommu_unmap(d, dfn, page_count, 0, &flush_flags, 0);

    if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
        rc = _iommu_iotlb_flush(d, dfn, page_count, flush_flags, 0);
    spin_unlock(&hd->lock);

    return rc;
}

int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->lookup_page )
        return -EOPNOTSUPP;

    if (!iommu_check_context(d, ctx_no))
        return -ENOENT;

    spin_lock(&hd->lock);
    ret = iommu_call(hd->platform_ops, lookup_page, d, dfn, mfn, flags, iommu_get_context(d, ctx_no));
    spin_unlock(&hd->lock);

    return ret;
}

int _iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                       unsigned int flush_flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !page_count || !flush_flags )
        return 0;

    if ( dfn_eq(dfn, INVALID_DFN) )
        return -EINVAL;

    if ( !iommu_check_context(d, ctx_no) ) {
        spin_unlock(&hd->lock);
        return -ENOENT;
    }

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, iommu_get_context(d, ctx_no),
                    dfn, page_count, flush_flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %lu flags %x\n",
                   d->domain_id, rc, dfn_x(dfn), page_count, flush_flags);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret;

    spin_lock(&hd->lock);
    ret = _iommu_iotlb_flush(d, dfn, page_count, flush_flags, ctx_no);
    spin_unlock(&hd->lock);

    return ret;
}

int iommu_context_init(struct domain *d, struct iommu_context *ctx, u16 ctx_no, u32 flags)
{
    if ( !dom_iommu(d)->platform_ops->context_init )
        return -ENOSYS;

    INIT_LIST_HEAD(&ctx->devices);
    ctx->id = ctx_no;
    ctx->dying = false;

    return iommu_call(dom_iommu(d)->platform_ops, context_init, d, ctx, flags);
}

int iommu_context_alloc(struct domain *d, u16 *ctx_no, u32 flags)
{
    unsigned int i;
    int ret;
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock(&hd->lock);

    /* TODO: use TSL instead ? */
    i = find_first_zero_bit(hd->other_contexts.bitmap, hd->other_contexts.count);

    if ( i < hd->other_contexts.count )
        set_bit(i, hd->other_contexts.bitmap);

    if ( i >= hd->other_contexts.count ) /* no free context */
        return -ENOSPC;

    *ctx_no = i + 1;

    ret = iommu_context_init(d, iommu_get_context(d, *ctx_no), *ctx_no, flags);

    if ( ret )
        __clear_bit(*ctx_no, hd->other_contexts.bitmap);

    spin_unlock(&hd->lock);

    return ret;
}

int _iommu_attach_context(struct domain *d, device_t *dev, u16 ctx_no)
{
    struct iommu_context *ctx;
    int ret;

    pcidevs_lock();

    if ( !iommu_check_context(d, ctx_no) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    ctx = iommu_get_context(d, ctx_no);

    if ( ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    ret = iommu_call(dom_iommu(d)->platform_ops, attach, d, dev, ctx);

    if ( !ret )
    {
        dev->context = ctx_no;
        list_add(&dev->context_list, &ctx->devices);
    }

unlock:
    pcidevs_unlock();
    return ret;
}

int iommu_attach_context(struct domain *d, device_t *dev, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret;

    spin_lock(&hd->lock);
    ret = _iommu_attach_context(d, dev, ctx_no);
    spin_unlock(&hd->lock);

    return ret;
}

int _iommu_dettach_context(struct domain *d, device_t *dev)
{
    struct iommu_context *ctx;
    int ret;

    if (!dev->domain)
    {
        printk("IOMMU: Trying to dettach a non-attached device.");
        WARN();
        return 0;
    }

    /* Make sure device is actually in the domain. */
    ASSERT(d == dev->domain);

    pcidevs_lock();

    ctx = iommu_get_context(d, dev->context);
    ASSERT(ctx); /* device is using an invalid context ?
                    dev->context invalid ? */

    ret = iommu_call(dom_iommu(d)->platform_ops, dettach, d, dev, ctx);

    if ( !ret )
    {
        list_del(&dev->context_list);

        /** TODO: Do we need to remove the device from domain ?
         *        Reattaching to something (quarantine, hardware domain ?)
         */

        /*
         * rcu_lock_domain ?
         * list_del(&dev->domain_list);
         * dev->domain = ?;
         */
    }

    pcidevs_unlock();
    return ret;
}

int iommu_dettach_context(struct domain *d, device_t *dev)
{
    int ret;
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock(&hd->lock);
    ret = _iommu_dettach_context(d, dev);
    spin_unlock(&hd->lock);

    return ret;
}

int _iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                            device_t *dev, u16 ctx_no)
{
    struct domain_iommu *hd;
    u16 prev_ctx_no;
    device_t *ctx_dev;
    struct iommu_context *prev_ctx, *next_ctx;
    int ret;
    bool same_domain;

    /* Make sure we actually are doing something meaningful */
    BUG_ON(!prev_dom && !next_dom);

    /// TODO: Do such cases exists ?
    // /* Platform ops must match */
    // if (dom_iommu(prev_dom)->platform_ops != dom_iommu(next_dom)->platform_ops)
    //     return -EINVAL;

    pcidevs_lock();

    if (!prev_dom)
        return _iommu_attach_context(next_dom, dev, ctx_no);

    if (!next_dom)
        return _iommu_dettach_context(prev_dom, dev);

    hd = dom_iommu(prev_dom);
    same_domain = prev_dom == next_dom;

    prev_ctx_no = dev->context;

    if ( !same_domain && (ctx_no == prev_ctx_no) )
    {
        printk(XENLOG_DEBUG "Reattaching %pp to same IOMMU context c%hu\n", &dev, ctx_no);
        ret = 0;
        goto unlock;
    }

    if ( !iommu_check_context(next_dom, ctx_no) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    prev_ctx = iommu_get_context(prev_dom, prev_ctx_no);
    next_ctx = iommu_get_context(next_dom, ctx_no);

    if ( next_ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    ret = iommu_call(hd->platform_ops, reattach, next_dom, dev, prev_ctx,
                     next_ctx);

    if ( ret )
        goto unlock;

    /* Remove device from previous context, and add it to new one. */
    list_for_each_entry(ctx_dev, &prev_ctx->devices, context_list)
    {
        if ( ctx_dev == dev )
        {
            list_del(&ctx_dev->context_list);
            list_add(&ctx_dev->context_list, &next_ctx->devices);
            break;
        }
    }

    if ( !same_domain )
    {
        /* Update domain pci devices accordingly */

        /** TODO: should be done here or elsewhere ? */
        /* TODO */
    }

    if (!ret)
        dev->context = ctx_no; /* update device context*/

unlock:
    pcidevs_unlock();
    return ret;
}

int iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                           device_t *dev, u16 ctx_no)
{
    int ret;
    struct domain_iommu *prev_hd = dom_iommu(prev_dom);
    struct domain_iommu *next_hd = dom_iommu(next_dom);

    spin_lock(&prev_hd->lock);

    if (prev_dom != next_dom)
        spin_lock(&next_hd->lock);

    ret = _iommu_reattach_context(prev_dom, next_dom, dev, ctx_no);

    spin_unlock(&prev_hd->lock);

    if (prev_dom != next_dom)
        spin_unlock(&next_hd->lock);

    return ret;
}

int _iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !dom_iommu(d)->platform_ops->context_teardown )
        return -ENOSYS;

    ctx->dying = true;

    /* first reattach devices back to default context if needed */
    if ( flags & IOMMU_TEARDOWN_REATTACH_DEFAULT )
    {
        struct pci_dev *device;
        list_for_each_entry(device, &ctx->devices, context_list)
            _iommu_reattach_context(d, d, device, 0);
    }
    else if (!list_empty(&ctx->devices))
        return -EBUSY; /* there is a device in context */

    return iommu_call(hd->platform_ops, context_teardown, d, ctx, flags);
}

int iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret;

    spin_lock(&hd->lock);
    ret = _iommu_context_teardown(d, ctx, flags);
    spin_unlock(&hd->lock);

    return ret;
}

int iommu_context_free(struct domain *d, u16 ctx_no, u32 flags)
{
    int ret;
    struct domain_iommu *hd = dom_iommu(d);

    if ( ctx_no == 0 )
        return -EINVAL;

    spin_lock(&hd->lock);
    if ( !iommu_check_context(d, ctx_no) )
        return -ENOENT;

    ret = _iommu_context_teardown(d, iommu_get_context(d, ctx_no), flags);

    if ( !ret )
        clear_bit(ctx_no - 1, hd->other_contexts.bitmap);

    spin_unlock(&hd->lock);

    return ret;
}
