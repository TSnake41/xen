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
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/bitops.h>
#include <xen/bitmap.h>

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
    struct iommu_context *ctx;

    if ( !iommu_check_context(d, ctx_no) )
        return NULL;

    if (ctx_no == 0)
        ctx = &hd->default_ctx;
    else
        ctx = &hd->other_contexts.map[ctx_no - 1];

    rspin_lock(&ctx->lock);
    /* Check if the context is still valid at this point */
    if ( unlikely(!iommu_check_context(d, ctx_no)) )
    {
        /* Context has been destroyed in between */
        rspin_unlock(&ctx->lock);
        return NULL;
    }

    return ctx;
}

void iommu_put_context(struct iommu_context *ctx)
{
    rspin_unlock(&ctx->lock);
}

static unsigned int mapping_order(const struct domain_iommu *hd,
                                  dfn_t dfn, mfn_t mfn, unsigned long nr)
{
    unsigned long res = dfn_x(dfn) | mfn_x(mfn);
    unsigned long sizes = hd->platform_ops->page_sizes;
    unsigned int bit = ffsl(sizes) - 1, order = 0;

    ASSERT(bit == PAGE_SHIFT);

    while ( (sizes = (sizes >> bit) & ~1) )
    {
        unsigned long mask;

        bit = ffsl(sizes) - 1;
        mask = (1UL << bit) - 1;
        if ( nr <= mask || (res & mask) )
            break;
        order += bit;
        nr >>= bit;
        res >>= bit;
    }

    return order;
}

static long _iommu_map(struct domain *d, dfn_t dfn0, mfn_t mfn0,
                       unsigned long page_count, unsigned int flags,
                       unsigned int *flush_flags, struct iommu_context *ctx)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

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
                        flags | IOMMUF_order(order), flush_flags, ctx);

        if ( likely(!rc) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), mfn_x(mfn), rc);

        /* while statement to satisfy __must_check */
        while ( iommu_unmap(d, dfn0, i, 0, flush_flags, ctx->id) )
            break;

        if ( !ctx->id && !is_hardware_domain(d) )
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
    struct iommu_context *ctx;
    long ret;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
        return -ENOENT;

    ret = _iommu_map(d, dfn0, mfn0, page_count, flags, flush_flags, ctx);

    iommu_put_context(ctx);

    return ret;
}

int iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                     unsigned long page_count, unsigned int flags)
{
    struct iommu_context *ctx;
    unsigned int flush_flags = 0;
    int rc = 0;

    ASSERT(!(flags & IOMMUF_preempt));

    if ( dom_iommu(d)->no_dma )
        return 0;

    ctx = iommu_get_context(d, 0);

    if ( !ctx->opaque )
    {
        rc = iommu_map(d, dfn, mfn, page_count, flags, &flush_flags, 0);

        if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
            rc = iommu_iotlb_flush(d, dfn, page_count, flush_flags, 0);
    }

    iommu_put_context(ctx);

    return rc;
}

static long _iommu_unmap(struct domain *d, dfn_t dfn0, unsigned long page_count,
                         unsigned int flags, unsigned int *flush_flags,
                         struct iommu_context *ctx)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

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
                         ctx);

        if ( likely(!err) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), err);

        if ( !rc )
            rc = err;

        if ( !ctx->id && !is_hardware_domain(d) )
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

long iommu_unmap(struct domain *d, dfn_t dfn0, unsigned long page_count,
                 unsigned int flags, unsigned int *flush_flags,
                 u16 ctx_no)
{
    struct iommu_context *ctx;
    long ret;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
        return -ENOENT;

    ret = _iommu_unmap(d, dfn0, page_count, flags, flush_flags, ctx);

    iommu_put_context(ctx);

    return ret;
}

int iommu_legacy_unmap(struct domain *d, dfn_t dfn, unsigned long page_count)
{
    unsigned int flush_flags = 0;
    struct iommu_context *ctx;
    int rc;

    if ( dom_iommu(d)->no_dma )
        return 0;

    ctx = iommu_get_context(d, 0);

    if ( ctx->opaque )
        return 0;

    rc = iommu_unmap(d, dfn, page_count, 0, &flush_flags, 0);

    if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
        rc = iommu_iotlb_flush(d, dfn, page_count, flush_flags, 0);

    iommu_put_context(ctx);

    return rc;
}

int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;
    int ret = 0;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->lookup_page )
        return -EOPNOTSUPP;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
        return -ENOENT;

    ret = iommu_call(hd->platform_ops, lookup_page, d, dfn, mfn, flags, ctx);

    iommu_put_context(ctx);
    return ret;
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags, u16 ctx_no)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !page_count || !flush_flags )
        return 0;

    if ( dfn_eq(dfn, INVALID_DFN) )
        return -EINVAL;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
        return -ENOENT;

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, ctx, dfn, page_count,
                    flush_flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %lu flags %x\n",
                   d->domain_id, rc, dfn_x(dfn), page_count, flush_flags);

        if ( !ctx->id && !is_hardware_domain(d) )
            domain_crash(d);
    }

    iommu_put_context(ctx);

    return rc;
}

int iommu_context_init(struct domain *d, struct iommu_context *ctx, u16 ctx_no,
                       u32 flags)
{
    if ( !dom_iommu(d)->platform_ops->context_init )
        return -ENOSYS;

    INIT_LIST_HEAD(&ctx->devices);
    ctx->id = ctx_no;
    ctx->dying = false;
    ctx->opaque = false; /* assume opaque by default */

    return iommu_call(dom_iommu(d)->platform_ops, context_init, d, ctx, flags);
}

int iommu_context_alloc(struct domain *d, u16 *ctx_no, u32 flags)
{
    unsigned int i;
    int ret;
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;

    do {
        i = find_first_zero_bit(hd->other_contexts.bitmap, hd->other_contexts.count);

        if ( i >= hd->other_contexts.count )
            return -ENOSPC;

        ctx = &hd->other_contexts.map[i];

        /* Try to lock the mutex, can fail on concurrent accesses */
        if ( !rspin_trylock(&ctx->lock) )
            continue;

        /* We can now set it as used, we keep the lock for initialization. */
        set_bit(i, hd->other_contexts.bitmap);
    } while (0);

    *ctx_no = i + 1;

    ret = iommu_context_init(d, ctx, *ctx_no, flags);

    if ( ret )
        clear_bit(*ctx_no, hd->other_contexts.bitmap);

    iommu_put_context(ctx);
    return ret;
}

/**
 * Attach dev phantom functions to ctx, override any existing
 * mapped context.
 */
static int iommu_reattach_phantom(struct domain *d, device_t *dev,
                                  struct iommu_context *ctx)
{
    int ret = 0;
    uint8_t devfn = dev->devfn;
    struct domain_iommu *hd = dom_iommu(d);

    while ( dev->phantom_stride )
    {
        devfn += dev->phantom_stride;

        if ( PCI_SLOT(devfn) != PCI_SLOT(dev->devfn) )
            break;

        ret = iommu_call(hd->platform_ops, add_devfn, d, dev, devfn, ctx);

        if ( ret )
            break;
    }

    return ret;
}

/**
 * Detach all device phantom functions.
 */
static int iommu_detach_phantom(struct domain *d, device_t *dev)
{
    int ret = 0;
    uint8_t devfn = dev->devfn;
    struct domain_iommu *hd = dom_iommu(d);

    while ( dev->phantom_stride )
    {
        devfn += dev->phantom_stride;

        if ( PCI_SLOT(devfn) != PCI_SLOT(dev->devfn) )
            break;

        ret = iommu_call(hd->platform_ops, remove_devfn, d, dev, devfn);

        if ( ret )
            break;
    }

    return ret;
}

int iommu_attach_context(struct domain *d, device_t *dev, u16 ctx_no)
{
    struct iommu_context *ctx = NULL;
    int ret, rc;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    pcidevs_lock();

    if ( ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    ret = iommu_call(dom_iommu(d)->platform_ops, attach, d, dev, ctx);

    if ( ret )
        goto unlock;

    /* See iommu_reattach_context() */
    rc = iommu_reattach_phantom(d, dev, ctx);

    if ( rc )
    {
        printk(XENLOG_ERR "IOMMU: Unable to attach %pp phantom functions\n",
               &dev->sbdf);

        if( iommu_call(dom_iommu(d)->platform_ops, detach, d, dev, ctx)
            || iommu_detach_phantom(d, dev) )
        {
            printk(XENLOG_ERR "IOMMU: Improperly detached %pp\n", &dev->sbdf);
            WARN();
        }

        ret = -EIO;
        goto unlock;
    }

    dev->context = ctx_no;
    list_add(&dev->context_list, &ctx->devices);

unlock:
    pcidevs_unlock();

    if ( ctx )
        iommu_put_context(ctx);

    return ret;
}

int iommu_detach_context(struct domain *d, device_t *dev)
{
    struct iommu_context *ctx;
    int ret, rc;

    if ( !dev->domain )
    {
        printk(XENLOG_WARNING "IOMMU: Trying to detach a non-attached device\n");
        WARN();
        return 0;
    }

    /* Make sure device is actually in the domain. */
    ASSERT(d == dev->domain);

    pcidevs_lock();

    ctx = iommu_get_context(d, dev->context);
    ASSERT(ctx); /* device is using an invalid context ?
                    dev->context invalid ? */

    ret = iommu_call(dom_iommu(d)->platform_ops, detach, d, dev, ctx);

    if ( ret )
        goto unlock;

    rc = iommu_detach_phantom(d, dev);

    if ( rc )
        printk(XENLOG_WARNING "IOMMU: "
               "Improperly detached device functions (%d)\n", rc);

    list_del(&dev->context_list);

unlock:
    pcidevs_unlock();
    iommu_put_context(ctx);
    return ret;
}

int iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                           device_t *dev, u16 ctx_no)
{
    u16 prev_ctx_no;
    device_t *ctx_dev;
    struct domain_iommu *prev_hd, *next_hd;
    struct iommu_context *prev_ctx = NULL, *next_ctx = NULL;
    int ret, rc;
    bool same_domain;

    /* Make sure we actually are doing something meaningful */
    BUG_ON(!prev_dom && !next_dom);

    /// TODO: Do such cases exists ?
    // /* Platform ops must match */
    // if (dom_iommu(prev_dom)->platform_ops != dom_iommu(next_dom)->platform_ops)
    //     return -EINVAL;

    if ( !prev_dom )
        return iommu_attach_context(next_dom, dev, ctx_no);

    if ( !next_dom )
        return iommu_detach_context(prev_dom, dev);

    prev_hd = dom_iommu(prev_dom);
    next_hd = dom_iommu(next_dom);

    pcidevs_lock();

    same_domain = prev_dom == next_dom;

    prev_ctx_no = dev->context;

    if ( !same_domain && (ctx_no == prev_ctx_no) )
    {
        printk(XENLOG_DEBUG
               "IOMMU: Reattaching %pp to same IOMMU context c%hu\n",
               &dev, ctx_no);
        ret = 0;
        goto unlock;
    }

    if ( !(prev_ctx = iommu_get_context(prev_dom, prev_ctx_no)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    if ( !(next_ctx = iommu_get_context(next_dom, ctx_no)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    if ( next_ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    ret = iommu_call(prev_hd->platform_ops, reattach, next_dom, dev, prev_ctx,
                     next_ctx);

    if ( ret )
        goto unlock;

    /*
     * We need to do special handling for phantom devices as they
     * also use some other PCI functions behind the scenes.
     */
    rc = iommu_reattach_phantom(next_dom, dev, next_ctx);

    if ( rc )
    {
        /**
         * Device is being partially reattached (we have primary function and
         * maybe some phantom functions attached to next_ctx, some others to prev_ctx),
         * some functions of the device will be attached to next_ctx.
         */
        printk(XENLOG_WARNING "IOMMU: "
               "Device %pp improperly reattached due to phantom function"
               " reattach failure between %dd%dc and %dd%dc (%d)\n", dev,
               prev_dom->domain_id, prev_ctx->id, next_dom->domain_id,
               next_dom->domain_id, rc);

        /* Try reattaching to previous context, reverting into a consistent state. */
        if ( iommu_call(prev_hd->platform_ops, reattach, prev_dom, dev, next_ctx,
                        prev_ctx) || iommu_reattach_phantom(prev_dom, dev, prev_ctx) )
        {
            printk(XENLOG_ERR "Unable to reattach %pp back to %dd%dc\n",
                   &dev->sbdf, prev_dom->domain_id, prev_ctx->id);

            if ( !is_hardware_domain(prev_dom) )
                domain_crash(prev_dom);

            if ( prev_dom != next_dom && !is_hardware_domain(next_dom) )
                domain_crash(next_dom);

            rc = -EIO;
        }

        ret = rc;
        goto unlock;
    }

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

    if (!ret)
        dev->context = ctx_no; /* update device context*/

unlock:
    pcidevs_unlock();

    if ( prev_ctx )
        iommu_put_context(prev_ctx);

    if ( next_ctx )
        iommu_put_context(next_ctx);

    return ret;
}

int iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->platform_ops->context_teardown )
        return -ENOSYS;

    ctx->dying = true;

    /* first reattach devices back to default context if needed */
    if ( flags & IOMMU_TEARDOWN_REATTACH_DEFAULT )
    {
        struct pci_dev *device;
        list_for_each_entry(device, &ctx->devices, context_list)
            iommu_reattach_context(d, d, device, 0);
    }
    else if (!list_empty(&ctx->devices))
        return -EBUSY; /* there is a device in context */

    return iommu_call(hd->platform_ops, context_teardown, d, ctx, flags);
}

int iommu_context_free(struct domain *d, u16 ctx_no, u32 flags)
{
    int ret;
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;

    if ( ctx_no == 0 )
        return -EINVAL;

    if ( !(ctx = iommu_get_context(d, ctx_no)) )
        return -ENOENT;

    ret = iommu_context_teardown(d, ctx, flags);

    if ( !ret )
        clear_bit(ctx_no - 1, hd->other_contexts.bitmap);

    iommu_put_context(ctx);
    return ret;
}
