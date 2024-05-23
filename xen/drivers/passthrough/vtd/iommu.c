/*
 * Copyright (c) 2006, Intel Corporation.
 *
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
 *
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 * Copyright (C) Shaohua Li <shaohua.li@intel.com>
 * Copyright (C) Allen Kay <allen.m.kay@intel.com> - adapted to xen
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/numa.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/keyhandler.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/iommu.h>
#include <xen/lib.h>
#include <asm/msi.h>
#include <asm/nops.h>
#include <asm/irq.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/p2m.h>
#include <asm/bitops.h>
#include <asm/iommu.h>
#include <asm/page.h>
#include <mach_apic.h>
#include "iommu.h"
#include "dmar.h"
#include "extern.h"
#include "vtd.h"
#include "../ats.h"

#define CONTIG_MASK DMA_PTE_CONTIG_MASK
#include <asm/pt-contig-markers.h>

bool __read_mostly iommu_igfx = true;
bool __read_mostly iommu_qinval = true;
#ifndef iommu_snoop
bool __read_mostly iommu_snoop = true;
#endif

static unsigned int __read_mostly nr_iommus;
static unsigned int __ro_after_init min_pt_levels = UINT_MAX;

static struct tasklet vtd_fault_tasklet;

static int cf_check setup_hwdom_device(u8 devfn, struct pci_dev *);
static void setup_hwdom_rmrr(struct domain *d);

static bool domid_mapping(const struct vtd_iommu *iommu)
{
    return (const void *)iommu->domid_bitmap != (const void *)iommu->domid_map;
}

static domid_t convert_domid(const struct vtd_iommu *iommu, domid_t domid)
{
    /*
     * While we need to avoid DID 0 for caching-mode IOMMUs, maintain
     * the property of the transformation being the same in either
     * direction. By clipping to 16 bits we ensure that the resulting
     * DID will fit in the respective context entry field.
     */
    BUILD_BUG_ON(DOMID_MASK >= 0xffff);

    return !cap_caching_mode(iommu->cap) ? domid : ~domid;
}

static int get_iommu_did(domid_t domid, const struct vtd_iommu *iommu,
                         bool warn)
{
    unsigned int nr_dom, i;

    if ( !domid_mapping(iommu) )
        return convert_domid(iommu, domid);

    nr_dom = cap_ndoms(iommu->cap);
    i = find_first_bit(iommu->domid_bitmap, nr_dom);
    while ( i < nr_dom )
    {
        if ( iommu->domid_map[i] == domid )
            return i;

        i = find_next_bit(iommu->domid_bitmap, nr_dom, i + 1);
    }

    if ( warn )
        dprintk(XENLOG_ERR VTDPREFIX,
                "No valid iommu %u domid for Dom%d\n",
                iommu->index, domid);

    return -1;
}

#define DID_FIELD_WIDTH 16
#define DID_HIGH_OFFSET 8

/*
 * This function may have "context" passed as NULL, to merely obtain a DID
 * for "domid".
 */
static int context_set_domain_id(struct context_entry *context,
                                 domid_t domid, struct vtd_iommu *iommu)
{
    unsigned int i;

    ASSERT(pcidevs_locked());

    if ( domid_mapping(iommu) )
    {
        unsigned int nr_dom = cap_ndoms(iommu->cap);

        i = find_first_bit(iommu->domid_bitmap, nr_dom);
        while ( i < nr_dom && iommu->domid_map[i] != domid )
            i = find_next_bit(iommu->domid_bitmap, nr_dom, i + 1);

        if ( i >= nr_dom )
        {
            i = find_first_zero_bit(iommu->domid_bitmap, nr_dom);
            if ( i >= nr_dom )
            {
                dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: no free domain id\n");
                return -EBUSY;
            }
            iommu->domid_map[i] = domid;
            set_bit(i, iommu->domid_bitmap);
        }
    }
    else
        i = convert_domid(iommu, domid);

    printk("context_set_domain_id: %hu -> %hu\n", domid, i);

    if ( context )
    {
        context->hi &= ~(((1 << DID_FIELD_WIDTH) - 1) << DID_HIGH_OFFSET);
        context->hi |= (i & ((1 << DID_FIELD_WIDTH) - 1)) << DID_HIGH_OFFSET;
    }

    return 0;
}

static void cleanup_domid_map(domid_t domid, struct vtd_iommu *iommu)
{
    int iommu_domid;

    if ( !domid_mapping(iommu) )
        return;

    iommu_domid = get_iommu_did(domid, iommu, false);

    if ( iommu_domid >= 0 )
    {
        /*
         * Update domid_map[] /before/ domid_bitmap[] to avoid a race with
         * context_set_domain_id(), setting the slot to DOMID_INVALID for
         * did_to_domain_id() to return a suitable value while the bit is
         * still set.
         */
        iommu->domid_map[iommu_domid] = DOMID_INVALID;
        clear_bit(iommu_domid, iommu->domid_bitmap);
    }
}

static bool any_pdev_behind_iommu(const struct domain *d,
                                  const struct pci_dev *exclude,
                                  const struct vtd_iommu *iommu)
{
    const struct pci_dev *pdev;

    for_each_pdev ( d, pdev )
    {
        const struct acpi_drhd_unit *drhd;

        if ( pdev == exclude )
            continue;

        drhd = acpi_find_matched_drhd_unit(pdev);
        if ( drhd && drhd->iommu == iommu )
            return true;
    }

    return false;
}

/*
 * If no other devices under the same iommu owned by this domain,
 * clear iommu in iommu_bitmap and clear domain_id in domid_bitmap.
 */
static void check_cleanup_domid_map(const struct domain *d,
                                    const struct iommu_context *ctx,
                                    const struct pci_dev *exclude,
                                    struct vtd_iommu *iommu)
{
    if ( !any_pdev_behind_iommu(d, exclude, iommu) )
    {
        clear_bit(iommu->index, ctx->arch.vtd.iommu_bitmap);
        cleanup_domid_map(ctx->arch.vtd.didmap[iommu->index], iommu);
    }
}

domid_t did_to_domain_id(const struct vtd_iommu *iommu, unsigned int did)
{
    if ( did >= cap_ndoms(iommu->cap) )
        return DOMID_INVALID;

    if ( !domid_mapping(iommu) )
        return convert_domid(iommu, did);

    if ( !test_bit(did, iommu->domid_bitmap) )
        return DOMID_INVALID;

    return iommu->domid_map[did];
}

/* Allocate page table, return its machine address */
uint64_t alloc_pgtable_maddr(unsigned long npages, nodeid_t node)
{
    struct page_info *pg, *cur_pg;
    unsigned int i;

    pg = alloc_domheap_pages(NULL, get_order_from_pages(npages),
                             (node == NUMA_NO_NODE) ? 0 : MEMF_node(node));
    if ( !pg )
        return 0;

    cur_pg = pg;
    for ( i = 0; i < npages; i++ )
    {
        void *vaddr = __map_domain_page(cur_pg);

        clear_page(vaddr);

        iommu_sync_cache(vaddr, PAGE_SIZE);
        unmap_domain_page(vaddr);
        cur_pg++;
    }

    return page_to_maddr(pg);
}

void free_pgtable_maddr(u64 maddr)
{
    if ( maddr != 0 )
        free_domheap_page(maddr_to_page(maddr));
}

/* context entry handling */
static u64 bus_to_context_maddr(struct vtd_iommu *iommu, u8 bus)
{
    struct root_entry *root, *root_entries;
    u64 maddr;

    ASSERT(spin_is_locked(&iommu->lock));
    root_entries = (struct root_entry *)map_vtd_domain_page(iommu->root_maddr);
    root = &root_entries[bus];
    if ( !root_present(*root) )
    {
        maddr = alloc_pgtable_maddr(1, iommu->node);
        if ( maddr == 0 )
        {
            unmap_vtd_domain_page(root_entries);
            return 0;
        }
        set_root_value(*root, maddr);
        set_root_present(*root);
        iommu_sync_cache(root, sizeof(struct root_entry));
    }
    maddr = (u64) get_context_addr(*root);
    unmap_vtd_domain_page(root_entries);
    return maddr;
}

/*
 * This function walks (and if requested allocates) page tables to the
 * designated target level. It returns
 * - 0 when a non-present entry was encountered and no allocation was
 *   requested,
 * - a small positive value (the level, i.e. below PAGE_SIZE) upon allocation
 *   failure,
 * - for target > 0 the physical address of the page table holding the leaf
 *   PTE for the requested address,
 * - for target == 0 the full PTE contents below PADDR_BITS limit.
 */
static uint64_t addr_to_dma_page_maddr(struct domain *domain,
                                       struct iommu_context *ctx,
                                       daddr_t addr, unsigned int target,
                                       unsigned int *flush_flags, bool alloc)
{
    struct domain_iommu *hd = dom_iommu(domain);
    int addr_width = agaw_to_width(hd->arch.vtd.agaw);
    struct dma_pte *parent, *pte = NULL;
    unsigned int level = agaw_to_level(hd->arch.vtd.agaw), offset;
    u64 pte_maddr = 0;

    addr &= (((u64)1) << addr_width) - 1;
    ASSERT(target || !alloc);

    if ( !ctx->arch.vtd.pgd_maddr )
    {
        struct page_info *pg;

        if ( !alloc )
            goto out;

        pte_maddr = level;
        if ( !(pg = iommu_alloc_pgtable(hd, ctx, 0)) )
            goto out;

        ctx->arch.vtd.pgd_maddr = page_to_maddr(pg);
    }

    pte_maddr = ctx->arch.vtd.pgd_maddr;
    parent = map_vtd_domain_page(pte_maddr);
    while ( level > target )
    {
        offset = address_level_offset(addr, level);
        pte = &parent[offset];

        pte_maddr = dma_pte_addr(*pte);
        if ( !dma_pte_present(*pte) || (level > 1 && dma_pte_superpage(*pte)) )
        {
            struct page_info *pg;
            /*
             * Higher level tables always set r/w, last level page table
             * controls read/write.
             */
            struct dma_pte new_pte = { DMA_PTE_PROT };

            if ( !alloc )
            {
                pte_maddr = 0;
                if ( !dma_pte_present(*pte) )
                    break;

                /*
                 * When the leaf entry was requested, pass back the full PTE,
                 * with the address adjusted to account for the residual of
                 * the walk.
                 */
                pte_maddr = (pte->val & PADDR_MASK) +
                    (addr & ((1UL << level_to_offset_bits(level)) - 1) &
                     PAGE_MASK);
                if ( !target )
                    break;
            }

            pte_maddr = level - 1;
            pg = iommu_alloc_pgtable(hd, ctx, DMA_PTE_CONTIG_MASK);
            if ( !pg )
                break;

            pte_maddr = page_to_maddr(pg);
            dma_set_pte_addr(new_pte, pte_maddr);

            if ( dma_pte_present(*pte) )
            {
                struct dma_pte *split = map_vtd_domain_page(pte_maddr);
                unsigned long inc = 1UL << level_to_offset_bits(level - 1);

                split[0].val |= pte->val & ~DMA_PTE_CONTIG_MASK;
                if ( inc == PAGE_SIZE )
                    split[0].val &= ~DMA_PTE_SP;

                for ( offset = 1; offset < PTE_NUM; ++offset )
                    split[offset].val |=
                        (split[offset - 1].val & ~DMA_PTE_CONTIG_MASK) + inc;

                iommu_sync_cache(split, PAGE_SIZE);
                unmap_vtd_domain_page(split);

                if ( flush_flags )
                    *flush_flags |= IOMMU_FLUSHF_modified;

                perfc_incr(iommu_pt_shatters);
            }

            write_atomic(&pte->val, new_pte.val);
            iommu_sync_cache(pte, sizeof(struct dma_pte));
            pt_update_contig_markers(&parent->val,
                                     address_level_offset(addr, level),
                                     level, PTE_kind_table);
        }

        if ( --level == target )
        {
            if ( !target )
                pte_maddr = pte->val & PADDR_MASK;
            break;
        }

        unmap_vtd_domain_page(parent);
        parent = map_vtd_domain_page(pte_maddr);
    }

    unmap_vtd_domain_page(parent);
 out:
    return pte_maddr;
}

static paddr_t get_context_pgd(struct domain *d, struct iommu_context *ctx,
                               unsigned int nr_pt_levels)
{
    unsigned int agaw;
    paddr_t pgd_maddr = ctx->arch.vtd.pgd_maddr;

    if ( !ctx->arch.vtd.pgd_maddr )
    {
        /*
         * Ensure we have pagetables allocated down to the smallest
         * level the loop below may need to run to.
         */
        addr_to_dma_page_maddr(d, ctx, 0, min_pt_levels, NULL, true);

        if ( !ctx->arch.vtd.pgd_maddr )
            return 0;
    }

    pgd_maddr = ctx->arch.vtd.pgd_maddr;

    /* Skip top level(s) of page tables for less-than-maximum level DRHDs. */
    for ( agaw = level_to_agaw(4);
          agaw != level_to_agaw(nr_pt_levels);
          agaw-- )
    {
        const struct dma_pte *p = map_vtd_domain_page(pgd_maddr);

        pgd_maddr = dma_pte_addr(*p);
        unmap_vtd_domain_page(p);
        if ( !pgd_maddr )
            return 0;
    }

    return pgd_maddr;
}

static void iommu_flush_write_buffer(struct vtd_iommu *iommu)
{
    u32 val;
    unsigned long flags;

    if ( !rwbf_quirk && !cap_rwbf(iommu->cap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    val = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, val | DMA_GCMD_WBF);

    /* Make sure hardware complete it */
    IOMMU_FLUSH_WAIT("write buffer", iommu, DMAR_GSTS_REG, dmar_readl,
                     !(val & DMA_GSTS_WBFS), val);

    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

/* return value determine if we need a write buffer flush */
int cf_check vtd_flush_context_reg(
    struct vtd_iommu *iommu, uint16_t did, uint16_t source_id,
    uint8_t function_mask, uint64_t type, bool flush_non_present_entry)
{
    unsigned long flags;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( flush_non_present_entry )
    {
        if ( !cap_caching_mode(iommu->cap) )
            return 1;
        else
            did = 0;
    }

    /* use register invalidation */
    switch ( type )
    {
    case DMA_CCMD_GLOBAL_INVL:
        break;

    case DMA_CCMD_DEVICE_INVL:
        type |= DMA_CCMD_SID(source_id) | DMA_CCMD_FM(function_mask);
        fallthrough;
    case DMA_CCMD_DOMAIN_INVL:
        type |= DMA_CCMD_DID(did);
        break;

    default:
        BUG();
    }
    type |= DMA_CCMD_ICC;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writeq(iommu->reg, DMAR_CCMD_REG, type);

    /* Make sure hardware complete it */
    IOMMU_FLUSH_WAIT("context", iommu, DMAR_CCMD_REG, dmar_readq,
                     !(type & DMA_CCMD_ICC), type);

    spin_unlock_irqrestore(&iommu->register_lock, flags);
    /* flush context entry will implicitly flush write buffer */
    return 0;
}

static int __must_check iommu_flush_context_global(struct vtd_iommu *iommu,
                                                   bool flush_non_present_entry)
{
    return iommu->flush.context(iommu, 0, 0, 0, DMA_CCMD_GLOBAL_INVL,
                                flush_non_present_entry);
}

static int __must_check iommu_flush_context_device(struct vtd_iommu *iommu,
                                                   u16 did, u16 source_id,
                                                   u8 function_mask,
                                                   bool flush_non_present_entry)
{
    return iommu->flush.context(iommu, did, source_id, function_mask,
                                DMA_CCMD_DEVICE_INVL, flush_non_present_entry);
}

/* return value determine if we need a write buffer flush */
int cf_check vtd_flush_iotlb_reg(
    struct vtd_iommu *iommu, uint16_t did, uint64_t addr,
    unsigned int size_order, uint64_t type, bool flush_non_present_entry,
    bool flush_dev_iotlb)
{
    int tlb_offset = ecap_iotlb_offset(iommu->ecap);
    uint64_t val = type | DMA_TLB_IVT;
    unsigned long flags;

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entries we do nothing.
     */
    if ( flush_non_present_entry && !cap_caching_mode(iommu->cap) )
        return 1;

    /* use register invalidation */
    switch ( type )
    {
    case DMA_TLB_GLOBAL_FLUSH:
        break;

    case DMA_TLB_DSI_FLUSH:
    case DMA_TLB_PSI_FLUSH:
        val |= DMA_TLB_DID(did);
        break;

    default:
        BUG();
    }
    /* Note: set drain read/write */
    if ( cap_read_drain(iommu->cap) )
        val |= DMA_TLB_READ_DRAIN;
    if ( cap_write_drain(iommu->cap) )
        val |= DMA_TLB_WRITE_DRAIN;

    spin_lock_irqsave(&iommu->register_lock, flags);
    /* Note: Only uses first TLB reg currently */
    if ( type == DMA_TLB_PSI_FLUSH )
    {
        /* Note: always flush non-leaf currently. */
        dmar_writeq(iommu->reg, tlb_offset,
                    size_order | DMA_TLB_IVA_ADDR(addr));
    }
    dmar_writeq(iommu->reg, tlb_offset + 8, val);

    /* Make sure hardware complete it */
    IOMMU_FLUSH_WAIT("iotlb", iommu, (tlb_offset + 8), dmar_readq,
                     !(val & DMA_TLB_IVT), val);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* check IOTLB invalidation granularity */
    if ( DMA_TLB_IAIG(val) == 0 )
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: flush IOTLB failed\n");

    /* flush iotlb entry will implicitly flush write buffer */
    return 0;
}

static int __must_check iommu_flush_iotlb_global(struct vtd_iommu *iommu,
                                                 bool flush_non_present_entry,
                                                 bool flush_dev_iotlb)
{
    int status;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, 0, 0, 0, DMA_TLB_GLOBAL_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

static int __must_check iommu_flush_iotlb_dsi(struct vtd_iommu *iommu, u16 did,
                                              bool flush_non_present_entry,
                                              bool flush_dev_iotlb)
{
    int status;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, did, 0, 0, DMA_TLB_DSI_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

static int __must_check iommu_flush_iotlb_psi(struct vtd_iommu *iommu, u16 did,
                                              u64 addr, unsigned int order,
                                              bool flush_non_present_entry,
                                              bool flush_dev_iotlb)
{
    int status;

    /* Fallback to domain selective flush if no PSI support */
    if ( !cap_pgsel_inv(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did, flush_non_present_entry,
                                     flush_dev_iotlb);

    /* Fallback to domain selective flush if size is too big */
    if ( order > cap_max_amask_val(iommu->cap) )
        return iommu_flush_iotlb_dsi(iommu, did, flush_non_present_entry,
                                     flush_dev_iotlb);

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    status = iommu->flush.iotlb(iommu, did, addr, order, DMA_TLB_PSI_FLUSH,
                                flush_non_present_entry, flush_dev_iotlb);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    return status;
}

int __must_check iommu_flush_all(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    bool flush_dev_iotlb;
    int rc = 0;

    flush_local(FLUSH_CACHE);

    for_each_drhd_unit ( drhd )
    {
        int context_rc, iotlb_rc;

        iommu = drhd->iommu;
        context_rc = iommu_flush_context_global(iommu, 0);
        flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
        iotlb_rc = iommu_flush_iotlb_global(iommu, 0, flush_dev_iotlb);

        /*
         * The current logic for returns:
         *   - positive  invoke iommu_flush_write_buffer to flush cache.
         *   - zero      on success.
         *   - negative  on failure. Continue to flush IOMMU IOTLB on a
         *               best effort basis.
         */
        if ( context_rc > 0 || iotlb_rc > 0 )
            iommu_flush_write_buffer(iommu);
        if ( rc >= 0 )
            rc = context_rc;
        if ( rc >= 0 )
            rc = iotlb_rc;
    }

    if ( rc > 0 )
        rc = 0;

    return rc;
}

static int __must_check cf_check iommu_flush_iotlb(struct domain *d,
                                                   struct iommu_context *ctx,
                                                   dfn_t dfn,
                                                   unsigned long page_count,
                                                   unsigned int flush_flags)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    bool flush_dev_iotlb;
    int iommu_domid;
    int ret = 0;

    /*
     * No need pcideves_lock here because we have flush
     * when assign/deassign device
     */
    for_each_drhd_unit ( drhd )
    {
        int rc;

        iommu = drhd->iommu;

        if ( ctx )
        {
            if ( !test_bit(iommu->index, ctx->arch.vtd.iommu_bitmap) )
                continue;

            iommu_domid = get_iommu_did(ctx->arch.vtd.didmap[iommu->index], iommu, true);

            if ( iommu_domid == -1 )
                continue;
        }
        else
            iommu_domid = 0;

        flush_dev_iotlb = !!find_ats_dev_drhd(iommu);

        if ( !page_count || (page_count & (page_count - 1)) ||
             dfn_eq(dfn, INVALID_DFN) || !IS_ALIGNED(dfn_x(dfn), page_count) )
            rc = iommu_flush_iotlb_dsi(iommu, iommu_domid,
                                       0, flush_dev_iotlb);
        else
            rc = iommu_flush_iotlb_psi(iommu, iommu_domid,
                                       dfn_to_daddr(dfn),
                                       get_order_from_pages(page_count),
                                       !(flush_flags & IOMMU_FLUSHF_modified),
                                       flush_dev_iotlb);

        if ( rc > 0 )
            iommu_flush_write_buffer(iommu);
        else if ( !ret )
            ret = rc;
    }

    return ret;
}

static void queue_free_pt(struct iommu_context *ctx, mfn_t mfn, unsigned int level)
{
    if ( level > 1 )
    {
        struct dma_pte *pt = map_domain_page(mfn);
        unsigned int i;

        for ( i = 0; i < PTE_NUM; ++i )
            if ( dma_pte_present(pt[i]) && !dma_pte_superpage(pt[i]) )
                queue_free_pt(ctx, maddr_to_mfn(dma_pte_addr(pt[i])),
                              level - 1);

        unmap_domain_page(pt);
    }

    iommu_queue_free_pgtable(ctx, mfn_to_page(mfn));
}

static int iommu_set_root_entry(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writeq(iommu->reg, DMAR_RTADDR_REG, iommu->root_maddr);

    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts | DMA_GCMD_SRTP);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_RTPS), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return 0;
}

static void iommu_enable_translation(struct acpi_drhd_unit *drhd)
{
    u32 sts;
    unsigned long flags;
    struct vtd_iommu *iommu = drhd->iommu;
    static const char crash_fmt[] = "%s; crash Xen for security purpose\n";

    if ( drhd->gfx_only )
    {
        static const char disable_fmt[] = XENLOG_WARNING VTDPREFIX
                                          " %s; disabling IGD VT-d engine\n";

        if ( !iommu_igfx )
        {
            printk(disable_fmt, "passed iommu=no-igfx option");
            return;
        }

        if ( !is_igd_vt_enabled_quirk() )
        {
            static const char msg[] = "firmware did not enable IGD for VT properly";

            if ( force_iommu )
                panic(crash_fmt, msg);

            printk(disable_fmt, msg);
            return;
        }
    }

    if ( !is_azalia_tlb_enabled(drhd) )
    {
        static const char msg[] = "firmware did not enable TLB for sound device";

        if ( force_iommu )
            panic(crash_fmt, msg);

        printk(XENLOG_WARNING VTDPREFIX " %s; disabling ISOCH VT-d engine\n",
               msg);
        return;
    }

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    if ( iommu_verbose )
        printk(VTDPREFIX "iommu_enable_translation: iommu->reg = %p\n",
               iommu->reg);
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts | DMA_GCMD_TE);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_TES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);

    /* Disable PMRs when VT-d engine takes effect per spec definition */
    disable_pmr(iommu);
}

static void iommu_disable_translation(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    /* apply platform specific errata workarounds */
    vtd_ops_preamble_quirk(iommu);

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_TE));

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_TES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* undo platform specific errata workarounds */
    vtd_ops_postamble_quirk(iommu);
}

enum faulttype {
    DMA_REMAP,
    INTR_REMAP,
    UNKNOWN,
};

static const char *dma_remap_fault_reasons[] =
{
    "Software",
    "Present bit in root entry is clear",
    "Present bit in context entry is clear",
    "Invalid context entry",
    "Access beyond MGAW",
    "PTE Write access is not set",
    "PTE Read access is not set",
    "Next page table ptr is invalid",
    "Root table address invalid",
    "Context table ptr is invalid",
    "non-zero reserved fields in RTP",
    "non-zero reserved fields in CTP",
    "non-zero reserved fields in PTE",
    "Blocked a DMA translation request",
};

static const char *intr_remap_fault_reasons[] =
{
    "Detected reserved fields in the decoded interrupt-remapped request",
    "Interrupt index exceeded the interrupt-remapping table size",
    "Present field in the IRTE entry is clear",
    "Error accessing interrupt-remapping table pointed by IRTA_REG",
    "Detected reserved fields in the IRTE entry",
    "Blocked a compatibility format interrupt request",
    "Blocked an interrupt request due to source-id verification failure",
};

static const char *iommu_get_fault_reason(u8 fault_reason,
                                          enum faulttype *fault_type)
{
    if ( fault_reason >= 0x20 && ( fault_reason < 0x20 +
                ARRAY_SIZE(intr_remap_fault_reasons)) )
    {
        *fault_type = INTR_REMAP;
        return intr_remap_fault_reasons[fault_reason - 0x20];
    }
    else if ( fault_reason < ARRAY_SIZE(dma_remap_fault_reasons) )
    {
        *fault_type = DMA_REMAP;
        return dma_remap_fault_reasons[fault_reason];
    }
    else
    {
        *fault_type = UNKNOWN;
        return "Unknown";
    }
}

static int iommu_page_fault_do_one(struct vtd_iommu *iommu, int type,
                                   u8 fault_reason, u16 source_id, u64 addr)
{
    const char *reason, *kind;
    enum faulttype fault_type;
    u16 seg = iommu->drhd->segment;

    reason = iommu_get_fault_reason(fault_reason, &fault_type);
    switch ( fault_type )
    {
    case DMA_REMAP:
        printk(XENLOG_G_WARNING VTDPREFIX
               "DMAR:[%s] Request device [%pp] "
               "fault addr %"PRIx64"\n",
               (type ? "DMA Read" : "DMA Write"),
               &PCI_SBDF(seg, source_id), addr);
        kind = "DMAR";
        break;
    case INTR_REMAP:
        printk(XENLOG_G_WARNING VTDPREFIX
               "INTR-REMAP: Request device [%pp] "
               "fault index %"PRIx64"\n",
               &PCI_SBDF(seg, source_id), addr >> 48);
        kind = "INTR-REMAP";
        break;
    default:
        printk(XENLOG_G_WARNING VTDPREFIX
               "UNKNOWN: Request device [%pp] "
               "fault addr %"PRIx64"\n",
               &PCI_SBDF(seg, source_id), addr);
        kind = "UNKNOWN";
        break;
    }

    printk(XENLOG_G_WARNING VTDPREFIX "%s: reason %02x - %s\n",
           kind, fault_reason, reason);

    if ( iommu_verbose && fault_type == DMA_REMAP )
        print_vtd_entries(iommu, PCI_BUS(source_id), PCI_DEVFN(source_id),
                          addr >> PAGE_SHIFT);

    return 0;
}

static void iommu_fault_status(u32 fault_status)
{
    if ( fault_status & DMA_FSTS_PFO )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Fault Overflow\n");
    if ( fault_status & DMA_FSTS_PPF )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Primary Pending Fault\n");
    if ( fault_status & DMA_FSTS_AFO )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Advanced Fault Overflow\n");
    if ( fault_status & DMA_FSTS_APF )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Advanced Pending Fault\n");
    if ( fault_status & DMA_FSTS_IQE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Queue Error\n");
    if ( fault_status & DMA_FSTS_ICE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Completion Error\n");
    if ( fault_status & DMA_FSTS_ITE )
        INTEL_IOMMU_DEBUG("iommu_fault_status: Invalidation Time-out Error\n");
}

#define PRIMARY_FAULT_REG_LEN (16)
static void __do_iommu_page_fault(struct vtd_iommu *iommu)
{
    int reg, fault_index;
    u32 fault_status;
    unsigned long flags;

    fault_status = dmar_readl(iommu->reg, DMAR_FSTS_REG);

    iommu_fault_status(fault_status);

    /* FIXME: ignore advanced fault log */
    if ( !(fault_status & DMA_FSTS_PPF) )
        goto clear_overflow;

    fault_index = dma_fsts_fault_record_index(fault_status);
    reg = cap_fault_reg_offset(iommu->cap);
    while (1)
    {
        u8 fault_reason;
        u16 source_id;
        u32 data;
        u64 guest_addr;
        int type;

        /* highest 32 bits */
        spin_lock_irqsave(&iommu->register_lock, flags);
        data = dmar_readl(iommu->reg, reg +
                          fault_index * PRIMARY_FAULT_REG_LEN + 12);
        if ( !(data & DMA_FRCD_F) )
        {
            spin_unlock_irqrestore(&iommu->register_lock, flags);
            break;
        }

        fault_reason = dma_frcd_fault_reason(data);
        type = dma_frcd_type(data);

        data = dmar_readl(iommu->reg, reg +
                          fault_index * PRIMARY_FAULT_REG_LEN + 8);
        source_id = dma_frcd_source_id(data);

        guest_addr = dmar_readq(iommu->reg, reg +
                                fault_index * PRIMARY_FAULT_REG_LEN);
        guest_addr = dma_frcd_page_addr(guest_addr);
        /* clear the fault */
        dmar_writel(iommu->reg, reg +
                    fault_index * PRIMARY_FAULT_REG_LEN + 12, DMA_FRCD_F);
        spin_unlock_irqrestore(&iommu->register_lock, flags);

        iommu_page_fault_do_one(iommu, type, fault_reason,
                                source_id, guest_addr);

        pci_check_disable_device(iommu->drhd->segment,
                                 PCI_BUS(source_id), PCI_DEVFN(source_id));

        fault_index++;
        if ( fault_index > cap_num_fault_regs(iommu->cap) )
            fault_index = 0;
    }
clear_overflow:
    /* clear primary fault overflow */
    if ( dmar_readl(iommu->reg, DMAR_FSTS_REG) & DMA_FSTS_PFO )
    {
        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_PFO);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }
}

static void cf_check do_iommu_page_fault(void *unused)
{
    struct acpi_drhd_unit *drhd;

    if ( list_empty(&acpi_drhd_units) )
    {
       INTEL_IOMMU_DEBUG("no device found, something must be very wrong!\n");
       return;
    }

    /*
     * No matter from whom the interrupt came from, check all the
     * IOMMUs present in the system. This allows for having just one
     * tasklet (instead of one per each IOMMUs) and should be more than
     * fine, considering how rare the event of a fault should be.
     */
    for_each_drhd_unit ( drhd )
        __do_iommu_page_fault(drhd->iommu);
}

static void cf_check iommu_page_fault(int irq, void *dev_id)
{
    /*
     * Just flag the tasklet as runnable. This is fine, according to VT-d
     * specs since a new interrupt won't be generated until we clear all
     * the faults that caused this one to happen.
     */
    tasklet_schedule(&vtd_fault_tasklet);
}

static void cf_check dma_msi_unmask(struct irq_desc *desc)
{
    struct vtd_iommu *iommu = desc->action->dev_id;
    unsigned long flags;
    u32 sts;

    /* unmask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
    sts &= ~DMA_FECTL_IM;
    dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    iommu->msi.msi_attrib.host_masked = 0;
}

static void cf_check dma_msi_mask(struct irq_desc *desc)
{
    unsigned long flags;
    struct vtd_iommu *iommu = desc->action->dev_id;
    u32 sts;

    /* mask it */
    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
    sts |= DMA_FECTL_IM;
    dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
    iommu->msi.msi_attrib.host_masked = 1;
}

static unsigned int cf_check dma_msi_startup(struct irq_desc *desc)
{
    dma_msi_unmask(desc);
    return 0;
}

static void cf_check dma_msi_ack(struct irq_desc *desc)
{
    irq_complete_move(desc);
    dma_msi_mask(desc);
    move_masked_irq(desc);
}

static void cf_check dma_msi_end(struct irq_desc *desc, u8 vector)
{
    dma_msi_unmask(desc);
    end_nonmaskable_irq(desc, vector);
}

static void cf_check dma_msi_set_affinity(
    struct irq_desc *desc, const cpumask_t *mask)
{
    struct msi_msg msg;
    unsigned int dest;
    unsigned long flags;
    struct vtd_iommu *iommu = desc->action->dev_id;

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID){
        dprintk(XENLOG_ERR VTDPREFIX, "Set iommu interrupt affinity error!\n");
        return;
    }

    msi_compose_msg(desc->arch.vector, NULL, &msg);
    msg.dest32 = dest;
    if (x2apic_enabled)
        msg.address_hi = dest & 0xFFFFFF00;
    ASSERT(!(msg.address_lo & MSI_ADDR_DEST_ID_MASK));
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);
    iommu->msi.msg = msg;

    spin_lock_irqsave(&iommu->register_lock, flags);
    dmar_writel(iommu->reg, DMAR_FEDATA_REG, msg.data);
    dmar_writel(iommu->reg, DMAR_FEADDR_REG, msg.address_lo);
    /*
     * When x2APIC is not enabled, DMAR_FEUADDR_REG is reserved and
     * it's not necessary to update it.
     */
    if ( x2apic_enabled )
        dmar_writel(iommu->reg, DMAR_FEUADDR_REG, msg.address_hi);
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static hw_irq_controller dma_msi_type = {
    .typename = "DMA_MSI",
    .startup = dma_msi_startup,
    .shutdown = dma_msi_mask,
    .enable = dma_msi_unmask,
    .disable = dma_msi_mask,
    .ack = dma_msi_ack,
    .end = dma_msi_end,
    .set_affinity = dma_msi_set_affinity,
};

static int __init iommu_set_interrupt(struct acpi_drhd_unit *drhd)
{
    int irq, ret;
    struct acpi_rhsa_unit *rhsa = drhd_to_rhsa(drhd);
    struct vtd_iommu *iommu = drhd->iommu;
    struct irq_desc *desc;

    irq = create_irq(rhsa ? pxm_to_node(rhsa->proximity_domain)
                          : NUMA_NO_NODE,
                     false);
    if ( irq <= 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: no irq available!\n");
        return -EINVAL;
    }

    desc = irq_to_desc(irq);
    desc->handler = &dma_msi_type;
    ret = request_irq(irq, 0, iommu_page_fault, "dmar", iommu);
    if ( ret )
    {
        desc->handler = &no_irq_type;
        destroy_irq(irq);
        dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: can't request irq\n");
        return ret;
    }

    iommu->msi.irq = irq;
    iommu->msi.msi_attrib.pos = MSI_TYPE_IOMMU;
    iommu->msi.msi_attrib.maskbit = 1;
    iommu->msi.msi_attrib.is_64 = 1;
    desc->msi_desc = &iommu->msi;

    return 0;
}

int __init iommu_alloc(struct acpi_drhd_unit *drhd)
{
    struct vtd_iommu *iommu;
    unsigned int sagaw, agaw = 0, nr_dom;
    domid_t reserved_domid = DOMID_INVALID;
    int rc;

    iommu = xzalloc(struct vtd_iommu);
    if ( iommu == NULL )
        return -ENOMEM;

    iommu->msi.irq = -1; /* No irq assigned yet. */
    iommu->node = NUMA_NO_NODE;
    INIT_LIST_HEAD(&iommu->ats_devices);
    spin_lock_init(&iommu->lock);
    spin_lock_init(&iommu->register_lock);
    spin_lock_init(&iommu->intremap.lock);

    iommu->drhd = drhd;
    drhd->iommu = iommu;

    iommu->reg = ioremap(drhd->address, PAGE_SIZE);
    rc = -ENOMEM;
    if ( !iommu->reg )
        goto free;
    iommu->index = nr_iommus++;

    iommu->cap = dmar_readq(iommu->reg, DMAR_CAP_REG);
    iommu->ecap = dmar_readq(iommu->reg, DMAR_ECAP_REG);
    iommu->version = dmar_readl(iommu->reg, DMAR_VER_REG);

    if ( !iommu_qinval && !has_register_based_invalidation(iommu) )
    {
        printk(XENLOG_WARNING VTDPREFIX "IOMMU %d: cannot disable Queued Invalidation\n",
               iommu->index);
        iommu_qinval = true;
    }

    if ( iommu_verbose )
    {
        printk(VTDPREFIX "drhd->address = %"PRIx64" iommu->reg = %p\n",
               drhd->address, iommu->reg);
        printk(VTDPREFIX "cap = %"PRIx64" ecap = %"PRIx64"\n",
               iommu->cap, iommu->ecap);
    }
    rc = -ENODEV;
    if ( !(iommu->cap + 1) || !(iommu->ecap + 1) )
        goto free;

    quirk_iommu_caps(iommu);

    nr_dom = cap_ndoms(iommu->cap);

    if ( cap_fault_reg_offset(iommu->cap) +
         cap_num_fault_regs(iommu->cap) * PRIMARY_FAULT_REG_LEN > PAGE_SIZE ||
         ((nr_dom - 1) >> 16) /* I.e. cap.nd > 6 */ ||
         (has_register_based_invalidation(iommu) &&
          ecap_iotlb_offset(iommu->ecap) >= PAGE_SIZE) )
    {
        printk(XENLOG_ERR VTDPREFIX "IOMMU: unsupported\n");
        print_iommu_regs(drhd);
        rc = -ENODEV;
        goto free;
    }

    /* Calculate number of pagetable levels: 3 or 4. */
    sagaw = cap_sagaw(iommu->cap);
    agaw = fls(sagaw & 6) - 1;
    if ( agaw <= 0 )
    {
        printk(XENLOG_ERR VTDPREFIX "IOMMU: unsupported sagaw %x\n", sagaw);
        print_iommu_regs(drhd);
        rc = -ENODEV;
        goto free;
    }

    if ( sagaw >> 3 )
    {
        printk_once(XENLOG_WARNING VTDPREFIX
                    " Unhandled bits in SAGAW %#x%s\n",
                    sagaw,
                    iommu_hwdom_passthrough ? ", disabling passthrough" : "");

        iommu_hwdom_passthrough = false;
    }

    iommu->nr_pt_levels = agaw_to_level(agaw);
    if ( min_pt_levels > iommu->nr_pt_levels )
        min_pt_levels = iommu->nr_pt_levels;

    if ( !ecap_coherent(iommu->ecap) )
        iommu_non_coherent = true;

    if ( nr_dom <= DOMID_MASK * 2 + cap_caching_mode(iommu->cap) )
    {
        /* Allocate domain id (bit) maps. */
        iommu->domid_bitmap = xzalloc_array(unsigned long,
                                            BITS_TO_LONGS(nr_dom));
        iommu->domid_map = xzalloc_array(domid_t, nr_dom);
        rc = -ENOMEM;
        if ( !iommu->domid_bitmap || !iommu->domid_map )
            goto free;

        /*
         * If Caching mode is set, then invalid translations are tagged
         * with domain id 0. Hence reserve bit/slot 0.
         */
        if ( cap_caching_mode(iommu->cap) )
        {
            iommu->domid_map[0] = DOMID_INVALID;
            __set_bit(0, iommu->domid_bitmap);
        }
    }
    else
    {
        /* Don't leave dangling NULL pointers. */
        iommu->domid_bitmap = ZERO_BLOCK_PTR;
        iommu->domid_map = ZERO_BLOCK_PTR;

        /*
         * If Caching mode is set, then invalid translations are tagged
         * with domain id 0. Hence reserve the ID taking up bit/slot 0.
         */
        reserved_domid = convert_domid(iommu, 0) ?: DOMID_INVALID;
    }

    iommu->pseudo_domid_map = iommu_init_domid(reserved_domid);
    rc = -ENOMEM;
    if ( !iommu->pseudo_domid_map )
        goto free;

    return 0;

 free:
    iommu_free(drhd);
    return rc;
}

void __init iommu_free(struct acpi_drhd_unit *drhd)
{
    struct vtd_iommu *iommu = drhd->iommu;

    if ( iommu == NULL )
        return;

    drhd->iommu = NULL;

    if ( iommu->root_maddr != 0 )
    {
        free_pgtable_maddr(iommu->root_maddr);
        iommu->root_maddr = 0;
    }

    if ( iommu->reg )
        iounmap(iommu->reg);

    xfree(iommu->domid_bitmap);
    xfree(iommu->domid_map);
    xfree(iommu->pseudo_domid_map);

    if ( iommu->msi.irq >= 0 )
        destroy_irq(iommu->msi.irq);
    xfree(iommu);
}

#define guestwidth_to_adjustwidth(gaw) ({       \
    int agaw, r = (gaw - 12) % 9;               \
    agaw = (r == 0) ? gaw : (gaw + 9 - r);      \
    if ( agaw > 64 )                            \
        agaw = 64;                              \
    agaw; })

static int cf_check intel_iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    hd->arch.vtd.agaw = width_to_agaw(DEFAULT_DOMAIN_ADDRESS_WIDTH);

    return 0;
}

static void __hwdom_init cf_check intel_iommu_hwdom_init(struct domain *d)
{
    struct acpi_drhd_unit *drhd;

    setup_hwdom_pci_devices(d, setup_hwdom_device);
    setup_hwdom_rmrr(d);
    /* Make sure workarounds are applied before enabling the IOMMU(s). */
    arch_iommu_hwdom_init(d);

    if ( iommu_flush_all() )
        printk(XENLOG_WARNING VTDPREFIX
               " IOMMU flush all failed for hardware domain\n");

    for_each_drhd_unit ( drhd )
    {
        if ( iomem_deny_access(d, PFN_DOWN(drhd->address),
                               PFN_DOWN(drhd->address)) )
            BUG();
        iommu_enable_translation(drhd);
    }
}

/**
 * Apply a context on a device.
 * @param domain Domain of the context
 * @param iommu IOMMU hardware to use (must match device iommu)
 * @param ctx IOMMU context to apply
 * @param devfn PCI device function (may be different to pdev)
 */
int apply_context_single(struct domain *domain, struct iommu_context *ctx,
                         struct vtd_iommu *iommu, uint8_t bus, uint8_t devfn)
{
    struct context_entry *context, *context_entries, lctxt;
    __uint128_t res, old;
    uint64_t maddr;
    uint16_t seg = iommu->drhd->segment, prev_did = 0, did;
    int rc, ret;
    bool flush_dev_iotlb, overwrite_entry = false;

    printk("apply_context_single: %hud %huc %pp\n", domain->domain_id, ctx->id, &PCI_SBDF(seg, bus, devfn));

    ASSERT(pcidevs_locked());
    spin_lock(&iommu->lock);
    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];
    old = (lctxt = *context).full;

    did = ctx->arch.vtd.didmap[iommu->index];
    printk("apply_context_single: did=%hu\n", did);

    if ( context_present(*context) )
    {
        prev_did = context_domain_id(lctxt);
        overwrite_entry = true;
    }

    if ( iommu_hwdom_passthrough && is_hardware_domain(domain) && !ctx->id )
    {
        context_set_translation_type(lctxt, CONTEXT_TT_PASS_THRU);
    }
    else
    {
        paddr_t root;

        root = get_context_pgd(domain, ctx, iommu->nr_pt_levels);
        if ( !root )
        {
            unmap_vtd_domain_page(context_entries);
            return -ENOMEM;
        }

        context_set_address_root(lctxt, root);
        if ( ats_enabled && ecap_dev_iotlb(iommu->ecap) )
            context_set_translation_type(lctxt, CONTEXT_TT_DEV_IOTLB);
        else
            context_set_translation_type(lctxt, CONTEXT_TT_MULTI_LEVEL);
    }

    rc = context_set_domain_id(&lctxt, did, iommu);
    if ( rc )
        goto unlock;

    context_set_address_width(lctxt, level_to_agaw(iommu->nr_pt_levels));
    context_set_fault_enable(lctxt);
    context_set_present(lctxt);

    res = cmpxchg16b(context, &old, &lctxt.full);

    /*
     * Hardware does not update the context entry behind our backs,
     * so the return value should match "old".
     */
    if ( res != old )
    {
        printk(XENLOG_ERR
                "%pp: unexpected context entry %016lx_%016lx (expected %016lx_%016lx)\n",
                &PCI_SBDF(seg, bus, devfn),
                (uint64_t)(res >> 64), (uint64_t)res,
                (uint64_t)(old >> 64), (uint64_t)old);
        rc = -EILSEQ;
        goto unlock;
    }

    iommu_sync_cache(context, sizeof(struct context_entry));

    rc = iommu_flush_context_device(iommu, prev_did, PCI_BDF(bus, devfn),
                                    DMA_CCMD_MASK_NOBIT, !overwrite_entry);
    flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
    ret = iommu_flush_iotlb_dsi(iommu, prev_did, !overwrite_entry, flush_dev_iotlb);

    /*
     * The current logic for returns:
     *   - positive  invoke iommu_flush_write_buffer to flush cache.
     *   - zero      on success.
     *   - negative  on failure. Continue to flush IOMMU IOTLB on a
     *               best effort basis.
     */
    if ( rc > 0 || ret > 0 )
        iommu_flush_write_buffer(iommu);
    if ( rc >= 0 )
        rc = ret;
    if ( rc > 0 )
        rc = 0;

    set_bit(iommu->index, ctx->arch.vtd.iommu_bitmap);

    unmap_vtd_domain_page(context_entries);
    spin_unlock(&iommu->lock);

    if ( !seg && !rc )
        rc = me_wifi_quirk(domain, bus, devfn, did, 0, ctx);

    return rc;

    unlock:
        unmap_vtd_domain_page(context_entries);
        spin_unlock(&iommu->lock);
        return rc;
}

int apply_context(struct domain *d, struct iommu_context *ctx,
                  struct pci_dev *pdev, u8 devfn)
{
    const struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);
    int ret = 0;

    if ( !drhd )
        return -EINVAL;

    ASSERT(pcidevs_locked());

    ret = apply_context_single(d, ctx, drhd->iommu, pdev->bus, devfn);

    if ( !ret && devfn == pdev->devfn )
        pci_vtd_quirk(pdev);

    return ret;
}

int unapply_context_single(struct domain *domain, struct iommu_context *ctx,
                           struct vtd_iommu *iommu, uint8_t bus, uint8_t devfn)
{
    struct context_entry *context, *context_entries;
    u64 maddr;
    int iommu_domid, rc, ret;
    bool flush_dev_iotlb;

    ASSERT(pcidevs_locked());
    spin_lock(&iommu->lock);

    maddr = bus_to_context_maddr(iommu, bus);
    context_entries = (struct context_entry *)map_vtd_domain_page(maddr);
    context = &context_entries[devfn];

    if ( !context_present(*context) )
    {
        unmap_vtd_domain_page(context_entries);
        spin_unlock(&iommu->lock);
        return 0;
    }

    iommu_domid = context_domain_id(*context);

    context_clear_present(*context);
    context_clear_entry(*context);
    iommu_sync_cache(context, sizeof(struct context_entry));

    rc = iommu_flush_context_device(iommu, iommu_domid,
                                    PCI_BDF(bus, devfn),
                                    DMA_CCMD_MASK_NOBIT, 0);

    flush_dev_iotlb = !!find_ats_dev_drhd(iommu);
    ret = iommu_flush_iotlb_dsi(iommu, iommu_domid, 0, flush_dev_iotlb);

    /*
     * The current logic for returns:
     *   - positive  invoke iommu_flush_write_buffer to flush cache.
     *   - zero      on success.
     *   - negative  on failure. Continue to flush IOMMU IOTLB on a
     *               best effort basis.
     */
    if ( rc > 0 || ret > 0 )
        iommu_flush_write_buffer(iommu);
    if ( rc >= 0 )
        rc = ret;
    if ( rc > 0 )
        rc = 0;

    unmap_vtd_domain_page(context_entries);

    if ( !iommu->drhd->segment && !rc )
        rc = me_wifi_quirk(domain, bus, devfn, DOMID_INVALID, UNMAP_ME_PHANTOM_FUNC,
                           NULL);

    if ( rc && !is_hardware_domain(domain) && domain != dom_io )
    {
        if ( domain->is_dying )
        {
            printk(XENLOG_ERR "%pd: error %d unmapping %04x:%02x:%02x.%u\n",
                   domain, rc, iommu->drhd->segment, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
            rc = 0; /* Make upper layers continue in a best effort manner. */
        }
        else
            domain_crash(domain);
    }

    spin_unlock(&iommu->lock);
    return rc;
}

static void cf_check iommu_clear_root_pgtable(struct domain *d, struct iommu_context *ctx)
{
    //struct domain_iommu *hd = dom_iommu(d);

    //spin_lock(&hd->lock);
    ctx->arch.vtd.pgd_maddr = 0;
    //spin_unlock(&hd->lock);
}

static void cf_check iommu_domain_teardown(struct domain *d)
{
    struct iommu_context *ctx = iommu_default_context(d);
    const struct acpi_drhd_unit *drhd;

    if ( list_empty(&acpi_drhd_units) )
        return;

    iommu_identity_map_teardown(d);

    ASSERT(!ctx->arch.vtd.pgd_maddr);

    for_each_drhd_unit ( drhd )
        cleanup_domid_map(d->domain_id, drhd->iommu);
}

static int __must_check cf_check intel_iommu_map_page(
    struct domain *d, dfn_t dfn, mfn_t mfn, unsigned int flags,
    unsigned int *flush_flags, struct iommu_context *ctx)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct dma_pte *page, *pte, old, new = {};
    u64 pg_maddr;
    unsigned int level = (IOMMUF_order(flags) / LEVEL_STRIDE) + 1;
    int rc = 0;

    ASSERT((hd->platform_ops->page_sizes >> IOMMUF_order(flags)) &
           PAGE_SIZE_4K);

    /* Do nothing if VT-d shares EPT page table */
    if ( iommu_use_hap_pt(d) && !ctx->id )
        return 0;

    /* Do nothing if hardware domain and iommu supports pass thru. */
    if ( iommu_hwdom_passthrough && is_hardware_domain(d) && !ctx->id )
        return 0;

    /*
     * IOMMU mapping request can be safely ignored when the domain is dying.
     *
     * hd->lock guarantees that d->is_dying will be observed
     * before any page tables are freed (see iommu_free_pgtables())
     */
    if ( d->is_dying )
    {
        return 0;
    }

    pg_maddr = addr_to_dma_page_maddr(d, ctx, dfn_to_daddr(dfn), level, flush_flags,
                                      true);
    if ( pg_maddr < PAGE_SIZE )
    {
        return -ENOMEM;
    }

    page = (struct dma_pte *)map_vtd_domain_page(pg_maddr);
    pte = &page[address_level_offset(dfn_to_daddr(dfn), level)];
    old = *pte;

    dma_set_pte_addr(new, mfn_to_maddr(mfn));
    dma_set_pte_prot(new,
                     ((flags & IOMMUF_readable) ? DMA_PTE_READ  : 0) |
                     ((flags & IOMMUF_writable) ? DMA_PTE_WRITE : 0));
    if ( IOMMUF_order(flags) )
        dma_set_pte_superpage(new);

    /* Set the SNP on leaf page table if Snoop Control available */
    if ( iommu_snoop )
        dma_set_pte_snp(new);

    if ( !((old.val ^ new.val) & ~DMA_PTE_CONTIG_MASK) )
    {
        unmap_vtd_domain_page(page);
        return 0;
    }

    *pte = new;
    iommu_sync_cache(pte, sizeof(struct dma_pte));

    /*
     * While the (ab)use of PTE_kind_table here allows to save some work in
     * the function, the main motivation for it is that it avoids a so far
     * unexplained hang during boot (while preparing Dom0) on a Westmere
     * based laptop.  This also has the intended effect of terminating the
     * loop when super pages aren't supported anymore at the next level.
     */
    while ( pt_update_contig_markers(&page->val,
                                     address_level_offset(dfn_to_daddr(dfn), level),
                                     level,
                                     (hd->platform_ops->page_sizes &
                                      (1UL << level_to_offset_bits(level + 1))
                                       ? PTE_kind_leaf : PTE_kind_table)) )
    {
        struct page_info *pg = maddr_to_page(pg_maddr);

        unmap_vtd_domain_page(page);

        new.val &= ~(LEVEL_MASK << level_to_offset_bits(level));
        dma_set_pte_superpage(new);

        pg_maddr = addr_to_dma_page_maddr(d, ctx, dfn_to_daddr(dfn), ++level,
                                          flush_flags, false);
        BUG_ON(pg_maddr < PAGE_SIZE);

        page = map_vtd_domain_page(pg_maddr);
        pte = &page[address_level_offset(dfn_to_daddr(dfn), level)];
        *pte = new;
        iommu_sync_cache(pte, sizeof(*pte));

        *flush_flags |= IOMMU_FLUSHF_modified | IOMMU_FLUSHF_all;
        iommu_queue_free_pgtable(ctx, pg);
        perfc_incr(iommu_pt_coalesces);
    }

    unmap_vtd_domain_page(page);

    *flush_flags |= IOMMU_FLUSHF_added;
    if ( dma_pte_present(old) )
    {
        *flush_flags |= IOMMU_FLUSHF_modified;

        if ( IOMMUF_order(flags) && !dma_pte_superpage(old) )
            queue_free_pt(ctx, maddr_to_mfn(dma_pte_addr(old)),
                          IOMMUF_order(flags) / LEVEL_STRIDE);
    }

    return rc;
}

static int __must_check cf_check intel_iommu_unmap_page(
    struct domain *d, dfn_t dfn, unsigned int order, unsigned int *flush_flags,
    struct iommu_context *ctx)
{
    struct domain_iommu *hd = dom_iommu(d);
    daddr_t addr = dfn_to_daddr(dfn);
    struct dma_pte *page = NULL, *pte = NULL, old;
    uint64_t pg_maddr;
    unsigned int level = (order / LEVEL_STRIDE) + 1;

    /*
     * While really we could unmap at any granularity, for now we assume unmaps
     * are issued by common code only at the same granularity as maps.
     */
    ASSERT((hd->platform_ops->page_sizes >> order) & PAGE_SIZE_4K);

    /* Do nothing if VT-d shares EPT page table */
    if ( iommu_use_hap_pt(d) && !ctx->id )
        return 0;

    /* Do nothing if hardware domain and iommu supports pass thru. */
    if ( iommu_hwdom_passthrough && is_hardware_domain(d) )
        return 0;

    /* get target level pte */
    pg_maddr = addr_to_dma_page_maddr(d, ctx, addr, level, flush_flags, false);
    if ( pg_maddr < PAGE_SIZE )
        return pg_maddr ? -ENOMEM : 0;

    page = map_vtd_domain_page(pg_maddr);
    pte = &page[address_level_offset(addr, level)];

    if ( !dma_pte_present(*pte) )
    {
        unmap_vtd_domain_page(page);
        return 0;
    }

    old = *pte;
    dma_clear_pte(*pte);
    iommu_sync_cache(pte, sizeof(*pte));

    while ( pt_update_contig_markers(&page->val,
                                     address_level_offset(addr, level),
                                     level, PTE_kind_null) &&
            ++level < min_pt_levels )
    {
        struct page_info *pg = maddr_to_page(pg_maddr);

        unmap_vtd_domain_page(page);

        pg_maddr = addr_to_dma_page_maddr(d, ctx, addr, level, flush_flags, false);
        BUG_ON(pg_maddr < PAGE_SIZE);

        page = map_vtd_domain_page(pg_maddr);
        pte = &page[address_level_offset(addr, level)];
        dma_clear_pte(*pte);
        iommu_sync_cache(pte, sizeof(*pte));

        *flush_flags |= IOMMU_FLUSHF_all;
        iommu_queue_free_pgtable(ctx, pg);
        perfc_incr(iommu_pt_coalesces);
    }

    unmap_vtd_domain_page(page);

    *flush_flags |= IOMMU_FLUSHF_modified;

    if ( order && !dma_pte_superpage(old) )
        queue_free_pt(ctx, maddr_to_mfn(dma_pte_addr(old)),
                      order / LEVEL_STRIDE);

    return 0;
}

static int cf_check intel_iommu_lookup_page(
    struct domain *d, dfn_t dfn, mfn_t *mfn, unsigned int *flags,
    struct iommu_context *ctx)
{
    uint64_t val;

    /*
     * If VT-d shares EPT page table or if the domain is the hardware
     * domain and iommu_passthrough is set then pass back the dfn.
     */
    if ( iommu_use_hap_pt(d) ||
         (iommu_hwdom_passthrough && is_hardware_domain(d)) )
        return -EOPNOTSUPP;


    val = addr_to_dma_page_maddr(d, ctx, dfn_to_daddr(dfn), 0, NULL, false);

    if ( val < PAGE_SIZE )
        return -ENOENT;

    *mfn = maddr_to_mfn(val);
    *flags = val & DMA_PTE_READ ? IOMMUF_readable : 0;
    *flags |= val & DMA_PTE_WRITE ? IOMMUF_writable : 0;

    return 0;
}

static bool __init vtd_ept_page_compatible(const struct vtd_iommu *iommu)
{
    uint64_t ept_cap, vtd_cap = iommu->cap;

    if ( !IS_ENABLED(CONFIG_HVM) )
        return false;

    /* EPT is not initialised yet, so we must check the capability in
     * the MSR explicitly rather than use cpu_has_vmx_ept_*() */
    if ( rdmsr_safe(MSR_IA32_VMX_EPT_VPID_CAP, ept_cap) != 0 )
        return false;

    return (ept_has_2mb(ept_cap) && opt_hap_2mb) <=
            (cap_sps_2mb(vtd_cap) && iommu_superpages) &&
           (ept_has_1gb(ept_cap) && opt_hap_1gb) <=
            (cap_sps_1gb(vtd_cap) && iommu_superpages);
}

static int cf_check intel_iommu_enable_device(struct pci_dev *pdev)
{
    struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);
    int ret = drhd ? ats_device(pdev, drhd) : -ENODEV;

    pci_vtd_quirk(pdev);

    if ( ret <= 0 )
        return ret;

    ret = enable_ats_device(pdev, &drhd->iommu->ats_devices);

    return ret >= 0 ? 0 : ret;
}

static int __hwdom_init cf_check setup_hwdom_device(
    u8 devfn, struct pci_dev *pdev)
{
    if (pdev->type == DEV_TYPE_PCI_HOST_BRIDGE ||
        pdev->type == DEV_TYPE_PCIe_BRIDGE ||
        pdev->type == DEV_TYPE_PCIe2PCI_BRIDGE ||
        pdev->type == DEV_TYPE_LEGACY_PCI_BRIDGE)
        return 0;

    return _iommu_attach_context(hardware_domain, pdev, 0);
}

void clear_fault_bits(struct vtd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->register_lock, flags);

    if ( dmar_readl(iommu->reg, DMAR_FSTS_REG) & DMA_FSTS_PPF )
    {
        unsigned int reg = cap_fault_reg_offset(iommu->cap);
        unsigned int end = reg + cap_num_fault_regs(iommu->cap);

        do {
           dmar_writel(iommu->reg, reg + 12, DMA_FRCD_F);
           reg += PRIMARY_FAULT_REG_LEN;
        } while ( reg < end );
    }

    dmar_writel(iommu->reg, DMAR_FSTS_REG, DMA_FSTS_FAULTS);

    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

static void adjust_irq_affinity(struct acpi_drhd_unit *drhd)
{
    const struct acpi_rhsa_unit *rhsa = drhd_to_rhsa(drhd);
    unsigned int node = rhsa ? pxm_to_node(rhsa->proximity_domain)
                             : NUMA_NO_NODE;
    const cpumask_t *cpumask = NULL;
    struct irq_desc *desc;
    unsigned long flags;

    if ( node < MAX_NUMNODES && node_online(node) &&
         cpumask_intersects(&node_to_cpumask(node), &cpu_online_map) )
        cpumask = &node_to_cpumask(node);

    desc = irq_to_desc(drhd->iommu->msi.irq);
    spin_lock_irqsave(&desc->lock, flags);
    dma_msi_set_affinity(desc, cpumask);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static void cf_check adjust_vtd_irq_affinities(void)
{
    struct acpi_drhd_unit *drhd;

    for_each_drhd_unit ( drhd )
        adjust_irq_affinity(drhd);
}

static int __must_check init_vtd_hw(bool resume)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    int ret;
    unsigned long flags;
    u32 sts;

    /*
     * Basic VT-d HW init: set VT-d interrupt, clear VT-d faults, etc.
     */
    for_each_drhd_unit ( drhd )
    {
        adjust_irq_affinity(drhd);

        iommu = drhd->iommu;

        clear_fault_bits(iommu);

        /*
         * Disable interrupt remapping and queued invalidation if
         * already enabled by BIOS in case we've not initialized it yet.
         */
        if ( !iommu_x2apic_enabled )
        {
            disable_intremap(iommu);
            disable_qinval(iommu);
        }

        if ( resume )
            /* FECTL write done by vtd_resume(). */
            continue;

        spin_lock_irqsave(&iommu->register_lock, flags);
        sts = dmar_readl(iommu->reg, DMAR_FECTL_REG);
        sts &= ~DMA_FECTL_IM;
        dmar_writel(iommu->reg, DMAR_FECTL_REG, sts);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }

    /*
     * Enable queue invalidation
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        /*
         * If queued invalidation not enabled, use regiser based
         * invalidation
         */
        if ( enable_qinval(iommu) != 0 )
        {
            /* Ensure register-based invalidation is available */
            if ( !has_register_based_invalidation(iommu) )
                return -EIO;

            iommu->flush.context = vtd_flush_context_reg;
            iommu->flush.iotlb   = vtd_flush_iotlb_reg;
        }
    }

    /*
     * Enable interrupt remapping
     */
    if ( iommu_intremap != iommu_intremap_off )
    {
        int apic;
        for ( apic = 0; apic < nr_ioapics; apic++ )
        {
            if ( ioapic_to_iommu(IO_APIC_ID(apic)) == NULL )
            {
                iommu_intremap = iommu_intremap_off;
                dprintk(XENLOG_ERR VTDPREFIX,
                    "ioapic_to_iommu: ioapic %#x (id: %#x) is NULL! "
                    "Will not try to enable Interrupt Remapping.\n",
                    apic, IO_APIC_ID(apic));
                break;
            }
        }
    }
    if ( iommu_intremap != iommu_intremap_off )
    {
        for_each_drhd_unit ( drhd )
        {
            iommu = drhd->iommu;
            if ( enable_intremap(iommu, 0) != 0 )
            {
                iommu_intremap = iommu_intremap_off;
                dprintk(XENLOG_WARNING VTDPREFIX,
                        "Interrupt Remapping not enabled\n");

                break;
            }
        }
        if ( !iommu_intremap )
            for_each_drhd_unit ( drhd )
                disable_intremap(drhd->iommu);
    }

    /*
     * Set root entries for each VT-d engine.  After set root entry,
     * must globally invalidate context cache, and then globally
     * invalidate IOTLB
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        ret = iommu_set_root_entry(iommu);
        if ( ret )
        {
            dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: set root entry failed\n");
            return -EIO;
        }
    }

    return iommu_flush_all();
}

static void __hwdom_init setup_hwdom_rmrr(struct domain *d)
{
    struct acpi_rmrr_unit *rmrr;
    u16 bdf;
    int ret, i;

    pcidevs_lock();
    for_each_rmrr_device ( rmrr, bdf, i )
    {
        /*
         * Here means we're add a device to the hardware domain.
         * Since RMRRs are always reserved in the e820 map for the hardware
         * domain, there shouldn't be a conflict. So its always safe and
         * strict to set 0.
         */
        ret = iommu_identity_mapping(d, p2m_access_rw, rmrr->base_address,
                                     rmrr->end_address, 0);
        if ( ret )
            dprintk(XENLOG_ERR VTDPREFIX,
                     "IOMMU: mapping reserved region failed\n");
    }
    pcidevs_unlock();
}

static struct iommu_state {
    uint32_t fectl;
} *__read_mostly iommu_state;

static void arch_iommu_dump_domain_contexts(struct domain *d)
{
    unsigned int i, iommu_no;
    struct pci_dev *pdev;
    struct iommu_context *ctx;
    struct domain_iommu *hd = dom_iommu(d);

    printk("d%hu contexts\n", d->domain_id);

    spin_lock(&hd->lock);

    for (i = 0; i < (1 + dom_iommu(d)->other_contexts.count); ++i)
    {
        if (iommu_check_context(d, i))
        {
            ctx = iommu_get_context(d, i);
            printk(" Context %d (%"PRIx64")\n", i, ctx->arch.vtd.pgd_maddr);

            for (iommu_no = 0; iommu_no < nr_iommus; iommu_no++)
                printk("  IOMMU %hu (used=%u; did=%hu)\n", iommu_no,
                       test_bit(iommu_no, ctx->arch.vtd.iommu_bitmap),
                       ctx->arch.vtd.didmap[iommu_no]);

            list_for_each_entry(pdev, &ctx->devices, context_list)
            {
                printk("  - %pp\n", &pdev->sbdf);
            }
        }
    }

    spin_unlock(&hd->lock);
}

static void arch_iommu_dump_contexts(unsigned char key)
{
    struct domain *d;

    for_each_domain(d) {
        arch_iommu_dump_domain_contexts(d);
    }
}
static int __init cf_check vtd_setup(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    unsigned int large_sizes = iommu_superpages ? PAGE_SIZE_2M | PAGE_SIZE_1G : 0;
    int ret;
    bool reg_inval_supported = true;

    if ( list_empty(&acpi_drhd_units) )
    {
        ret = -ENODEV;
        goto error;
    }

    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
    {
        ret = -EPERM;
        goto error;
    }

    platform_quirks_init();
    if ( !iommu_enable )
    {
        ret = -ENODEV;
        goto error;
    }

    iommu_state = xmalloc_array(struct iommu_state, nr_iommus);
    if ( !iommu_state )
    {
        ret = -ENOMEM;
        goto error;
    }

    /* We enable the following features only if they are supported by all VT-d
     * engines: Snoop Control, DMA passthrough, Register-based Invalidation,
     * Queued Invalidation, Interrupt Remapping, and Posted Interrupt.
     */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        printk("Intel VT-d iommu %u supported page sizes: 4kB%s%s\n",
               iommu->index,
               cap_sps_2mb(iommu->cap) ? ", 2MB" : "",
               cap_sps_1gb(iommu->cap) ? ", 1GB" : "");

        if ( !cap_sps_2mb(iommu->cap) )
            large_sizes &= ~PAGE_SIZE_2M;
        if ( !cap_sps_1gb(iommu->cap) )
            large_sizes &= ~PAGE_SIZE_1G;

#ifndef iommu_snoop
        if ( iommu_snoop && !ecap_snp_ctl(iommu->ecap) )
            iommu_snoop = false;
#endif

        if ( iommu_hwdom_passthrough && !ecap_pass_thru(iommu->ecap) )
            iommu_hwdom_passthrough = false;

        if ( iommu_qinval && !ecap_queued_inval(iommu->ecap) )
            iommu_qinval = 0;

        if ( !has_register_based_invalidation(iommu) )
            reg_inval_supported = false;

        if ( iommu_intremap && !ecap_intr_remap(iommu->ecap) )
            iommu_intremap = iommu_intremap_off;

#ifndef iommu_intpost
        /*
         * We cannot use posted interrupt if X86_FEATURE_CX16 is
         * not supported, since we count on this feature to
         * atomically update 16-byte IRTE in posted format.
         */
        if ( !cap_intr_post(iommu->cap) || !iommu_intremap || !cpu_has_cx16 )
            iommu_intpost = false;
#endif

        if ( !vtd_ept_page_compatible(iommu) )
            clear_iommu_hap_pt_share();

        ret = iommu_set_interrupt(drhd);
        if ( ret )
        {
            dprintk(XENLOG_ERR VTDPREFIX, "IOMMU: interrupt setup failed\n");
            goto error;
        }
    }

    softirq_tasklet_init(&vtd_fault_tasklet, do_iommu_page_fault, NULL);

    if ( !iommu_qinval && !reg_inval_supported )
    {
        dprintk(XENLOG_ERR VTDPREFIX, "No available invalidation interface\n");
        ret = -ENODEV;
        goto error;
    }

    if ( !iommu_qinval && iommu_intremap )
    {
        iommu_intremap = iommu_intremap_off;
        dprintk(XENLOG_WARNING VTDPREFIX, "Interrupt Remapping disabled "
            "since Queued Invalidation isn't supported or enabled.\n");
    }

#define P(p,s) printk("Intel VT-d %s %senabled.\n", s, (p)? "" : "not ")
#ifndef iommu_snoop
    P(iommu_snoop, "Snoop Control");
#endif
    P(iommu_hwdom_passthrough, "Dom0 DMA Passthrough");
    P(iommu_qinval, "Queued Invalidation");
    P(iommu_intremap, "Interrupt Remapping");
#ifndef iommu_intpost
    P(iommu_intpost, "Posted Interrupt");
#endif
    P(iommu_hap_pt_share, "Shared EPT tables");
#undef P

    ret = init_vtd_hw(false);
    if ( ret )
        goto error;

    ASSERT(iommu_ops.page_sizes == PAGE_SIZE_4K);
    iommu_ops.page_sizes |= large_sizes;

    register_keyhandler('V', vtd_dump_iommu_info, "dump iommu info", 1);
    register_keyhandler('X', arch_iommu_dump_contexts, "dump iommu contexts", 1);

    return 0;

 error:
    iommu_enabled = 0;
    iommu_hwdom_passthrough = false;
    iommu_qinval = 0;
    iommu_intremap = iommu_intremap_off;
#ifndef iommu_intpost
    iommu_intpost = false;
#endif
    return ret;
}

static int cf_check intel_iommu_group_id(u16 seg, u8 bus, u8 devfn)
{
    u8 secbus;

    if ( find_upstream_bridge(seg, &bus, &devfn, &secbus) < 0 )
        return -ENODEV;

    return PCI_BDF(bus, devfn);
}

static int __must_check cf_check vtd_suspend(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    u32    i;
    int rc;

    if ( !iommu_enabled )
        return 0;

    rc = iommu_flush_all();
    if ( unlikely(rc) )
    {
        printk(XENLOG_WARNING VTDPREFIX
               " suspend: IOMMU flush all failed: %d\n", rc);

        return rc;
    }

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        i = iommu->index;

        iommu_state[i].fectl = dmar_readl(iommu->reg, DMAR_FECTL_REG);

        /* don't disable VT-d engine when force_iommu is set. */
        if ( force_iommu )
            continue;

        iommu_disable_translation(iommu);

        /* If interrupt remapping is enabled, queued invalidation
         * will be disabled following interupt remapping disabling
         * in local apic suspend
         */
        if ( !iommu_intremap && iommu_qinval )
            disable_qinval(iommu);
    }

    return 0;
}

static void cf_check vtd_crash_shutdown(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;

    if ( !iommu_enabled )
        return;

    if ( iommu_flush_all() )
        printk(XENLOG_WARNING VTDPREFIX
               " crash shutdown: IOMMU flush all failed\n");

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        iommu_disable_translation(iommu);
        disable_intremap(drhd->iommu);
        disable_qinval(drhd->iommu);
    }
}

static void cf_check vtd_resume(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;
    u32 i;
    unsigned long flags;

    if ( !iommu_enabled )
        return;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FEDATA_REG, iommu->msi.msg.data);
        dmar_writel(iommu->reg, DMAR_FEADDR_REG, iommu->msi.msg.address_lo);
        if ( x2apic_enabled )
            dmar_writel(iommu->reg, DMAR_FEUADDR_REG,
                        iommu->msi.msg.address_hi);
        spin_unlock_irqrestore(&iommu->register_lock, flags);
    }

    if ( init_vtd_hw(true) != 0 && force_iommu )
         panic("IOMMU setup failed, crash Xen for security purpose\n");

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        i = iommu->index;

        spin_lock_irqsave(&iommu->register_lock, flags);
        dmar_writel(iommu->reg, DMAR_FECTL_REG, iommu_state[i].fectl);
        spin_unlock_irqrestore(&iommu->register_lock, flags);

        iommu_enable_translation(drhd);
    }
}

static void vtd_dump_page_table_level(paddr_t pt_maddr, int level, paddr_t gpa,
                                      int indent)
{
    paddr_t address;
    int i;
    struct dma_pte *pt_vaddr, *pte;
    int next_level;

    if ( level < 1 )
        return;

    if (pt_maddr == 0) {
        printk(" (empty)\n");
        return;
    }

    pt_vaddr = map_vtd_domain_page(pt_maddr);

    next_level = level - 1;
    for ( i = 0; i < PTE_NUM; i++ )
    {
        if ( !(i % 2) )
            process_pending_softirqs();

        pte = &pt_vaddr[i];
        if ( !dma_pte_present(*pte) )
            continue;

        address = gpa + offset_level_address(i, level);
        if ( next_level && !dma_pte_superpage(*pte) )
            vtd_dump_page_table_level(dma_pte_addr(*pte), next_level,
                                      address, indent + 1);
        else
            printk("%*sdfn: %08lx mfn: %08lx %c%c\n",
                   indent, "",
                   (unsigned long)(address >> PAGE_SHIFT_4K),
                   (unsigned long)(dma_pte_addr(*pte) >> PAGE_SHIFT_4K),
                   dma_pte_read(*pte) ? 'r' : '-',
                   dma_pte_write(*pte) ? 'w' : '-');
    }

    unmap_vtd_domain_page(pt_vaddr);
}

static void cf_check vtd_dump_page_tables(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned int i;

    printk(VTDPREFIX" %pd table has %d levels\n", d,
           agaw_to_level(hd->arch.vtd.agaw));

    for (i = 1; i < (1 + hd->other_contexts.count); ++i)
    {
        bool allocated = iommu_check_context(d, i);
        printk(VTDPREFIX " %pd context %d: %s\n", d, i,
               allocated ? "allocated" : "non-allocated");

        if (allocated) {
            const struct iommu_context *ctx = iommu_get_context(d, i);
            vtd_dump_page_table_level(ctx->arch.vtd.pgd_maddr,
                                      agaw_to_level(hd->arch.vtd.agaw), 0, 0);
        }
    }
}

static int intel_iommu_context_init(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct acpi_drhd_unit *drhd;

    ctx->arch.vtd.didmap = xzalloc_array(u16, nr_iommus);

    if (!ctx->arch.vtd.didmap)
        return -ENOMEM;

    ctx->arch.vtd.iommu_bitmap = xzalloc_array(unsigned long,
                                              BITS_TO_LONGS(nr_iommus));
    if ( !ctx->arch.vtd.iommu_bitmap )
        return -ENOMEM;

    if ( flags & IOMMU_CONTEXT_INIT_default )
    {
        ctx->arch.vtd.pgd_maddr = 0;

        /* Populate context DID map using domain id. */
        for_each_drhd_unit(drhd)
        {
            ctx->arch.vtd.didmap[drhd->iommu->index] =
                convert_domid(drhd->iommu, d->domain_id);
        }
    }
    else
    {
        /* Populate context DID map using pseudo DIDs */
        for_each_drhd_unit(drhd)
        {
            ctx->arch.vtd.didmap[drhd->iommu->index] =
                iommu_alloc_domid(drhd->iommu->pseudo_domid_map);
        }

        /* Create initial context page */
        addr_to_dma_page_maddr(d, ctx, 0, min_pt_levels, NULL, true);
    }

    return arch_iommu_context_init(d, ctx, flags);
}

static int intel_iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct acpi_drhd_unit *drhd;

    if (ctx->arch.vtd.didmap)
    {
        for_each_drhd_unit(drhd)
        {
            iommu_free_domid(ctx->arch.vtd.didmap[drhd->iommu->index],
                drhd->iommu->pseudo_domid_map);
        }

        xfree(ctx->arch.vtd.didmap);
    }

    return arch_iommu_context_teardown(d, ctx, flags);
}

static int intel_iommu_attach(struct domain *d, struct pci_dev *pdev,
                              struct iommu_context *ctx)
{
    int ret;
    const struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);

    if (!pdev || !drhd)
        return -EINVAL;

    ret = apply_context(d, ctx, pdev, pdev->devfn);

    if ( ret )
        return ret;

    pci_vtd_quirk(pdev);

    return ret;
}

static int intel_iommu_dettach(struct domain *d, struct pci_dev *pdev,
                               struct iommu_context *prev_ctx)
{
    int ret;
    const struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);

    if (!pdev || !drhd)
        return -EINVAL;

    ret = unapply_context_single(d, prev_ctx, drhd->iommu, pdev->bus, pdev->devfn);

    if ( ret )
        return ret;

    check_cleanup_domid_map(d, prev_ctx, NULL, drhd->iommu);

    return ret;
}

static int intel_iommu_reattach(struct domain *d, struct pci_dev *pdev,
                                struct iommu_context *prev_ctx,
                                struct iommu_context *ctx)
{
    int ret;
    const struct acpi_drhd_unit *drhd = acpi_find_matched_drhd_unit(pdev);

    if (!pdev || !drhd)
        return -EINVAL;

    ret = apply_context_single(d, ctx, drhd->iommu, pdev->bus, pdev->devfn);

    if ( ret )
        return ret;

    /* We are overwriting an entry, cleanup previous domid if needed. */
    check_cleanup_domid_map(d, prev_ctx, pdev, drhd->iommu);

    pci_vtd_quirk(pdev);

    return ret;
}

static const struct iommu_ops __initconst_cf_clobber vtd_ops = {
    .page_sizes = PAGE_SIZE_4K,
    .init = intel_iommu_domain_init,
    .hwdom_init = intel_iommu_hwdom_init,
    .context_init = intel_iommu_context_init,
    .context_teardown = intel_iommu_context_teardown,
    .attach = intel_iommu_attach,
    .dettach = intel_iommu_dettach,
    .reattach = intel_iommu_reattach,
    .enable_device = intel_iommu_enable_device,
    .teardown = iommu_domain_teardown,
    .clear_root_pgtable = iommu_clear_root_pgtable,
    .map_page = intel_iommu_map_page,
    .unmap_page = intel_iommu_unmap_page,
    .lookup_page = intel_iommu_lookup_page,
    .get_device_group_id = intel_iommu_group_id,
    .enable_x2apic = intel_iommu_enable_eim,
    .disable_x2apic = intel_iommu_disable_eim,
    .update_ire_from_apic = io_apic_write_remap_rte,
    .update_ire_from_msi = msi_msg_write_remap_rte,
    .read_apic_from_ire = io_apic_read_remap_rte,
    .setup_hpet_msi = intel_setup_hpet_msi,
    .adjust_irq_affinities = adjust_vtd_irq_affinities,
    .suspend = vtd_suspend,
    .resume = vtd_resume,
    .crash_shutdown = vtd_crash_shutdown,
    .iotlb_flush = iommu_flush_iotlb,
    .get_reserved_device_memory = intel_iommu_get_reserved_device_memory,
    .dump_page_tables = vtd_dump_page_tables,
};

const struct iommu_init_ops __initconstrel intel_iommu_init_ops = {
    .ops = &vtd_ops,
    .setup = vtd_setup,
    .supports_x2apic = intel_iommu_supports_eim,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
