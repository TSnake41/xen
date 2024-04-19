/* SPDX-License-Identifier: MIT */
/******************************************************************************
 * pv-iommu.h
 *
 * Paravirtualized IOMMU driver interface.
 *
 * Copyright (c) 2024 Teddy Astie <teddy.astie@vates.tech>
 */

#ifndef __XEN_PUBLIC_PV_IOMMU_H__
#define __XEN_PUBLIC_PV_IOMMU_H__

#include "xen.h"
#include "physdev.h"

#define IOMMU_DEFAULT_CONTEXT (0)

/**
 * Query PV-IOMMU capabilities for this domain.
 */
#define IOMMUOP_query_capabilities    1

/**
 * Allocate an IOMMU context, the new context handle will be written to ctx_no.
 */
#define IOMMUOP_alloc_context         2

/**
 * Destroy a IOMMU context.
 * All devices attached to this context are reattached to default context.
 *
 * The default context can't be destroyed (0).
 */
#define IOMMUOP_free_context          3

/**
 * Reattach the device to IOMMU context.
 */
#define IOMMUOP_reattach_device       4

#define IOMMUOP_map_pages             5
#define IOMMUOP_unmap_pages           6

/**
 * Get the GFN associated to a specific DFN.
 */
#define IOMMUOP_lookup_page           7

struct pv_iommu_op {
    uint16_t subop_id;
    uint16_t ctx_no;

/**
 * Create a context that is cloned from default.
 * The new context will be populated with 1:1 mappings covering the entire guest memory.
 */
#define IOMMU_CREATE_clone (1 << 0)

#define IOMMU_OP_readable (1 << 0)
#define IOMMU_OP_writeable (1 << 1)
    uint32_t flags;

    union {
        struct {
            uint64_t gfn;
            uint64_t dfn;
            /* Number of pages to map */
            uint32_t nr_pages;
            /* Number of pages actually mapped after sub-op */
            uint32_t mapped;
        } map_pages;

        struct {
            uint64_t dfn;
            /* Number of pages to unmap */
            uint32_t nr_pages;
            /* Number of pages actually unmapped after sub-op */
            uint32_t unmapped;
        } unmap_pages;

        struct {
            struct physdev_pci_device dev;
        } reattach_device;

        struct {
            uint64_t gfn;
            uint64_t dfn;
        } lookup_page;

        struct {
            /* Maximum number of IOMMU context this domain can use. */
            uint16_t max_ctx_no;
            /* Maximum number of pages that can be modified in a single map/unmap operation. */
            uint32_t max_nr_pages;
            /* Maximum device address (iova) that the guest can use for mappings. */
            uint64_t max_iova_addr;
        } cap;
    };
};

typedef struct pv_iommu_op pv_iommu_op_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_op_t);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */