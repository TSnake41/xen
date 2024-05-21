/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Simple arena-based page allocator.
 */

#ifndef __XEN_IOMMU_ARENA_H__
#define __XEN_IOMMU_ARENA_H__

#include "xen/domain.h"
#include "xen/atomic.h"
#include "xen/mm-frame.h"
#include "xen/types.h"

#define IOMMU_ARENA_PAGE_ORDER 9
#define IOMMU_ARENA_PAGE_COUNT (1ULL << IOMMU_ARENA_PAGE_ORDER)

/**
 * struct page_arena: Page arena structure
 */
struct iommu_arena {
    /* mfn of the first page of the memory region */
    mfn_t region_start;
    /* bitmap of allocations */
    DECLARE_BITMAP(map, IOMMU_ARENA_PAGE_COUNT);

    /* Used page count */
    atomic_t used_pages;
};

/**
 * Initialize a arena using domheap allocator.
 * @param [out] arena Arena to allocate
 * @param [in] domain domain that has ownership of arena pages
 * @param [in] memflags Flags for domheap_alloc_pages()
 * @return -ENOMEM on arena allocation error, 0 otherwise
 */
int iommu_arena_initialize(struct iommu_arena *arena, struct domain *domain,
                           unsigned int memflags);

/**
 * Teardown a arena.
 * @param [out] arena arena to allocate
 * @param [in] check check for existing allocations
 * @return -EBUSY if check is specified
 */
int iommu_arena_teardown(struct iommu_arena *arena, bool check);

struct page_info *iommu_arena_allocate_page(struct iommu_arena *arena);
bool iommu_arena_free_page(struct iommu_arena *arena, struct page_info *page);

#endif
