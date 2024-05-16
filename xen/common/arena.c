/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Simple arena-based page allocator.
 *
 * Allocate a large block using alloc_domheam_pages and allocate single pages
 * using arena_allocate_page and arena_free_page functions.
 *
 * Concurrent {allocate/free}_page is thread-safe
 * arena_teardown during {allocate/free}_page is not thread-safe.
 *
 * Written by Teddy Astie <teddy.astie@vates.tech>
 */

#include "xen/compiler.h"
#include <asm/bitops.h>
#include <asm/page.h>
#include <xen/atomic.h>
#include <xen/bug.h>
#include <xen/config.h>
#include <xen/mm-frame.h>
#include <xen/mm.h>
#include <xen/arena.h>

/* Maximum of scan tries if the bit found not available */
#define ARENA_TSL_MAX_TRIES 5

int arena_initialize(struct page_arena *arena, struct domain *d, unsigned int memflags)
{
    struct page_info *page;

    /* TODO: Maybe allocate differently ? */
    page = alloc_domheap_pages(d, ARENA_PAGE_ORDER, memflags);

    if ( !page )
        return -ENOMEM;

    arena->region_start = page_to_mfn(page);
    _atomic_set(&arena->used_pages, 0);
    bitmap_zero(arena->map, ARENA_PAGE_COUNT);

    printk(XENLOG_DEBUG "ARENA: Allocated arena (%llu pages, start=%"PRI_mfn")\n",
           ARENA_PAGE_COUNT, mfn_x(arena->region_start));
    return 0;
}

int arena_teardown(struct page_arena *arena, bool check)
{
    BUG_ON(mfn_x(arena->region_start) == 0);

    /* Check for allocations if check is specified */
    if ( check && (atomic_read(&arena->used_pages) > 0) )
        return -EBUSY;

    free_domheap_pages(mfn_to_page(arena->region_start), ARENA_PAGE_ORDER);

    arena->region_start = _mfn(0);
    _atomic_set(&arena->used_pages, 0);
    bitmap_fill(arena->map, ARENA_PAGE_COUNT);

    return 0;
}

mfn_t arena_allocate_page(struct page_arena *arena)
{
    unsigned int index;
    unsigned int tsl_tries = 0;

    BUG_ON(mfn_x(arena->region_start) == 0);

    if ( atomic_read(&arena->used_pages) == ARENA_PAGE_COUNT )
        /* All pages used */
        return INVALID_MFN;

    do
    {
        index = find_first_zero_bit(arena->map, ARENA_PAGE_COUNT);

        if ( index >= ARENA_PAGE_COUNT )
            /* No more free pages */
            return INVALID_MFN;

        /*
         * While there shouldn't be a lot of retries in practice, this loop
         * *may* run indefinetly if the found bit is never free due to being
         * overwriten by another CPU core right after. Add a safeguard for
         * such very rare cases.
         */
        tsl_tries++;

        if ( unlikely(tsl_tries == ARENA_TSL_MAX_TRIES) )
        {
            printk(XENLOG_ERR "ARENA: Too many TSL retries !");
            return INVALID_MFN;
        }

        /* Make sure that the bit we found is still free */
    } while ( test_and_set_bit(index, arena->map) );

    atomic_inc(&arena->used_pages);

    return mfn_add(arena->region_start, index);
}

bool arena_free_page(struct page_arena *arena, mfn_t page)
{
    unsigned long index;

    /* Check if page belongs to our arena */
    if ( (mfn_x(page) < mfn_x(arena->region_start))
        || (mfn_x(page) >= (mfn_x(arena->region_start) + ARENA_PAGE_COUNT)) )
    {
        printk(XENLOG_WARNING
               "ARENA: Trying to free outside arena region [mfn=%"PRI_mfn"]",
               mfn_x(page));
        WARN();
        return false;
    }

    index = mfn_x(page) - mfn_x(arena->region_start);

    /* Sanity check in case of underflow. */
    ASSERT(index < ARENA_PAGE_COUNT);

    if ( !test_and_clear_bit(index, arena->map) )
    {
        /* Bit was free during our arena_free_page, which means that
           either this page was never allocated, or we are in a double-free
           situation. */
        printk(XENLOG_WARNING
               "ARENA: Freeing non-allocated region (double-free?) [mfn=%"PRI_mfn"]",
               mfn_x(page));
        WARN();
        return false;
    }

    atomic_dec(&arena->used_pages);

    return true;
}