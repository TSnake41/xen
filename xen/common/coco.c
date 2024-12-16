/******************************************************************************
 * coco.c
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <asm/p2m.h>

long
do_dom_coco_op(unsigned int cmd, domid_t domid, uint64_t arg1, uint64_t arg2)
{
#ifdef CONFIG_X86
    return arch_dom_coco_op(cmd, domid, arg1, arg2);
#else
    return -ENOSYS;
#endif
}

long
do_sev_hox_demo_op(uint64_t addr, uint64_t size)
{
    mfn_t mfn;
    gfn_t gfn;
    struct page_info *page;
    p2m_type_t p2mt;

    void* va;
    uint8_t* start;

    uint8_t offset = addr & ~ PAGE_MASK;

    if ( (offset + size) > PAGE_SIZE )
    {
	printk("%s: the secret crosses page boundary\n", __FUNCTION__);
	return -EINVAL;
    }

    gfn = gaddr_to_gfn(addr);

    page = get_page_from_gfn(current->domain, gfn_x(gfn), &p2mt, P2M_UNSHARE);
    if (!page)
    {
	printk("%s: can't get page for 0x%lx gfn\n", __FUNCTION__, gfn);
    }

    mfn = page_to_mfn(page);

    va = map_domain_page(mfn);
    if ( !va )
    {
	printk("%s: can't map domain address\n", __FUNCTION__);
    }

    printk("ACCESS GUEST SECRET\n");

    for ( start = va + offset; size; start++, size-- )
    {
	printk("Ox%x ", *start);
    }

    printk("\nDONE GUEST SECRET\n");

    unmap_domain_page(va);

    return 0;
}
