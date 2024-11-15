#ifndef __XEN_PUBLIC_HVM_COCO_H__
#define __XEN_PUBLIC_HVM_COCO_H__

#include "../xen.h"

/* Map to the sev_dom_coco_op */
struct sev_launch_update_data {
    unsigned int cmd;
    domid_t domid;
    uint64_t address;
    uint64_t len;
};
typedef struct sev_launch_update_data sev_launch_update_data_t;
DEFINE_XEN_GUEST_HANDLE(sev_launch_update_data_t);

extern long do_dom_coco_op(unsigned int cmd, domid_t domid, uint64_t arg1, uint64_t arg2);

#endif /* __XEN_PUBLIC_HVM_COCO_H__ */
