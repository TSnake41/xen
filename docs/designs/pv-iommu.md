# IOMMU paravirtualization for Dom0

Status: Experimental

# Background

By default, Xen only uses the IOMMU for itself, either to make device adress
space coherent with guest adress space (x86 HVM/PVH) or to prevent devices
from doing DMA outside it's expected memory regions including the hypervisor
(x86 PV).

A limitation is that guests (especially privildged ones) may want to use
IOMMU hardware in order to implement features such as DMA protection and
VFIO [1] as IOMMU functionality is not available outside of the hypervisor
currently.

[1] VFIO - "Virtual Function I/O" - https://www.kernel.org/doc/html/latest/driver-api/vfio.html

# Design

The operating system may want to have access to various IOMMU features such as
context management and DMA remapping. We can create a new hypercall that allows
the guest to have access to a new paravirtualized IOMMU interface.

This feature is only meant to be available for the Dom0, as DomU have some
emulated devices that can't be managed on Xen side and are not hardware, we
can't rely on the hardware IOMMU to enforce DMA remapping.

This interface is exposed under the `iommu_op` hypercall.

In addition, Xen domains are modified in order to allow existence of several
IOMMU context including a default one that implement default behavior (e.g
hardware assisted paging) and can't be modified by guest. DomU cannot have
contexts, and therefore act as if they only have the default domain.

Each IOMMU context within a Xen domain is identified using a domain-specific
context number that is used in the Xen IOMMU subsystem and the hypercall
interface.

The number of IOMMU context a domain can use is predetermined at domain creation
and is configurable through `dom0-iommu=nb-ctx=N` xen cmdline.

# IOMMU operations

## Alloc context

Create a new IOMMU context for the guest and return the context number to the
guest.
Fail if the IOMMU context limit of the guest is reached.

A flag can be specified to create a identity mapping.

## Free context

Destroy a IOMMU context created previously.
It is not possible to free the default context.

Reattach context devices to default context if specified by the guest.

Fail if there is a device in the context and reattach-to-default flag is not
specified.

## Reattach device

Reattach a device to another IOMMU context (including the default one).
The target IOMMU context number must be valid and the context allocated.

The guest needs to specify a PCI SBDF of a device he has access to.

## Map/unmap page

Map/unmap a page on a context.
The guest needs to specify a gfn and target dfn to map.

Refuse to create the mapping if one already exist for the same dfn.

## Lookup page

Get the gfn mapped by a specific dfn.

# Implementation considerations

## Hypercall batching

In order to prevent unneeded hypercalls and IOMMU flushing, it is advisable to
be able to batch some critical IOMMU operations (e.g map/unmap multiple pages).

## Hardware without IOMMU support

Operating system needs to be aware on PV-IOMMU capability, and whether it is
able to make contexts. However, some operating system may critically fail in
case they are able to make a new IOMMU context. Which is supposed to happen
if no IOMMU hardware is available.

The hypercall interface needs a interface to advertise the ability to create
and manage IOMMU contexts including the amount of context the guest is able
to use. Using these informations, the Dom0 may decide whether to use or not
the PV-IOMMU interface.

## Page pool for contexts

In order to prevent unexpected starving on the hypervisor memory with a
buggy Dom0. We can preallocate the pages the contexts will use and make
map/unmap use these pages instead of allocating them dynamically.

