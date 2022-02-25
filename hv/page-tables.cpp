#include "page-tables.h"
#include "vcpu.h"
#include "hv.h"
#include "mm.h"

namespace hv {

// map the first 128GB of physical memory into the specified PML4E
static void map_physical_memory(host_page_tables& pt) {
  auto& pml4e = pt.pml4[host_physical_memory_pml4_idx];
  pml4e.flags                    = 0;
  pml4e.present                  = 1;
  pml4e.write                    = 1;
  pml4e.supervisor               = 0;
  pml4e.page_level_write_through = 0;
  pml4e.page_level_cache_disable = 0;
  pml4e.accessed                 = 0;
  pml4e.execute_disable          = 0;
  pml4e.page_frame_number = get_physical(&pt.phys_pdpt) >> 12;

  // TODO: add support for 1GB pages
  // TODO: check if 2MB pages are supported (pretty much always are)

  for (uint64_t i = 0; i < 128; ++i) {
    auto& pdpte = pt.phys_pdpt[i];
    pdpte.flags                    = 0;
    pdpte.present                  = 1;
    pdpte.write                    = 1;
    pdpte.supervisor               = 0;
    pdpte.page_level_write_through = 0;
    pdpte.page_level_cache_disable = 0;
    pdpte.accessed                 = 0;
    pdpte.execute_disable          = 0;
    pdpte.page_frame_number = get_physical(pt.phys_pds[i]) >> 12;

    for (uint64_t j = 0; j < 512; ++j) {
      auto& pde = pt.phys_pds[i][j];
      pde.flags                    = 0;
      pde.present                  = 1;
      pde.write                    = 1;
      pde.supervisor               = 0;
      pde.page_level_write_through = 0;
      pde.page_level_cache_disable = 0;
      pde.accessed                 = 0;
      pde.dirty                    = 0;
      pde.large_page               = 1;
      pde.global                   = 0;
      pde.pat                      = 0;
      pde.execute_disable          = 0;
      pde.page_frame_number = (i << 9) + j;
    }
  }
}

// initialize the host page tables
void prepare_host_page_tables() {
  auto& pt = ghv.host_page_tables;
  memset(&pt, 0, sizeof(pt));

  // TODO: perform a deep copy instead of a shallow copy (for the memory
  //   ranges that our hypervisor code resides in)

  auto const system_pml4 = static_cast<pml4e_64*>(get_virtual(
    ghv.system_cr3.address_of_page_directory << 12));

  // copy the top half of the System pml4 (a.k.a. the kernel address space)
  memcpy(&pt.pml4[256], &system_pml4[256], sizeof(pml4e_64) * 256);

  // map all of physical memory into our address space
  map_physical_memory(pt);
}

} // namespace hv
