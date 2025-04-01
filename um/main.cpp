#include <iostream>

#include "hv.h"
#include "dumper.h"

void hide_hypervisor() {
  auto const hv_base = static_cast<uint8_t*>(hv::get_hv_base());
  auto const hv_size = 0x64000;

  // hide the hypervisor
  hv::for_each_cpu([&](uint32_t) {
    for (size_t i = 0; i < hv_size; i += 0x1000) {
      auto const virt = hv_base + i;
      auto const phys = hv::get_physical_address(0, virt);

      if (!phys) {
        printf("failed to get physical address for 0x%p.\n", virt);
        continue;
      }

      if (!hv::hide_physical_page(phys >> 12))
        printf("failed to hide page: 0x%p.\n", virt);
    }
  });
}

int main() {
  if (!hv::is_hv_running()) {
    printf("HV not running.\n");
    return 0;
  }

  hide_hypervisor();
  printf("Pinged the hypervisor! Flushing logs...\n");

  if (hv::get_message() != hv::driver_messages::loaded)
    if (hv::wait_for_message(4096) == hv::driver_messages::loaded)

  printf("Driver loaded!\n");

  hv::for_each_cpu([](uint32_t) {
    hv::remove_all_mmrs();
  });
}