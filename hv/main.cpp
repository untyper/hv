#include "hv.h"

#include <ntddk.h>
#include <ia32.hpp>

// kernel mode hv interface
namespace hvk {

namespace message_clients {
  // driver should always be client number 0.
  // this should always be taken into account by usermode clients,
  // when expanding the namespace.
  inline constexpr uint64_t driver = 0;
}

namespace messages {
  enum : uint64_t {
    loaded,
    failed_loading,
    unloading,
  };
}

namespace message_types {
  enum : uint64_t {
    load_state
  };
}

// get time in milliseconds based on boot-time tick frequency
inline uint64_t get_current_time() {
  LARGE_INTEGER frequency;
  LARGE_INTEGER time;

  time = KeQueryPerformanceCounter(&frequency);
  time.QuadPart *= 1000; // milliseconds
  time.QuadPart /= frequency.QuadPart;
  return time.QuadPart;
}

inline void send_message(uint64_t message, uint64_t type) {
  hv::hypercall_input input;
  input.code = hv::hypercall_send_message;
  input.key  = hv::hypercall_key;
  input.args[0] = message;
  input.args[1] = type;
  input.args[2] = get_current_time();
  input.args[3] = hvk::message_clients::driver;
  hv::vmx_vmcall(input);
}

inline uint64_t get_message() {
  hv::hypercall_input input;
  input.code = hv::hypercall_get_message;
  input.key  = hv::hypercall_key;
  return hv::vmx_vmcall(input);
}

inline uint64_t get_message_time() {
  hv::hypercall_input input;
  input.code = hv::hypercall_get_message_time;
  input.key  = hv::hypercall_key;
  return hv::vmx_vmcall(input);
}

inline NTSTATUS sleep_for(LONGLONG milliseconds) {
  LARGE_INTEGER delay;
  ULONG *split;

  milliseconds *= 1000000;
  milliseconds /= 100;
  milliseconds = -milliseconds;

  split = (ULONG*)&milliseconds;
  delay.LowPart = *split;
  split++;
  delay.HighPart = *split;

  KeDelayExecutionThread(KernelMode, 0, &delay);
  return STATUS_SUCCESS;
}

inline uint64_t wait_for_message(uint64_t timeout) {
  uint64_t timeout_start       = get_current_time();
  uint64_t cached_message_time = get_message_time();

  while (get_current_time() - timeout_start < timeout) {
    uint64_t message_time = get_message_time();

    if (message_time > cached_message_time)  {
      // new message available
      return get_message();
    }
    cached_message_time = message_time;
    sleep_for(10);
  }
  return 0;
}

// simple hypercall wrappers
inline uint64_t ping() {
  hv::hypercall_input input;
  input.code = hv::hypercall_ping;
  input.key  = hv::hypercall_key;
  return hv::vmx_vmcall(input);
}
} // namespace hv

void driver_unload(PDRIVER_OBJECT) {
  hv::stop();

  DbgPrint("[hv] Devirtualized the system.\n");
  DbgPrint("[hv] Driver unloaded.\n");
}

NTSTATUS driver_entry(PDRIVER_OBJECT const driver, PUNICODE_STRING) {
  DbgPrint("[hv] Driver loaded.\n");

  if (driver)
    driver->DriverUnload = driver_unload;

  if (!hv::start()) {
    DbgPrint("[hv] Failed to virtualize system.\n");
    return STATUS_HV_OPERATION_FAILED;
  }

  if (hvk::ping() == hv::hypervisor_signature)
    DbgPrint("[client] Hypervisor signature matches.\n");
  else
    DbgPrint("[client] Failed to ping hypervisor!\n");

  // tell usermode client that driver has been loaded successfully
  hvk::send_message(hvk::messages::loaded, hvk::message_types::load_state);

  return STATUS_SUCCESS;
}
