// Required header
#include "../gdb_stub/dbg.h"
#include "../prosper0gdb/offsets.h"
#include "../prosper0gdb/r0gdb.h"
#include "symbols.h"
#include "loging.h"
#include "probe/probe.h"
#include "probe/instr_db.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

enum Errors {
  ERR_LOG_SOCK = 1,
  ERR_LOG_CONNECT,
  ERR_PMAP_OFFSET_GUESS,
  ERR_DUMPER_BUF_MALLOC,
  ERR_DUMPER_SOCK,
  ERR_DUMPER_SETSOCKOPT,
  ERR_DUMPER_BIND,
  ERR_DUMPER_LISTEN,
  ERR_DUMPER_CMD_READ,
  ERR_DUMP_COPYOUT,
  ERR_DUMP_WRITE,
  ERR_PADDR_NEGATIVE,
  ERR_VADDR_NOT_PRESENT,
  ERR_VADDR_NO_LEAF,
};

struct flat_pmap {
  uint64_t mtx_name_ptr;
  uint64_t mtx_flags;
  uint64_t mtx_data;
  uint64_t mtx_lock;
  uint64_t pm_pml4;
  uint64_t pm_cr3;
};

struct page_level {
  int from;
  int to;
  size_t size;
  int sign_ext;
  int leaf;
};

const struct page_level LEVELS[] = {
    {.from = 39, .to = 47, .size = 1ULL << 39, .sign_ext = 1, .leaf = 0},
    {.from = 30, .to = 38, .size = 1ULL << 30, .sign_ext = 0, .leaf = 0},
    {.from = 21, .to = 29, .size = 1ULL << 21, .sign_ext = 0, .leaf = 0},
    {.from = 12, .to = 20, .size = 1ULL << 12, .sign_ext = 0, .leaf = 1},
};

enum pde_shift {
  PDE_PRESENT = 0,
  PDE_RW,
  PDE_USER,
  PDE_WRITE_THROUGH,
  PDE_CACHE_DISABLE,
  PDE_ACCESSED,
  PDE_DIRTY,
  PDE_PS,
  PDE_GLOBAL,
  PDE_AVL9,
  PDE_AVL10,
  PDE_AVL11,
  PDE_AVL52 = 52,
  PDE_AVL53,
  PDE_AVL54,
  PDE_AVL55,
  PDE_AVL56,
  PDE_AVL57,
  PDE_AVL58,
  PDE_PROTECTION_KEY = 59,
  PDE_EXECUTE_DISABLE = 63
};

const size_t PDE_PRESENT_MASK = 1;
const size_t PDE_RW_MASK = 1;
const size_t PDE_USER_MASK = 1;
const size_t PDE_WRITE_THROUGH_MASK = 1;
const size_t PDE_CACHE_DISABLE_MASK = 1;
const size_t PDE_ACCESSED_MASK = 1;
const size_t PDE_DIRTY_MASK = 1;
const size_t PDE_PS_MASK = 1;
const size_t PDE_GLOBAL_MASK = 1;
const size_t PDE_AVL9_MASK = 1;
const size_t PDE_AVL10_MASK = 1;
const size_t PDE_AVL11_MASK = 1;
const size_t PDE_AVL52_MASK = 1;
const size_t PDE_AVL53_MASK = 1;
const size_t PDE_AVL54_MASK = 1;
const size_t PDE_AVL55_MASK = 1;
const size_t PDE_AVL56_MASK = 1;
const size_t PDE_AVL57_MASK = 1;
const size_t PDE_AVL58_MASK = 1;
const size_t PDE_PROTECTION_KEY_MASK = 0xF;
const size_t PDE_EXECUTE_DISABLE_MASK = 1;

#define PDE_FIELD(pde, name) (((pde) >> PDE_##name) & PDE_##name##_MASK)

const size_t PDE_ADDR_MASK = 0xffffffffff800ULL;  // bits [12, 51]

#define PADDR_TO_DMAP(paddr) ((paddr) + dmap_base)

static struct flat_pmap kernel_pmap_store;
static size_t dmap_base;

ssize_t vaddr_to_paddr(size_t vaddr, size_t cr3) {
  ssize_t paddr = cr3;
  uint64_t pd[512];
  const struct page_level *level;

  for (size_t level_idx = 0; level_idx < 4; ++level_idx) {
    level = LEVELS + level_idx;
    if (paddr < 0) {
      // something is wrong
      return -ERR_PADDR_NEGATIVE;
    }
    copyout(&pd, PADDR_TO_DMAP(paddr), sizeof(pd));
    int idx_bits = (level->to - level->from) + 1;
    size_t idx_mask = (1ULL << idx_bits) - 1ULL;
    size_t idx = (vaddr >> level->from) & idx_mask;

    uint64_t pde = pd[idx];
    paddr = pde & PDE_ADDR_MASK;
    size_t leaf = level->leaf || PDE_FIELD(pde, PS);

    if (!PDE_FIELD(pde, PRESENT)) {
      // something is wrong
      return -ERR_VADDR_NOT_PRESENT;
    }

    if (leaf) {
      return paddr | (vaddr & (level->size - 1));
    }
  }
  return -ERR_VADDR_NO_LEAF;
}

extern uintptr_t kdata_base;

void init_pmap() {
  copyout(&kernel_pmap_store, offsets.kernel_pmap_store,
          sizeof(kernel_pmap_store));
  dmap_base = kernel_pmap_store.pm_pml4 - kernel_pmap_store.pm_cr3;
  printf("pm_pml4 0x%zx, pm_cr3 0x%zx, dmap_base 0x%p\n",
         kernel_pmap_store.pm_pml4, kernel_pmap_store.pm_cr3, dmap_base);
}