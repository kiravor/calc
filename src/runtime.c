#include "gost.h"

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal stop flag must be lock-free");
_Atomic sig_atomic_t stopping;
struct config config = {.timeout_ms = 60000, .connect_timeout_ms = 10000, .max_clients = 256};
