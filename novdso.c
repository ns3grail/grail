// This file should be compiled into a library used with LD_PRELOAD.
// It disables VDSO-Usage of glibc (tested with glibc-2.23).
// Manual building:
//   gcc -shared -o libnovdso.so novdso.c
//
// Note that if the vDSO usage is extended to more system calls in the
// future, this library needs updating. For this reason, we advise to
// simply disable vDSO system wide and only use this library if you do
// not have sufficient privilegs on the simulation host system.

#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
  return syscall(SYS_gettimeofday, tv, tz);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
  return syscall(SYS_clock_gettime, clk_id, tp);
}

time_t time(time_t *tloc)
{
  return syscall(SYS_time, tloc);
}

struct getcpu_cache;
int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
{
  return syscall(SYS_getcpu, cpu, node, tcache);
}
