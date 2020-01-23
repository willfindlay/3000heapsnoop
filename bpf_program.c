/* 3000heapsnoop: Snooping virtual to physical mapping of heap allocations in userspace
   Copyright (C) 2020  William Findlay

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.

   The BPF program used here is based on memleak.py from bcc tools:
   https://github.com/iovisor/bcc/blob/master/tools/memleak.py */

#include "bpf_program.h"

BPF_PERCPU_ARRAY(intermediate, u64, 1);
BPF_PERF_OUTPUT(allocation_events);

/* Helpers below this line --------------------------------------------- */

static inline u32 bpf_strlen(char *s)
{
    u32 i;
    for (i = 0; s[i] != '\0' && i < (1 << (32 - 1)); i++);
    return i;
}

static inline int bpf_strncmp(char *s1, char *s2, u32 n)
{
    int mismatch = 0;
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

static inline int bpf_strcmp(char *s1, char *s2)
{
    u32 s1_size = sizeof(s1);
    u32 s2_size = sizeof(s2);

    return bpf_strncmp(s1, s2, s1_size < s2_size ? s1_size : s2_size);
}

/* Keep userland pid and ignore tid */
static u32 heapsnoop_get_pid()
{
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

/* Return 1 if the filter is OK, 0 otherwise */
static int filter()
{
#ifdef HEAPSNOOP_PID
    return (heapsnoop_get_pid() == HEAPSNOOP_PID);
#elif defined(HEAPSNOOP_COMM)
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    return !(bpf_strncmp(comm, HEAPSNOOP_COMM, TASK_COMM_LEN));
#else
    return 1;
#endif
}

/* uprobes and uretprobes below this line ------------------------------ */

static int alloc_enter(struct pt_regs *ctx, size_t s)
{
    int zero = 0;
    u64 size = (u64)s;
    intermediate.update(&zero, &size);

    return 0;
}

static int alloc_exit(struct pt_regs *ctx, u64 virt)
{
    int zero = 0;
    u32 pid = heapsnoop_get_pid();

    u64 *size = intermediate.lookup(&zero);
    if (!size)
    {
        return -1;
    }

    /* Look up the allocation from intermediate array */
    struct allocation allocation = {};
    allocation.pid = pid;
    allocation.virt = virt;
    allocation.size = *size;
    bpf_get_current_comm(&allocation.comm, sizeof(allocation.comm));

    allocation_events.perf_submit(ctx, &allocation, sizeof(allocation));

    /* Clean up intermediate array */
    intermediate.delete(&zero);

    return 0;
}

/* Entry point for malloc calls in C programs */
int malloc_enter(struct pt_regs *ctx, size_t s)
{
    if (!filter())
        return 0;

    return alloc_enter(ctx, s);
}

/* Exit point for malloc calls in C programs */
int malloc_exit(struct pt_regs *ctx)
{
    if (!filter())
        return 0;

    return alloc_exit(ctx, (u64)PT_REGS_RC(ctx));
}

/* Entry point for calloc calls in C programs */
int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t s)
{
    if (!filter())
        return 0;

    return alloc_enter(ctx, s * nmemb);
}

/* Exit point for calloc calls in C programs */
int calloc_exit(struct pt_regs *ctx)
{
    if (!filter())
        return 0;

    return alloc_exit(ctx, (u64)PT_REGS_RC(ctx));
}
