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

#include <asm/pgtable.h>

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

static inline pgd_t *bpf_pgd_offset(struct mm_struct *mm, u64 virt)
{
    u64 shift;
    bpf_probe_read(&shift, sizeof(pgdir_shift), &pgdir_shift);

    pgd_t *pgd =  mm->pgd + (((virt) >> shift) & (PTRS_PER_PGD - 1));

    return pgd;
}

static inline p4d_t *bpf_p4d_offset(pgd_t *pgd, u64 virt)
{
    u64 shift = P4D_SHIFT;
    u64 ptrs;
    bpf_probe_read(&ptrs, sizeof(ptrs_per_p4d), &ptrs_per_p4d);

    p4d_t *p4d = (p4d_t *)pgd + (((virt) >> shift) & (ptrs - 1));

    return p4d;
}

static inline pud_t *bpf_pud_offset(p4d_t *p4d, u64 virt)
{
    u64 shift = PUD_SHIFT;

    pud_t *pud = (pud_t *)p4d + (((virt) >> shift) & (PTRS_PER_PUD - 1));

    return pud;
}

static inline pmd_t *bpf_pmd_offset(pud_t *pud, u64 virt)
{
    u64 shift = PUD_SHIFT;

    pmd_t *pmd = (pmd_t *)pud + (((virt) >> shift) & (PTRS_PER_PMD - 1));

    return pmd;
}

static inline pte_t *bpf_pte_offset(pmd_t *pmd, u64 virt)
{
    u64 shift = PAGE_SHIFT;

    pte_t *pte = (pte_t *)pmd + (((virt) >> shift) & (PTRS_PER_PTE - 1));

    return pte;
}

static u64 page_walk(u64 virt)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (!task)
    {
        return 0;
    }

    struct mm_struct *mm = task->mm;

    if (!mm)
    {
        return 0;
    }

    pgd_t *pgd = bpf_pgd_offset(mm, virt);
    if (!pgd)
        return 0;
    p4d_t *p4d = bpf_p4d_offset(pgd, virt);
    if (!p4d)
        return 0;
    pud_t *pud = bpf_pud_offset(p4d, virt);
    if (!pud)
        return 0;
    pmd_t *pmd = bpf_pmd_offset(pud, virt);
    if (!pmd)
        return 0;
    pte_t *ptep = bpf_pte_offset(pmd, virt);
    if (!ptep)
        return 0;
    pte_t pte = *ptep;

#ifdef HEAPSNOOP_DEBUG
    bpf_trace_printk("pgd  %lx\n", pgd);
    bpf_trace_printk("p4d  %lx\n", p4d);
    bpf_trace_printk("pud  %lx\n", pud);
    bpf_trace_printk("pmd  %lx\n", pmd);
    bpf_trace_printk("ptep %lx\n", ptep);
    bpf_trace_printk("pte  %lx\n", pte);
#endif

    /* Take pteval from pte */
    u64 pfn = pte.pte;
    /* Check if it needs to be inverted... */
    u64 xor = pfn && !(pfn & _PAGE_PRESENT) ? ~0ull : 0;
    /* And if so, invert it. */
    pfn ^= xor;
    pfn = (pfn) >> PAGE_SHIFT;
    u64 phys = (pfn << PAGE_SHIFT) + (virt % PAGE_SIZE);

    return phys;
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
    allocation.phys = page_walk(virt);
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
