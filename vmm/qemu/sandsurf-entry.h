/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SANDSURF_QEMU_ENTRY_H
#define SANDSURF_QEMU_ENTRY_H
#include <stdint.h>
int sandsurf_qemu_enter(int argc, char ***argv);
uint32_t sandsurf_qemu_cpu_cap(void);
#ifdef _WIN32
void *sandsurf_qemu_disk(const char *role);
#endif
#endif
