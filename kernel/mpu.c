/*
 * Embedded Operating Systems and Architecture course
 * Licensed under the MIT License. See LICENSE in the repository root.
 *
 * Contact: Stefano Di Carlo <stefano.dicarlo@polito.it>
 *
 * MPU set-up: see kernel/mpu.h.
 *
 * Region 0 lets tasks read and run FLASH (code and constants).
 * Region 1 lets a task read and write its own partition, nothing else.
 * Any other access by a task raises a MemManage fault.
 */

#include <stdint.h>
#include "cmsdk.h"
#include "kernel/mpu.h"

void mpu_init( void )
{
    /* Region 0 = FLASH, from address 0, 4 MB = 2^22 bytes.
     * Read-only for everyone, and code may run from it (no XN). */
    MPU->RBAR = 0x00000000 | MPU_RBAR_VALID | 0;       /* = 0x00000010 */
    MPU->RASR = MPU_RASR_AP( MPU_AP_RO ) | MPU_RASR_C
              | MPU_RASR_SIZE( 22 ) | MPU_RASR_ENABLE; /* = 0x0602002B */

    /* Switch the MPU on. PRIVDEFENA: the kernel (privileged) keeps the
     * normal memory map, so only tasks are restricted. */
    MPU->CTRL = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA;  /* = 5 */
    __asm volatile ( "dsb" ::: "memory" );  /* finish the writes ... */
    __asm volatile ( "isb" ::: "memory" );  /* ... before the next instruction */
}

void mpu_set_task_region( uint32_t base, uint32_t size, int executable,
                          uint32_t code_size )
{
    uint32_t log2_size = __builtin_ctz( size );

    /* Region 1: the full task partition, read-write and normally XN. */
    MPU->RBAR = base | MPU_RBAR_VALID | 1;
    MPU->RASR = ( executable ? 0u : MPU_RASR_XN )
              | MPU_RASR_AP( MPU_AP_FULL_RW )
              | MPU_RASR_S | MPU_RASR_C
              | MPU_RASR_SIZE( log2_size ) | MPU_RASR_ENABLE;

    /* Region 2: overlay program code as read-only and executable.
     * Each subregion of a 4 KB slot is 512 bytes. */
    if ( size == 4096u && ( base & ( size - 1u ) ) == 0u
         && code_size >= 512u && code_size <= 3072u
         && ( code_size & 511u ) == 0u ) {
        uint32_t subregions = code_size / 512u;
        uint32_t disable_mask = 0xffu & ~(( 1u << subregions ) - 1u);

        MPU->RBAR = base | MPU_RBAR_VALID | 2;
        MPU->RASR = MPU_RASR_AP( MPU_AP_RO )
                  | MPU_RASR_S | MPU_RASR_C
                  | MPU_RASR_SIZE( 12 ) | MPU_RASR_ENABLE
                  | ( disable_mask << 8 );
    } else {
        /* Clear any old code overlay when switching to a normal task. */
        MPU->RBAR = MPU_RBAR_VALID | 2;
        MPU->RASR = 0;
    }

    __asm volatile ( "dsb" ::: "memory" );
    __asm volatile ( "isb" ::: "memory" );
}
