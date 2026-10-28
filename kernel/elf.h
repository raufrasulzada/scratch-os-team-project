#ifndef ELF_H
#define ELF_H

#include <stdint.h>

/* ELF32 standard record sizes. */
#define ELF_HEADER_SIZE 52u
#define ELF_PROGRAM_HEADER_SIZE 32u
#define ELF_SECTION_HEADER_SIZE 40u
#define ELF_SYMBOL_SIZE 16u
#define ELF_REL_SIZE 8u

#define ELF_PT_LOAD 1u

#define ELF_PF_X 1u
#define ELF_PF_W 2u
#define ELF_PF_R 4u

#define ELF_SHT_NULL 0u
#define ELF_SHT_PROGBITS 1u
#define ELF_SHT_SYMTAB 2u
#define ELF_SHT_STRTAB 3u
#define ELF_SHT_RELA 4u
#define ELF_SHT_NOBITS 8u
#define ELF_SHT_REL 9u

#define ELF_SHF_WRITE 1u
#define ELF_SHF_ALLOC 2u
#define ELF_SHF_EXECINSTR 4u

#define ELF_SHN_UNDEF 0u
#define ELF_SHN_ABS 0xfff1u
#define ELF_SHN_COMMON 0xfff2u

#define ELF_R_ARM_ABS32 2u
#define ELF_R_ARM_THM_CALL 10u
#define ELF_R_ARM_THM_JUMP24 30u

typedef struct {
    const uint8_t *data;
    uint32_t size;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint16_t phnum;
    uint16_t shnum;
    uint16_t shstrndx;
} elf_file_t;

typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} elf_program_header_t;

typedef struct {
    uint32_t name;
    uint32_t type;
    uint32_t flags;
    uint32_t addr;
    uint32_t offset;
    uint32_t size;
    uint32_t link;
    uint32_t info;
    uint32_t addralign;
    uint32_t entsize;
} elf_section_header_t;

/*
 * Address ranges are half-open: [start, end).
 * Code includes allocated read-only code and constants.
 */
typedef struct {
    uint32_t code_start;
    uint32_t code_end;
    uint32_t data_start;
    uint32_t data_end;
    uint32_t bss_start;
    uint32_t bss_end;
    uint32_t memory_end;
    uint8_t has_code;
    uint8_t has_data;
    uint8_t has_bss;
} elf_memory_layout_t;

typedef struct {
    uint32_t name;
    uint32_t value;
    uint32_t size;
    uint8_t info;
    uint8_t other;
    uint16_t shndx;
} elf_symbol_t;

typedef struct {
    uint32_t offset;
    uint32_t info;
} elf_rel_t;

int elf_open(const uint8_t *data, uint32_t size, elf_file_t *out);

/*
 * Validate the complete ELF before the loader uses its metadata.
 * Returns 0 on success, -1 for malformed/invalid ELF,
 * or -2 for an unsupported relocation in an allocated section.
 */
int elf_validate(const uint8_t *data,
                 uint32_t size,
                 elf_file_t *out,
                 uint32_t *unsupported_type);

int elf_program_header_get(const elf_file_t *elf,
                           unsigned index,
                           elf_program_header_t *out);

int elf_validate_program_headers(const elf_file_t *elf);

/* Validate PT_LOAD coverage of allocated sections and the Thumb entry point. */
int elf_validate_layout(const elf_file_t *elf);

/* Validate and classify allocated code/rodata, data, and BSS. */
int elf_get_memory_layout(const elf_file_t *elf,
                          elf_memory_layout_t *out);

int elf_section_header_get(const elf_file_t *elf,
                           unsigned index,
                           elf_section_header_t *out);

int elf_validate_sections(const elf_file_t *elf);

int elf_symbol_get(const elf_file_t *elf,
                   unsigned symtab_index,
                   unsigned symbol_index,
                   elf_symbol_t *out);

int elf_rel_get(const elf_file_t *elf,
                unsigned rel_section_index,
                unsigned rel_index,
                elf_rel_t *out);

/*
 * Return 0 when relocation metadata is valid,
 * -1 for malformed metadata, or -2 for an unsupported
 * relocation affecting an allocated section.
 * If unsupported_type is non-NULL, report that type on -2.
 */
int elf_validate_relocations(const elf_file_t *elf,
                             uint32_t *unsupported_type);

#endif
