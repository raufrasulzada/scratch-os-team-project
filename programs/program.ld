ENTRY(_start)

PHDRS
{
    code PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x00000000;

    .text :
    {
        . = ALIGN(4);
        __program_code_start = .;

        KEEP(*(.text.startup))
        *(.text .text.*)
        *(.rodata .rodata.*)

        . = ALIGN(512);
        __program_code_end = .;
    } :code

    .data :
    {
        . = ALIGN(4);
        __program_data_start = .;

        *(.data .data.*)

        . = ALIGN(4);
        __program_data_end = .;
    } :data

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        __program_bss_start = .;

        *(.bss .bss.*)
        *(COMMON)

        . = ALIGN(4);
        __program_bss_end = .;
    } :data

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.eh_frame*)
        *(.comment*)
        *(.note*)
    }
}
