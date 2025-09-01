/*
 * Simple linker script for the ca_packer unpacking stub.
 * This script defines the necessary program headers (segments) to create a valid
 * Position-Independent Executable (PIE) that the OS loader can handle.
 */
ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(7);  /* R, W, X */
    data PT_LOAD FLAGS(6);  /* R, W */
}

SECTIONS
{
    /* The -pie flag makes the linker handle the base address, so we don't set a fixed one here.
       We start the .text section after the ELF and Program headers to leave space for them. */
    . = SIZEOF_HEADERS;
    .text : {
        *(.text)
        *(.text.*)
        *(.data)
        *(.data.*)
    } :text

    /* .rodata and .bss are not used by our stub, but we can leave placeholders.
       The linker will simply create empty sections if there's no input. */
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    } :text

    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    } :text
}
