/*
 * The linker script for C programs that link libopenvm_c_guest.a, for GNU ld and LLD (see
 * README.md). It lays out OpenVM's 4 GiB of memory:
 *
 *   below 0x0020_0400            the stack, which OpenVM's `_start` starts at 0x0020_0400 and
 *                                which grows down
 *   0x0020_0800 .. _end          the program: code, read-only data, then data and BSS, each in a
 *                                segment of its own
 *   _heap_start .. _heap_end     the program's heap, which the library doesn't use
 *   __openvm_heap_start .. 4 GiB the library's heap: OpenVM's allocator takes memory from there up
 *
 * `_heap_end` and `__openvm_heap_start` are 0x7FFF_F000, the last page below 2 GiB: code built for
 * the medlow code model, as C programs often are, addresses symbols only below 2 GiB.
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

PHDRS
{
  /* OpenVM transpiles every word of the executable segment as an instruction, and a data word can
     make the transpiler fail, so the segment holds only code. */
  text PT_LOAD FLAGS(5);   /* R X */
  rodata PT_LOAD FLAGS(4); /* R */
  data PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS
{
  /* OpenVM's TEXT_START. */
  . = 0x00200800;
  .text : {
    *(.text.unlikely .text.unlikely.*)
    *(.text.startup .text.startup.*)
    *(.text .text.*)
    KEEP(*(SORT_NONE(.init)))
    KEEP(*(SORT_NONE(.fini)))
  } :text

  . = ALIGN(0x1000);
  .rodata : {
    *(.rodata .rodata.*)
    *(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2) *(.srodata .srodata.*)
  } :rodata
  /* GNU ld would otherwise put the build ID note in the data segment, at the start of the code. */
  .note.gnu.build-id : { *(.note.gnu.build-id) } :rodata
  .eh_frame_hdr : { *(.eh_frame_hdr) } :rodata
  .eh_frame : { KEEP(*(.eh_frame)) *(.eh_frame.*) } :rodata
  .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) } :rodata
  /* The constructor and destructor arrays, with the bounds that GNU ld's default script defines and
     the library's startup code walks. */
  .preinit_array : {
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } :rodata
  .init_array : {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE_HIDDEN(__init_array_end = .);
  } :rodata
  .fini_array : {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE_HIDDEN(__fini_array_end = .);
  } :rodata
  /* Nothing runs the older .ctors and .dtors tables. */
  .ctors : { KEEP(*(.ctors .ctors.*)) KEEP(*(.dtors .dtors.*)) } :rodata
  ASSERT(SIZEOF(.ctors) == 0, ".ctors and .dtors aren't supported: use .init_array and .fini_array")
  .data.rel.ro : { *(.data.rel.ro.local .data.rel.ro.local.*) *(.data.rel.ro .data.rel.ro.*) } :rodata
  .got : { *(.got.plt) *(.igot.plt) *(.got) *(.igot) } :rodata

  . = ALIGN(0x1000);
  .data : { *(.data .data.*) } :data
  /* `_start` loads the global pointer, which the linker may relax small-data accesses against. */
  __global_pointer$ = . + 0x800;
  .sdata : { *(.sdata .sdata.*) } :data
  .sbss : { *(.sbss .sbss.*) *(.scommon) } :data
  .bss : { *(.bss .bss.*) *(COMMON) } :data
  /* Uninitialized data, which a linker could otherwise put after `_heap_start`. */
  .noinit (NOLOAD) : { *(.noinit .noinit.*) } :data
  /* OpenVM's `_start` doesn't set up the thread pointer. */
  .tdata : { *(.tdata .tdata.*) } :data
  .tbss : { *(.tbss .tbss.*) } :data
  ASSERT(SIZEOF(.tdata) == 0 && SIZEOF(.tbss) == 0, "thread-local storage isn't supported")

  . = ALIGN(16);
  _end = .;
  PROVIDE(end = .);
  _heap_start = .;
  _heap_end = 0x7FFFF000;
  /* picolibc's names for the heap's bounds. */
  PROVIDE(__heap_start = _heap_start);
  PROVIDE(__heap_end = _heap_end);
  /* build.sh renames the library's reference to `_end`, from OpenVM's allocator, to this symbol. */
  __openvm_heap_start = _heap_end;
  ASSERT(_heap_start <= _heap_end, "the program doesn't fit below _heap_end")
}
