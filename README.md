Cargo ASM
===

Disassemble single symbols in a binary.

### TODO

- [x] Read Cargo Metadata in order to find binaries automatically.

- [x] Disassemble ELF binaries. **Linux**
- [ ] Disassemble PE/COFF binaries. **Windows**
- [ ] Disassemble Mach binaries. **MacOS**

- [ ] Patch call instructions with symbol names.

- [ ] Use DWARF debug information to show Rust code alongside disassembly.
- [ ] ^ Do the equivalent of that for Windows and MacOS (I'll figure it out)


### Examples

**These have to be run from within the cargo-asm directory. They also require the the binary is compiled via cargo build first.**

**Listing symbols in a binary:**

`cargo run -- list main`

Example Output:
```
[address: 0x228300] [size: 310 bytes] cargo_asm::main::he2817aa33cca4269
[address: 0x3F0880] [size: 247 bytes] core::num::dec2flt::algorithm::round_by_remainder::hf61317af6f74374c
[address: 0x22A4A0] [size:  47 bytes] main
```

**Disassembling a symbol**

`cargo run -- disasm cargo_asm::main`

Example Output:
```asm
cargo_asm::main::he2817aa33cca4269:
    228300:    48 81 EC 88 00 00 00                 sub       rsp, 0x88                          
    228307:    E8 34 01 00 00                       call      0x228440                           
    22830c:    48 89 44 24 18                       mov       qword ptr [rsp + 0x18], rax        
    228311:    EB 0C                         ┌─────◀jmp       0x22831f                           
    228313:    48 8B 7C 24 78                │ ┌─┬─▶mov       rdi, qword ptr [rsp + 0x78]        
    228318:    E8 63 AE FE FF                │ │ │  call      0x213180                           
    22831d:    0F 0B                         │ │ │  ud2                                          
    22831f:    31 C0                         └─┼─┼─▶xor       eax, eax                           
    228321:    89 C1                           │ │  mov       ecx, eax                           
    228323:    48 83 7C 24 18 00               │ │  cmp       qword ptr [rsp + 0x18], 0          
    228329:    BA 01 00 00 00                  │ │  mov       edx, 1                             
    22832e:    48 0F 46 D1                     │ │  cmovbe    rdx, rcx                           
    228332:    48 83 FA 01                     │ │  cmp       rdx, 1                             
    228336:    74 0F                         ┌─┼─┼─◀je        0x228347                           
    228338:    48 8D 7C 24 18                │ │ │  lea       rdi, [rsp + 0x18]                  
    22833d:    E8 1E 02 01 00                │ │ │  call      0x238560                           
    228342:    E9 C8 00 00 00          ┌─────┼─┼─┼─◀jmp       0x22840f                           
    228347:    48 8B 44 24 18          │     └─┼─┼─▶mov       rax, qword ptr [rsp + 0x18]        
    22834c:    48 89 44 24 20          │       │ │  mov       qword ptr [rsp + 0x20], rax        
    228351:    48 8B 35 20 D6 7D 00    │       │ │  mov       rsi, qword ptr [rip + 0x7dd620]    
    228358:    48 8D 44 24 20          │       │ │  lea       rax, [rsp + 0x20]                  
    22835d:    48 89 44 24 68          │       │ │  mov       qword ptr [rsp + 0x68], rax        
    228362:    48 8B 44 24 68          │       │ │  mov       rax, qword ptr [rsp + 0x68]        
    228367:    48 89 44 24 70          │       │ │  mov       qword ptr [rsp + 0x70], rax        
    22836c:    48 8B 7C 24 70          │       │ │  mov       rdi, qword ptr [rsp + 0x70]        
    228371:    48 8D 05 38 6A 0F 00    │       │ │  lea       rax, [rip + 0xf6a38]               
    228378:    48 89 74 24 10          │       │ │  mov       qword ptr [rsp + 0x10], rsi        
    22837d:    48 89 C6                │       │ │  mov       rsi, rax                           
    228380:    E8 CB 7E FF FF          │       │ │  call      0x220250                           
    228385:    48 89 54 24 08          │       │ │  mov       qword ptr [rsp + 8], rdx           
    22838a:    48 89 04 24             │       │ │  mov       qword ptr [rsp], rax               
    22838e:    EB 00                   │     ┌─┼─┼─◀jmp       0x228390                           
    228390:    48 8B 04 24             │     └─┼─┼─▶mov       rax, qword ptr [rsp]               
    228394:    48 89 44 24 58          │       │ │  mov       qword ptr [rsp + 0x58], rax        
    228399:    48 8B 4C 24 08          │       │ │  mov       rcx, qword ptr [rsp + 8]           
    22839e:    48 89 4C 24 60          │       │ │  mov       qword ptr [rsp + 0x60], rcx        
    2283a3:    48 8D 7C 24 28          │       │ │  lea       rdi, [rsp + 0x28]                  
    2283a8:    BA 02 00 00 00          │       │ │  mov       edx, 2                             
    2283ad:    48 8D 4C 24 58          │       │ │  lea       rcx, [rsp + 0x58]                  
    2283b2:    41 B8 01 00 00 00       │       │ │  mov       r8d, 1                             
    2283b8:    48 8B 74 24 10          │       │ │  mov       rsi, qword ptr [rsp + 0x10]        
    2283bd:    E8 3E B0 00 00          │       │ │  call      0x233400                           
    2283c2:    EB 2B                   │ ┌─────┼─┼─◀jmp       0x2283ef                           
    2283c4:    31 C0                   │ │   ┌─┼─┼─▶xor       eax, eax                           
    2283c6:    89 C1                   │ │   │ │ │  mov       ecx, eax                           
    2283c8:    48 83 7C 24 18 00       │ │   │ │ │  cmp       qword ptr [rsp + 0x18], 0          
    2283ce:    BA 01 00 00 00          │ │   │ │ │  mov       edx, 1                             
    2283d3:    48 0F 46 D1             │ │   │ │ │  cmovbe    rdx, rcx                           
    2283d7:    48 83 FA 01             │ │   │ │ │  cmp       rdx, 1                             
    2283db:    0F 84 32 FF FF FF       │ │   │ │ └─◀je        0x228313                           
    2283e1:    EB 34                   │ │ ┌─┼─┼───◀jmp       0x228417                           
    2283e3:    48 8D 7C 24 20          │ │ │ │ │ ┌─▶lea       rdi, [rsp + 0x20]                  
    2283e8:    E8 03 01 01 00          │ │ │ │ │ │  call      0x2384f0                           
    2283ed:    EB D5                   │ │ │ └─┼─┼─◀jmp       0x2283c4                           
    2283ef:    48 8D 05 8A 77 4A 00    │ └─┼───┼─┼─▶lea       rax, [rip + 0x4a778a]              
    2283f6:    48 8D 7C 24 28          │   │   │ │  lea       rdi, [rsp + 0x28]                  
    2283fb:    FF D0                   │   │   │ │  call      rax                                
    2283fd:    EB 00                   │   │ ┌─┼─┼─◀jmp       0x2283ff                           
    2283ff:    48 8D 05 FA A5 4A 00    │   │ └─┼─┼─▶lea       rax, [rip + 0x4aa5fa]              
    228406:    BF 01 00 00 00          │   │   │ │  mov       edi, 1                             
    22840b:    FF D0                   │   │   │ │  call      rax                                
    22840d:    EB 25                   │   │ ┌─┼─┼─◀jmp       0x228434                           
    22840f:    48 81 C4 88 00 00 00    └───┼─┼─┼─┼─▶add       rsp, 0x88                          
    228416:    C3                          │ │ │ │  ret                                          
    228417:    48 8D 7C 24 18              └─┼─┼─┼─▶lea       rdi, [rsp + 0x18]                  
    22841c:    E8 3F 01 01 00                │ │ │  call      0x238560                           
    228421:    E9 ED FE FF FF                │ └─┼─◀jmp       0x228313                           
    228426:    48 89 44 24 78                │   │  mov       qword ptr [rsp + 0x78], rax        
    22842b:    89 94 24 80 00 00 00          │   │  mov       dword ptr [rsp + 0x80], edx        
    228432:    EB AF                         │   └─◀jmp       0x2283e3                           
    228434:    0F 0B                         └─────▶ud2                 
```
