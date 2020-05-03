Cargo ASM
===

Disassemble single symbols in a binary.

### TODO

- [ ] Read Cargo Metadata in order to find binaries automatically.

- [x] Disassemble ELF binaries. **Linux**
- [ ] Disassemble PE/COFF binaries. **Windows**
- [ ] Disassemble Mach binaries. **MacOS**

- [ ] Patch call instructions with symbol names.

- [ ] Use DWARF debug information to show Rust code alongside disassembly.
- [ ] ^ Do the equivalent of that for Windows and MacOS (I'll figure it out)


### Examples

**These have to be run from within the cargo-asm directory.**

**Listing symbols in a binary:**

`cargo run -- list --binary=<<MY BINARY>> "SharedGbaScheduler"`

Example Output:
```
[address: 0x264F60] [size: 395 bytes] pyrite_gba::scheduler::SharedGbaScheduler::purge::h24b3d5d65acad74a
[address: 0x2662B0] [size: 251 bytes] pyrite_gba::scheduler::SharedGbaScheduler::new::hd31299236c8d984b
[address: 0x2663B0] [size:  29 bytes] <pyrite_gba::scheduler::SharedGbaScheduler as core::clone::Clone>::clone::h150cc913f28b405a
```

**Disassembling a symbol**

`cargo run -- disasm --binary=<<MY BINARY>> "SharedGbaScheduler::purge"`

Example Output:
```asm
pyrite_gba::scheduler::SharedGbaScheduler::purge::h24b3d5d65acad74a:
    264020:    55                                                    push    rbp                                    
    264021:    48 89 E5                                              mov     rbp, rsp                               
    264024:    41 57                                                 push    r15                                    
    264026:    41 56                                                 push    r14                                    
    264028:    53                                                    push    rbx                                    
    264029:    50                                                    push    rax                                    
    26402a:    4C 8B 37                                              mov     r14, qword ptr [rdi]                   
    26402d:    49 8B 46 10                                           mov     rax, qword ptr [r14 + 0x10]            
    264031:    48 85 C0                                              test    rax, rax                               
    264034:    0F 84 B4 00 00 00                ┌───────────────────◀je      0x2640ee                               
    26403a:    31 DB                            │                    xor     ebx, ebx                               
    26403c:    4C 8B 3D C5 2A 0A 00             │                    mov     r15, qword ptr [rip + 0xa2ac5]         
    264043:    EB 17                            │                 ┌─◀jmp     0x26405c                               
    264045:    66 2E 0F 1F 84 00 00 00 00 00    │                 │  nop     word ptr cs:[rax + rax]                
    26404f:    90                               │                 │  nop                                            
    264050:    48 89 F3                         │               ┌─┼─▶mov     rbx, rsi                               
    264053:    48 39 C3                         │               │ │  cmp     rbx, rax                               
    264056:    0F 83 92 00 00 00                │ ┌─────────────┼─┼─◀jae     0x2640ee                               
    26405c:    48 83 FB 1F                      │ │             │ ├─▶cmp     rbx, 0x1f                              
    264060:    0F 87 93 00 00 00                │ │ ┌───────────┼─┼─◀ja      0x2640f9                               
    264066:    48 8D 73 01                      │ │ │           │ │  lea     rsi, [rbx + 1]                         
    26406a:    41 80 7C DE 1C 07                │ │ │           │ │  cmp     byte ptr [r14 + rbx*8 + 0x1c], 7       
    264070:    75 DE                            │ │ │           └─┼─◀jne     0x264050                               
    264072:    48 83 FE 1F                      │ │ │             │  cmp     rsi, 0x1f                              
    264076:    0F 87 94 00 00 00                │ │ │ ┌───────────┼─◀ja      0x264110                               
    26407c:    41 8B 44 DE 20                   │ │ │ │           │  mov     eax, dword ptr [r14 + rbx*8 + 0x20]    
    264081:    41 03 44 DE 18                   │ │ │ │           │  add     eax, dword ptr [r14 + rbx*8 + 0x18]    
    264086:    0F 82 98 00 00 00                │ │ │ │ ┌─────────┼─◀jb      0x264124                               
    26408c:    41 89 44 DE 20                   │ │ │ │ │         │  mov     dword ptr [r14 + rbx*8 + 0x20], eax    
    264091:    49 8B 56 10                      │ │ │ │ │         │  mov     rdx, qword ptr [r14 + 0x10]            
    264095:    48 39 DA                         │ │ │ │ │         │  cmp     rdx, rbx                               
    264098:    0F 86 A1 00 00 00                │ │ │ │ │ ┌───────┼─◀jbe     0x26413f                               
    26409e:    48 83 FA 20                      │ │ │ │ │ │       │  cmp     rdx, 0x20                              
    2640a2:    0F 87 B2 00 00 00                │ │ │ │ │ │ ┌─────┼─◀ja      0x26415a                               
    2640a8:    48 29 F2                         │ │ │ │ │ │ │     │  sub     rdx, rsi                               
    2640ab:    B8 20 00 00 00                   │ │ │ │ │ │ │     │  mov     eax, 0x20                              
    2640b0:    48 29 D0                         │ │ │ │ │ │ │     │  sub     rax, rdx                               
    2640b3:    48 39 D8                         │ │ │ │ │ │ │     │  cmp     rax, rbx                               
    2640b6:    0F 82 B9 00 00 00                │ │ │ │ │ │ │ ┌───┼─◀jb      0x264175                               
    2640bc:    49 8D 34 F6                      │ │ │ │ │ │ │ │   │  lea     rsi, [r14 + rsi*8]                     
    2640c0:    48 83 C6 18                      │ │ │ │ │ │ │ │   │  add     rsi, 0x18                              
    2640c4:    49 8D 3C DE                      │ │ │ │ │ │ │ │   │  lea     rdi, [r14 + rbx*8]                     
    2640c8:    48 83 C7 18                      │ │ │ │ │ │ │ │   │  add     rdi, 0x18                              
    2640cc:    48 C1 E2 03                      │ │ │ │ │ │ │ │   │  shl     rdx, 3                                 
    2640d0:    41 FF D7                         │ │ │ │ │ │ │ │   │  call    r15                                    
    2640d3:    49 8B 46 10                      │ │ │ │ │ │ │ │   │  mov     rax, qword ptr [r14 + 0x10]            
    2640d7:    48 83 E8 01                      │ │ │ │ │ │ │ │   │  sub     rax, 1                                 
    2640db:    0F 82 AF 00 00 00                │ │ │ │ │ │ │ │ ┌─┼─◀jb      0x264190                               
    2640e1:    49 89 46 10                      │ │ │ │ │ │ │ │ │ │  mov     qword ptr [r14 + 0x10], rax            
    2640e5:    48 39 C3                         │ │ │ │ │ │ │ │ │ │  cmp     rbx, rax                               
    2640e8:    0F 82 6E FF FF FF                │ │ │ │ │ │ │ │ │ └─◀jb      0x26405c                               
    2640ee:    48 83 C4 08                      └─┴─┼─┼─┼─┼─┼─┼─┼───▶add     rsp, 8                                 
    2640f2:    5B                                   │ │ │ │ │ │ │    pop     rbx                                    
    2640f3:    41 5E                                │ │ │ │ │ │ │    pop     r14                                    
    2640f5:    41 5F                                │ │ │ │ │ │ │    pop     r15                                    
    2640f7:    5D                                   │ │ │ │ │ │ │    pop     rbp                                    
    2640f8:    C3                                   │ │ │ │ │ │ │    ret                                            
    2640f9:    48 8D 3D B0 28 09 00                 └─┼─┼─┼─┼─┼─┼───▶lea     rdi, [rip + 0x928b0]                   
    264100:    BA 20 00 00 00                         │ │ │ │ │ │    mov     edx, 0x20                              
    264105:    48 89 DE                               │ │ │ │ │ │    mov     rsi, rbx                               
    264108:    FF 15 02 26 0A 00                      │ │ │ │ │ │    call    qword ptr [rip + 0xa2602]              
    26410e:    0F 0B                                  │ │ │ │ │ │    ud2                                            
    264110:    48 8D 3D B1 28 09 00                   └─┼─┼─┼─┼─┼───▶lea     rdi, [rip + 0x928b1]                   
    264117:    BA 20 00 00 00                           │ │ │ │ │    mov     edx, 0x20                              
    26411c:    FF 15 EE 25 0A 00                        │ │ │ │ │    call    qword ptr [rip + 0xa25ee]              
    264122:    0F 0B                                    │ │ │ │ │    ud2                                            
    264124:    48 8D 3D D5 EA E2 FF                     └─┼─┼─┼─┼───▶lea     rdi, [rip - 0x1d152b]                  
    26412b:    48 8D 15 96 28 09 00                       │ │ │ │    lea     rdx, [rip + 0x92896]                   
    264132:    BE 1C 00 00 00                             │ │ │ │    mov     esi, 0x1c                              
    264137:    FF 15 6B 25 0A 00                          │ │ │ │    call    qword ptr [rip + 0xa256b]              
    26413d:    0F 0B                                      │ │ │ │    ud2                                            
    26413f:    48 8D 3D 76 0C E3 FF                       └─┼─┼─┼───▶lea     rdi, [rip - 0x1cf38a]                  
    264146:    48 8D 15 DB 39 09 00                         │ │ │    lea     rdx, [rip + 0x939db]                   
    26414d:    BE 1B 00 00 00                               │ │ │    mov     esi, 0x1b                              
    264152:    FF 15 50 25 0A 00                            │ │ │    call    qword ptr [rip + 0xa2550]              
    264158:    0F 0B                                        │ │ │    ud2                                            
    26415a:    48 8D 3D BF 0C E3 FF                         └─┼─┼───▶lea     rdi, [rip - 0x1cf341]                  
    264161:    48 8D 15 C0 39 09 00                           │ │    lea     rdx, [rip + 0x939c0]                   
    264168:    BE 14 00 00 00                                 │ │    mov     esi, 0x14                              
    26416d:    FF 15 35 25 0A 00                              │ │    call    qword ptr [rip + 0xa2535]              
    264173:    0F 0B                                          │ │    ud2                                            
    264175:    48 8D 3D B8 0C E3 FF                           └─┼───▶lea     rdi, [rip - 0x1cf348]                  
    26417c:    48 8D 15 A5 39 09 00                             │    lea     rdx, [rip + 0x939a5]                   
    264183:    BE 15 00 00 00                                   │    mov     esi, 0x15                              
    264188:    FF 15 1A 25 0A 00                                │    call    qword ptr [rip + 0xa251a]              
    26418e:    0F 0B                                            │    ud2                                            
    264190:    48 8D 3D 89 EA E2 FF                             └───▶lea     rdi, [rip - 0x1d1577]                  
    264197:    48 8D 15 42 28 09 00                                  lea     rdx, [rip + 0x92842]                   
    26419e:    BE 21 00 00 00                                        mov     esi, 0x21                              
    2641a3:    FF 15 FF 24 0A 00                                     call    qword ptr [rip + 0xa24ff]              
    2641a9:    0F 0B                                                 ud2   
```
