Cargo ASM
===

Disassemble single symbols in a binary.

### TODO

- [x] Read Cargo Metadata in order to find binaries automatically.

- [x] Disassemble ELF binaries. **Linux**
- [ ] Disassemble PE/COFF binaries. **Windows**
- [ ] Disassemble Mach binaries. **MacOS**

- [ ] Patch call instructions with symbol names.

- [x] Use DWARF debug information to show Rust code alongside disassembly.
- [ ] ^ Do the equivalent of that for Windows and MacOS (I'll figure it out)


### Examples

**These have to be run from within the cargo-asm directory. They also require the the binary is compiled via cargo build first.**

**Listing symbols in a binary:**

`cargo run -- list main`

Example Output:
```
[address: 0x2CA6C0] [size: 310 bytes] cargo_asm::main::he7e4b90525b343c2
[address: 0x493590] [size: 247 bytes] core::num::dec2flt::algorithm::round_by_remainder::hf61317af6f74374c
[address: 0x2CC800] [size:  47 bytes] main
```

**Disassembling a symbol**

`cargo run -- disasm -S cargo_asm::main`

Example Output:
```asm
cargo_asm::main::he7e4b90525b343c2:

fn main() {
  2ca6c0:    sub       rsp, 0x88                                      
    if let Err(err) = run() {
  2ca6c7:    call      cargo_asm::run::hc35cb0c3475c7dfe              
  2ca6cc:    mov       qword ptr [rsp + 0x18], rax                    
  2ca6d1:    jmp       0x2ca6df                                       
fn main() {
  2ca6d3:    mov       rdi, qword ptr [rsp + 0x78]                    
  2ca6d8:    call      0x217180                                       
  2ca6dd:    ud2                                                      
  2ca6df:    xor       eax, eax                                       
  2ca6e1:    mov       ecx, eax                                       
    if let Err(err) = run() {
  2ca6e3:    cmp       qword ptr [rsp + 0x18], 0                      
  2ca6e9:    mov       edx, 1                                         
  2ca6ee:    cmovbe    rdx, rcx                                       
  2ca6f2:    cmp       rdx, 1                                         
  2ca6f6:    je        0x2ca707                                       
}
  2ca6f8:    lea       rdi, [rsp + 0x18]                              
  2ca6fd:    call      core::ptr::drop_in_place::h3ba6e349fe585cc9    
  2ca702:    jmp       0x2ca7cf                                       
    if let Err(err) = run() {
  2ca707:    mov       rax, qword ptr [rsp + 0x18]                    
  2ca70c:    mov       qword ptr [rsp + 0x20], rax                    
        eprintln!("error: {:?}", err);
  2ca711:    mov       rsi, qword ptr [rip + 0x8057f8]                
  2ca718:    lea       rax, [rsp + 0x20]                              
        eprintln!("error: {:?}", err);
  2ca71d:    mov       qword ptr [rsp + 0x68], rax                    
  2ca722:    mov       rax, qword ptr [rsp + 0x68]                    
  2ca727:    mov       qword ptr [rsp + 0x70], rax                    
        eprintln!("error: {:?}", err);
  2ca72c:    mov       rdi, qword ptr [rsp + 0x70]                    
  2ca731:    lea       rax, [rip + 0xf72e8]                           
  2ca738:    mov       qword ptr [rsp + 0x10], rsi                    
  2ca73d:    mov       rsi, rax                                       
  2ca740:    call      core::fmt::ArgumentV1::new::h9fcfdf5e06891ab6  
  2ca745:    mov       qword ptr [rsp + 8], rdx                       
  2ca74a:    mov       qword ptr [rsp], rax                           
  2ca74e:    jmp       0x2ca750                                       
  2ca750:    mov       rax, qword ptr [rsp]                           
        eprintln!("error: {:?}", err);
  2ca754:    mov       qword ptr [rsp + 0x58], rax                    
  2ca759:    mov       rcx, qword ptr [rsp + 8]                       
  2ca75e:    mov       qword ptr [rsp + 0x60], rcx                    
  2ca763:    lea       rdi, [rsp + 0x28]                              
  2ca768:    mov       edx, 2                                         
  2ca76d:    lea       rcx, [rsp + 0x58]                              
  2ca772:    mov       r8d, 1                                         
  2ca778:    mov       rsi, qword ptr [rsp + 0x10]                    
        eprintln!("error: {:?}", err);
  2ca77d:    call      core::fmt::Arguments::new_v1::h82cc96922c9a1896
  2ca782:    jmp       0x2ca7af                                       
  2ca784:    xor       eax, eax                                       
  2ca786:    mov       ecx, eax                                       
}
  2ca788:    cmp       qword ptr [rsp + 0x18], 0                      
  2ca78e:    mov       edx, 1                                         
  2ca793:    cmovbe    rdx, rcx                                       
  2ca797:    cmp       rdx, 1                                         
  2ca79b:    je        0x2ca6d3                                       
  2ca7a1:    jmp       0x2ca7d7                                       
    }
  2ca7a3:    lea       rdi, [rsp + 0x20]                              
  2ca7a8:    call      core::ptr::drop_in_place::h2f9c3b8587adf9a5    
  2ca7ad:    jmp       0x2ca784                                       
        eprintln!("error: {:?}", err);
  2ca7af:    lea       rax, [rip + 0x4abe9a]                          
  2ca7b6:    lea       rdi, [rsp + 0x28]                              
  2ca7bb:    call      rax                                            
  2ca7bd:    jmp       0x2ca7bf                                       
        std::process::exit(1);
  2ca7bf:    lea       rax, [rip + 0x4aee7a]                          
  2ca7c6:    mov       edi, 1                                         
  2ca7cb:    call      rax                                            
  2ca7cd:    jmp       0x2ca7f4                                       
}
  2ca7cf:    add       rsp, 0x88                                      
  2ca7d6:    ret                                                      
}
  2ca7d7:    lea       rdi, [rsp + 0x18]                              
  2ca7dc:    call      core::ptr::drop_in_place::h3ba6e349fe585cc9    
  2ca7e1:    jmp       0x2ca6d3                                       
  2ca7e6:    mov       qword ptr [rsp + 0x78], rax                    
  2ca7eb:    mov       dword ptr [rsp + 0x80], edx                    
  2ca7f2:    jmp       0x2ca7a3                                       
  2ca7f4:    ud2                             
```
