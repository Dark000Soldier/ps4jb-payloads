%define iret_rdi 0
%define iret_rsi 8
%define iret_rdx 16
%define iret_rcx 24
%define iret_r8 32
%define iret_r9 40
%define iret_rax 48
%define iret_rbx 56
%define iret_rbp 64
%define iret_r10 72
%define iret_r11 80
%define iret_r12 88
%define iret_r13 96
%define iret_r14 104
%define iret_r15 112
%define iret_rip 232
%define iret_cs (iret_rip+8)
%define iret_eflags (iret_rip+16)
%define iret_rsp (iret_rip+24)
%define iret_ss (iret_rip+32)

%define td_retval 0x408

%define syscall_rsp_to_regs_stash 0x110