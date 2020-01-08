#!/usr/bin/python

from __future__ import print_function
from capstone import *
from unicorn import *
from unicorn.x86_const import *
from struct import pack,unpack
import sys, binascii
from WinAPIHook import *

###############

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_EXEC = 0x8
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

cnt = 0

class Layout:
    def __init__(self, uc):
        self.UC = uc

    def CreateGDTEntry(self, base, limit, access, flags):
        to_ret = limit & 0xffff;
        to_ret |= (base & 0xffffff) << 16;
        to_ret |= (access & 0xff) << 40;
        to_ret |= ((limit >> 16) & 0xf) << 48;
        to_ret |= (flags & 0xff) << 52;
        to_ret |= ((base >> 24) & 0xff) << 56;
        return pack('<Q',to_ret)

    def CreateSelector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def Setup(self, 
                gdt_addr = 0x80043000, 
                gdt_limit = 0x1000, 
                gdt_entry_size = 0x8, 
                fs_base = None, 
                fs_limit = None, 
                gs_base = None, 
                gs_limit = None, 
                segment_limit = 0xffffffff
        ):
        self.UC.mem_map(gdt_addr, gdt_limit)
        gdt = [self.CreateGDTEntry(0,0,0,0) for i in range(0x34)]
        
        if fs_base != None and fs_limit != None:
            gdt[0x0e] = self.CreateGDTEntry(fs_base, fs_limit , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        else:
            gdt[0x0e] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

        if gs_base != None and gs_limit != None:
            gdt[0x0f] = self.CreateGDTEntry(gs_base, gs_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
        else:
            gdt[0x0f] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

        gdt[0x10] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment
        gdt[0x11] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment
        gdt[0x12] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment
        gdt[0x6] = self.CreateGDTEntry(0, segment_limit, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment

        for idx, value in enumerate(gdt):
            offset = idx * gdt_entry_size
            self.UC.mem_write(gdt_addr + offset, value)
        
        self.UC.reg_write(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) * gdt_entry_size-1, 0x0))
        self.UC.reg_write(UC_X86_REG_FS, self.CreateSelector(0x0e, S_GDT | S_PRIV_0))
        self.UC.reg_write(UC_X86_REG_GS, self.CreateSelector(0x0f, S_GDT | S_PRIV_3))
        self.UC.reg_write(UC_X86_REG_DS, self.CreateSelector(0x10, S_GDT | S_PRIV_3))
        self.UC.reg_write(UC_X86_REG_CS, self.CreateSelector(0x11, S_GDT | S_PRIV_3))
        self.UC.reg_write(UC_X86_REG_SS, self.CreateSelector(0x12, S_GDT | S_PRIV_0))

WINAPI = {}


def get_func_addr(uc, base, EXPORT_DIRECTORY_BASE):
    export_dir = uc.mem_read(base+EXPORT_DIRECTORY_BASE,0x30)
    num_funcs = unpack("<I", export_dir[24:28])[0]
    func_offset = unpack("<I", export_dir[28:32])[0]
    name_offset= unpack("<I", export_dir[32:36])[0]
    ordinal_offset = unpack("<I", export_dir[36:40])[0]

    names=[]
    for i in range(0,num_funcs):
        #func name
        offset = uc.mem_read(base+name_offset+i*4, 4)
        offset = unpack("<I", offset)[0]
        c=''
        name=bytearray(b'')
        while True:
            c = uc.mem_read(base+offset, 1)
            if c==b"\x00":
                break
            name+=c
            offset+=1
        #ordinal
        idx = unpack("<I", uc.mem_read(base+ordinal_offset+i*2, 2)+bytearray(b"\x00\x00"))[0]
        #func addr
        offset = unpack("<I", uc.mem_read(base+func_offset+idx*4, 4))[0]

        if base+offset not in WINAPI.keys():
            WINAPI[base+offset] = []
        WINAPI[base+offset].append(str(name.decode('utf-8')))
    


def printRegs(em):
    eax = em.reg_read(UC_X86_REG_EAX)
    ebx = em.reg_read(UC_X86_REG_EBX)
    ecx = em.reg_read(UC_X86_REG_ECX)
    edx = em.reg_read(UC_X86_REG_EDX)
    esi = em.reg_read(UC_X86_REG_ESI)
    edi = em.reg_read(UC_X86_REG_EDI)
    eip = em.reg_read(UC_X86_REG_EIP)
    esp = em.reg_read(UC_X86_REG_ESP)
    ebp = em.reg_read(UC_X86_REG_EBP)
    print("eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x"%(eax,ebx,ecx,edx,esi,edi))
    print("eip=%x esp=%x ebp=%x"%(eip,esp,ebp))


# memory address where emulation starts
def hook_code(uc, addr, size, data):
    '''
    print("---------------------------------------")
    printRegs(uc)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ins = uc.mem_read(addr, size)
    for i in md.disasm(ins, size):
        print("%x: %-8s\t%s\t%s" % (i.address, binascii.hexlify(ins), i.mnemonic, i.op_str) )
    '''
    
    eip=uc.reg_read(UC_X86_REG_EIP)
    if eip == 0x826503:
        uc.emu_stop()

    esp=uc.reg_read(UC_X86_REG_ESP)
    if eip in WINAPI:
        func = WINAPI[eip][0]
        print(func)
        if 'hook_'+func in globals():
            globals()['hook_'+func](uc,esp)
        if len(WINAPI[eip])>1:
            print(WINAPI[eip])
    

def hook_mem_invalid(uc, access, addr, size, value, data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print("UNMAPPED MEMORY WRITE at 0x%x, size: %u, value: 0x%x"%(addr,size,value))
    else:
        print("UNMAPPED MEMORY READ at 0x%x, size: %u, value: 0x%x"%(addr,size,value))
    printRegs(uc)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ins = uc.mem_read(addr, size)
    for i in md.disasm(ins, size):
        #print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print("%x: %-8s\t%s\t%s" % (i.address, binascii.hexlify(ins), i.mnemonic, i.op_str) )

    return True

#try:
# Initialize emulator in X86-32bit mode
UC = Uc(UC_ARCH_X86, UC_MODE_32)

#
fs_base = 0x00303000
fs_limit = 0xffff
segment_limit = 0xfffffff
gdt_layout = Layout(UC)
gdt_layout.Setup(fs_base = fs_base, fs_limit = fs_limit, segment_limit = segment_limit)
UC.mem_map(fs_base, 0x10000)
teb_data = open("teb.dmp","rb").read()
UC.mem_write(fs_base, teb_data)

PEB_BASE = 0x300000
PEB_SIZE = 0x3000
pebdump = open("PEB.dmp","rb").read()
UC.mem_map(PEB_BASE, PEB_SIZE)
UC.mem_write(PEB_BASE, pebdump)
#stack
STACK_BASE = 0x199000
STACK_TOP = 0x1a0000
STACK_SIZE = 0x7000
stackdump = open("stack.dmp","rb").read()
UC.mem_map(STACK_BASE, STACK_SIZE)
UC.mem_write(STACK_BASE, stackdump)

#
KERNEL32_BASE = 0x76740000
KERNEL32_SIZE = 0x1000
UC.mem_map(KERNEL32_BASE, KERNEL32_SIZE)
UC.mem_write(KERNEL32_BASE, open("kernel32.dmp","rb").read())
#
KERNEL32_BASE1 = 0x76750000
KERNEL32_SIZE1 = 0x64000
UC.mem_map(KERNEL32_BASE1, KERNEL32_SIZE1)
UC.mem_write(KERNEL32_BASE1, open("kernel32_1.dmp","rb").read())
#
KERNEL32_BASE2 = 0x767f0000
KERNEL32_SIZE2 = 0x1000
UC.mem_map(KERNEL32_BASE2, KERNEL32_SIZE2)
UC.mem_write(KERNEL32_BASE2, open("kernel32_2.dmp","rb").read())
#
KERNEL32_BASE3 = 0x767c0000
KERNEL32_SIZE3 = 0x27000
UC.mem_map(KERNEL32_BASE3, KERNEL32_SIZE3)
UC.mem_write(KERNEL32_BASE3, open("kernel32_3.dmp","rb").read())

#
USERSHARED_BASE = 0x7ffe0000
USERSHARED_SIZE = 0x1000
UC.mem_map(USERSHARED_BASE, USERSHARED_SIZE)
UC.mem_write(USERSHARED_BASE, open("usershared.dmp","rb").read())
#
KERNELBASE_BASE = 0x74890000
KERNELBASE_SIZE = 0x1a1000
UC.mem_map(KERNELBASE_BASE, KERNELBASE_SIZE)
UC.mem_write(KERNELBASE_BASE, open("kernelbase_full.dmp","rb").read())
#
UNKNOWN_BASE = 0x2040000
UNKNOWN_SIZE = 0x1000
UC.mem_map(UNKNOWN_BASE, UNKNOWN_SIZE)
UC.mem_write(UNKNOWN_BASE, open("unknown1.dmp","rb").read())
#
HEAP1_BASE = 0x7e0000
HEAP1_SIZE = 0xe5000
UC.mem_map(HEAP1_BASE, HEAP1_SIZE)
UC.mem_write(HEAP1_BASE,open("heap.dmp","rb").read())
#
HEAP2_BASE = 0x20000
HEAP2_SIZE = 0x2000
UC.mem_map(HEAP2_BASE, HEAP2_SIZE)
UC.mem_write(HEAP2_BASE,open("heap2.dmp","rb").read())



#
NTDLL_BASE = 0x77430000
NTDLL_SIZE = 0x182000
UC.mem_map(NTDLL_BASE, NTDLL_SIZE)
UC.mem_write(NTDLL_BASE, open("ntdllfull.dmp","rb").read())
#
URLMON_BASE = 0x731f0000
URLMON_SIZE = 0x195000
UC.mem_map(URLMON_BASE, URLMON_SIZE)
UC.mem_write(URLMON_BASE, open("urlmon.dmp","rb").read())

#
OTHER_BASE = 0x7ffb0000
OTHER_SIZE = 0x23000
UC.mem_map(OTHER_BASE, OTHER_SIZE)
UC.mem_write(OTHER_BASE, open("other.dmp","rb").read())
#
OTHER_BASE2 = 0x1b0000
OTHER_SIZE2 = 0x1000
UC.mem_map(OTHER_BASE2, OTHER_SIZE2)
UC.mem_write(OTHER_BASE2, open("other2.dmp","rb").read())
#
OTHER_BASE3 = 0x1a0000
OTHER_SIZE3 = 0x4000
UC.mem_map(OTHER_BASE3, OTHER_SIZE3)
UC.mem_write(OTHER_BASE3, open("other3.dmp","rb").read())

#eqnedt
EQNEDT_BASE = 0x400000
EQNEDT_SIZE = 0x8e000
eqnedtdump = open("eqnedt32_full.dmp","rb").read()
UC.mem_map(EQNEDT_BASE, EQNEDT_SIZE)
UC.mem_write(EQNEDT_BASE, eqnedtdump)

#
UC.hook_add(UC_HOOK_CODE, hook_code)
#UC.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED|UC_ERR_WRITE_UNMAPPED|UC_ERR_FETCH_UNMAPPED|UC_ERR_READ_UNMAPPED, hook_mem_invalid)
UC.hook_add(UC_ERR_READ_UNMAPPED, hook_mem_invalid)

#
UC.reg_write(UC_X86_REG_ESP, 0x19ebcc)
UC.reg_write(UC_X86_REG_EBP, 0x2040074)
UC.reg_write(UC_X86_REG_ECX, 0x826629)
UC.reg_write(UC_X86_REG_EDI, 0x0)

get_func_addr(UC, KERNEL32_BASE, 0x90320)
get_func_addr(UC, URLMON_BASE, 0x120140)


try:
    #phase1 -> stop at 0x826503
    UC.emu_start(0x19ed54, 0x0)
    #phase2
    HEAP1_BASE = 0x7e0000
    HEAP1_SIZE = 0xe5000
    UC.mem_write(HEAP1_BASE,open("heap.dmp","rb").read())
    print("phase2 restart---------------------------------")
    UC.emu_start(0x826691, 0x0)
except UcError as e:
    print("================================================================")
    printRegs(UC)
    print("ERROR: %s" % e)

