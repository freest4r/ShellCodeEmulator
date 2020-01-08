import struct
import string
import sys, binascii

def pop(em, esp):
    esp = em.mem_read(esp, 0x4)
    esp=struct.unpack("<I", esp)[0]
    return esp

def read_until_null(em, idx):
    ret = bytearray(b'')
    while True:
        c = em.mem_read(idx, 1)
        if c==b"\x00":
            break
        ret += c
        idx+=1
    return ret.decode('utf-8')

def read_until_doublenull(em, idx):
    ret = bytearray(b'')
    while True:
        c = em.mem_read(idx, 2)
        if c==b"\x00\x00":
            break
        ret += c
        idx+=2
    return ret.decode('utf-8').replace("\x00","")

#FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
#);
def hook_GetProcAddress(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    lpProcName = read_until_null(em, arg2)
    print("GetProcAddress(%x, %s)"%(arg1, lpProcName))

#HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
#);
def hook_LoadLibraryA(em, esp):
    arg1 = pop(em, esp+0x4)
    fname = read_until_null(em, arg1)
    print("LoadLibraryA(%s)"%(fname))

#HRESULT URLDownloadToFile(
#             LPUNKNOWN            pCaller,
#             LPCTSTR              szURL,
#             LPCTSTR              szFileName,
#  _Reserved_ DWORD                dwReserved,
#             LPBINDSTATUSCALLBACK lpfnCB
#);
def hook_URLDownloadToFileW(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    arg3 = pop(em, esp+0xc)
    arg4 = pop(em, esp+0x10)
    arg5 = pop(em, esp+0x14)
    url = read_until_doublenull(em, arg2)
    fname = read_until_doublenull(em, arg3)
    print("URLDownloadToFileW(%x, %s, %s, %x, %x)"%(arg1, url, fname, arg4, arg5))

