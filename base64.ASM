format          PE console 4.0
entry           start


section         '.text' code readable executable
 
  start:
       ; call    [GetConsoleCP]
        push    0x4e3                      ;ANSI-1251
        call    [SetConsoleCP]
        push    0x4e3                      ;ANSI-1251
        call    [SetConsoleOutputCP]
       ; call    [GetConsoleOutputCP]
       ; call    [GetConsoleCP]
        push    0xfffffff6
        call    [GetStdHandle]       ;Read
        xchg    eax,ebx
        push    0xfffffff5
        call    [GetStdHandle]       ;Write
        push    eax
        mov     ecx, Write_Message
        mov     edx, 0x79

  repeats_1:                         ;repeat after -d or -e
        push    0
        push    GetLengthBuffer_W
        push    edx
        push    ecx
        push    eax
        call    [WriteConsoleA]
  repeats:
        push    0
        push    GetLengthBuffer_R
        push    0x10000              ;1mb
        push    data_in
        push    ebx
        call    [ReadConsoleA]
        push    ebx

        xor     eax,eax
        mov     edi, [GetLengthBuffer_R]
        add     edi, data_in-2
        stosd                           ;\r\n = 0x0000

        mov     eax, [GetLengthBuffer_R]
        sub     eax, 0x5
        mov     [GetLengthBuffer_R],eax
        push    eax

        mov     eax, dword [data_in]
        and     eax,0x00ffffff
        cmp     eax,0x712d        ;-q
        je      exit_programm
        cmp     eax,0x20652d      ;-e
        je      start_encryption
        cmp     eax,0x20642d      ;-d
        je      start_decryption
        pop     eax
        pop     ebx
        jmp     repeats           ;if console input without parameters

  start_decryption:
        mov     eax,[GetLengthBuffer_R]
        add     eax,data_in+1
        cmp     [eax],byte 0x3d
        jne     a_1
        mov     [eax],byte 0x41    ; '=' = 'A'
  a_1:
        inc     eax
        cmp     [eax],byte 0x3d
        jne     a_2
        mov     [eax],byte 0x41
  a_2:
        mov     esi,data_in+0x3
        mov     edi,data_out+0x2

  take_bytes_d:
        xor     ebx,ebx
        lodsd
        push    edi
        mov     ecx, 4

  find_equal_1:
        mov     edi, base64
  find_equal:
        scasb
        jne     find_equal
        sub     edi,base64+0x1
        or      bx, di
        shl     ebx,0x6
        shr     eax,0x8
        loop    find_equal_1
        shr     ebx,0x6
        pop     edi
        std
        mov     eax,ebx
        or      cx,0x3
  loop_3:
        stosb
        shr     eax,0x8
        loop    loop_3
        cld
        add     edi,0x6
        mov     eax,[esi]
        cmp     eax, 0x0
        jne     take_bytes_d
        sub     edi,0x4
        jmp     write_to_file      ;end of decryption

  start_encryption:
        mov    esi,data_in+0x3
        mov    edi,data_out+0x3
  take_bytes:
        lodsb
        rol    eax,0x8
        lodsb
        rol    eax,0x8
        lodsb
        std
        mov    ecx,0x4
        _insert_base:
        push   eax
        and    eax,0x3f
        or     eax,base64
        mov    bl,byte [eax]
        xchg   ebx,eax
        stosb
        pop    eax
        shr    eax,0x6
        loop   _insert_base
        add    edi,0x8
        cld
        pop    eax
        sub    eax,0x3
        push   eax
        je     if_null
        jns    take_bytes
  if_null:
        sub    edi,0x4
        cmp    byte [edi],0x41
        jne    a
        mov    byte [edi],0x3d
  a:
        dec    edi
        cmp    byte [edi],0x41
        jne    write_to_file
        mov    byte [edi],0x3d       ;stop_encryption

write_to_file:                       ;if you need out in file
       ;  pop    eax
       ;  push   0x0
       ;  push   0x80000000
       ;  push   0x2
       ;  push   0x0
       ;  push   0x0
       ;  push   0x10000000
       ;  push   file_out
       ;  call   [CreateFileA]
       ;  xchg   ebx,eax
       ;  sub    edi,(data_out-2)

       ;  push   0x0
       ;  push   0x0
       ;  push   edi
       ;  push   data_out
       ;  push   ebx
       ;  call   [WriteFile]

       ;  push   ebx
       ;  call   [CloseHandle]
        sub    edi,(data_out-2)       ;delete this string if you need to create file
        pop    eax                    ;and this one

        pop    ebx                    ;hsndle for ReadConsoleA
        pop    eax                    ;handle for WriteConsoleA
        push   eax
        mov    ecx,data_out           ;buffer
        add    edi,data_out
        mov    dword [edi],0x0d0a     ;\r\n
        sub    edi,data_out-2
        mov    edx,edi                ;how much bytes to write
        jmp    repeats_1

  exit_programm:
        push   0x0
        call   [ExitProcess]

 
section         '.data' data readable writeable
 
base64            db      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
file_out          db      'base64_out.txt',0
GetLengthBuffer_R dd      0
                  db      0
GetLengthBuffer_W dd      0
                  db      0
Write_Message     db      '-(d)ecrypt <text> to decrypt inputted text',0xD,0xA,'-(e)ncrypt <text> to encrypt inputted text',0xD,0xA,'-(q)uit to exit from programm',0xD,0xA,0xD,0xA

 
section '.idata' import data readable writeable

  dd 0,0,0,RVA kernel_name,RVA exitprocess_table
  dd 0,0,0,RVA kernel_name,RVA write_table
  dd 0,0,0,RVA kernel_name,RVA create_table
  dd 0,0,0,RVA kernel_name,RVA closehandle_table
  dd 0,0,0,RVA kernel_name,RVA GetStdHandle_table
  dd 0,0,0,RVA kernel_name,RVA WriteConsoleA_table
  dd 0,0,0,RVA kernel_name,RVA ReadConsoleA_table
  dd 0,0,0,RVA kernel_name,RVA GetConsoleOutputCP_table
  dd 0,0,0,RVA kernel_name,RVA SetConsoleOutputCP_table
  dd 0,0,0,RVA kernel_name,RVA GetConsoleCP_table
  dd 0,0,0,RVA kernel_name,RVA SetConsoleCP_table
  dd 0,0,0,0,0

  exitprocess_table:
    ExitProcess dd RVA _ExitProcess
    dd 0
  write_table:
    WriteFile dd RVA _WriteFile
    dd 0
  create_table:
    CreateFileA dd RVA _CreateFileA
    dd 0
  closehandle_table:
    CloseHandle dd RVA _CloseHandle
    dd 0
  GetStdHandle_table:
    GetStdHandle dd RVA _GetStdHandle
    dd 0
  WriteConsoleA_table:
    WriteConsoleA dd RVA _WriteConsoleA
    dd 0
  ReadConsoleA_table:
    ReadConsoleA dd RVA _ReadConsoleA
    dd 0
  GetConsoleOutputCP_table:
    GetConsoleOutputCP dd RVA _GetConsoleOutputCP
    dd 0
  SetConsoleOutputCP_table:
    SetConsoleOutputCP dd RVA _SetConsoleOutputCP
    dd 0
  GetConsoleCP_table:
    GetConsoleCP dd RVA _GetConsoleCP
    dd 0
  SetConsoleCP_table:
    SetConsoleCP dd RVA _SetConsoleCP
    dd 0

  kernel_name db 'KERNEL32.DLL',0

  _CreateFileA dw 0
    db 'CreateFileA',0
  _WriteFile dw 0
    db 'WriteFile',0
  _CloseHandle dw 0
    db 'CloseHandle',0
  _ExitProcess dw 0
    db 'ExitProcess',0
  _GetStdHandle dw 0
    db 'GetStdHandle',0
  _WriteConsoleA dw 0
    db 'WriteConsoleA',0
  _ReadConsoleA dw 0
    db 'ReadConsoleA',0
  _GetConsoleOutputCP dw 0
    db 'GetConsoleOutputCP',0
  _SetConsoleOutputCP dw 0
    db 'SetConsoleOutputCP',0
  _GetConsoleCP dw 0
    db 'GetConsoleCP',0
  _SetConsoleCP dw 0
    db 'SetConsoleCP',0

section         '.datout' data readable writeable

data_out         db      0
reserv1          rb      0x17000

section         '.datin' data readable writeable ;code data readable writeable executable shareable discardable

data_in        db      0
reserv2        rb      0xf000         ; 0xf000+0x1000 = 0x10000 RAM