bits 16
org 0x8000

STATE   equ 0x0500
SEED    equ 0x0502
RKEY    equ 0x0506
CODEBUF equ 0x050a
CURS    equ 0x050e
PERM    equ 0x0510
INV     equ 0x0518
OFFX    equ 0x0520
OFFY    equ 0x0528
STORED  equ 0x1800
INTEN   equ 0x2000

XOFF    equ 32
FLAGROW equ 12

PLANES  equ panel_data + 18
GUARD   equ panel_data + 18 + 8192

_start:
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov sp, 0x7000
    sti

    mov ax, 0x0013
    int 0x10

    call set_palette
    call compute
    call draw_guard

    xor eax, eax
    mov [CODEBUF], eax
    mov word [CURS], 0

standby:
    call warm_frame
    call poll_key
    jmp standby

set_palette:
    mov dx, 0x3c8
    xor al, al
    out dx, al
    mov dx, 0x3c9
    xor cx, cx
.next:
    mov al, cl
    shr al, 2
    out dx, al
    out dx, al
    out dx, al
    inc cx
    cmp cx, 256
    jne .next
    ret

compute:
    mov eax, [SEED_SRC]
    mov [SEED], eax
    xor eax, 0x5bd1e995
    mov ecx, 0x9e3779b1
    imul eax, ecx
    mov ebx, eax
    shr ebx, 15
    xor eax, ebx
    mov ecx, 0x85ebca77
    imul eax, ecx
    mov ebx, eax
    shr ebx, 13
    xor eax, ebx
    mov [RKEY], eax

    mov ebx, eax
    shr ebx, 16
    xor eax, ebx
    and eax, 0xffff
    jnz .have
    mov ax, 0xbeef
.have:
    mov [STATE], ax

    xor bx, bx
.pinit:
    mov byte [PERM+bx], bl
    inc bx
    cmp bx, 8
    jne .pinit

    mov di, 7
.fy:
    call next_byte
    mov bx, di
    inc bx
    xor dx, dx
    div bx
    mov si, dx
    mov al, [PERM+di]
    mov bl, [PERM+si]
    mov [PERM+si], al
    mov [PERM+di], bl
    dec di
    jnz .fy

    xor di, di
.invl:
    call next_byte
    and al, 1
    mov [INV+di], al
    inc di
    cmp di, 8
    jne .invl

    xor di, di
.offl:
    call next_byte
    xor dx, dx
    mov bx, 5
    div bx
    sub dl, 2
    mov [OFFX+di], dl
    call next_byte
    xor dx, dx
    mov bx, 5
    div bx
    sub dl, 2
    mov [OFFY+di], dl
    inc di
    cmp di, 8
    jne .offl
    ret

next_byte:
    mov ax, [STATE]
    mov bx, ax
    shr bx, 15
    mov cx, ax
    shr cx, 13
    xor bx, cx
    mov cx, ax
    shr cx, 12
    xor bx, cx
    mov cx, ax
    shr cx, 10
    xor bx, cx
    and bx, 1
    shl ax, 1
    or ax, bx
    mov [STATE], ax
    and ax, 0xff
    ret

draw_guard:
    push es
    mov ax, 0xa000
    mov es, ax
    mov word [ROWV], 0
.row:
    xor dx, dx
.col:
    mov ax, dx
    shr ax, 3
    mov bx, [ROWV]
    shl bx, 5
    add bx, ax
    mov al, [GUARD+bx]
    mov cx, dx
    and cx, 7
    mov ah, 0x80
    shr ah, cl
    test al, ah
    mov al, 0
    jz .put
    mov al, 0xff
.put:
    mov di, [ROWV]
    imul di, di, 320
    add di, XOFF
    add di, dx
    mov [es:di], al
    inc dx
    cmp dx, 256
    jne .col
    mov ax, [ROWV]
    inc ax
    mov [ROWV], ax
    cmp ax, 8
    jne .row
    pop es
    ret

warm_frame:
    push es
    mov ax, 0xa000
    mov es, ax
    mov ax, [CURS]
    inc ax
    and ax, 7
    mov [CURS], ax
    shl ax, 10
    add ax, PLANES
    mov [WBASE], ax
    mov word [ROWV], 0
.wrow:
    xor dx, dx
.wcol:
    mov ax, dx
    shr ax, 3
    mov bx, [ROWV]
    shl bx, 5
    add bx, ax
    add bx, [WBASE]
    mov al, [bx]
    mov cx, dx
    and cx, 7
    mov ah, 0x80
    shr ah, cl
    test al, ah
    mov al, 0
    jz .wput
    mov al, 0xff
.wput:
    mov di, [ROWV]
    add di, FLAGROW
    imul di, di, 320
    add di, XOFF
    add di, dx
    mov [es:di], al
    inc dx
    cmp dx, 256
    jne .wcol
    mov ax, [ROWV]
    inc ax
    mov [ROWV], ax
    cmp ax, 32
    jne .wrow
    mov cx, 0x3000
.delay:
    dec cx
    jnz .delay
    pop es
    ret

poll_key:
    mov ah, 0x01
    int 0x16
    jz .none
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .enter
    call hexval
    jc .none
    mov ebx, [CODEBUF]
    shl ebx, 4
    and al, 0x0f
    movzx edx, al
    or ebx, edx
    mov [CODEBUF], ebx
.none:
    ret
.enter:
    mov eax, [CODEBUF]
    cmp eax, [RKEY]
    jne .reset
    call reconstruct
    call render_flag
.hang:
    hlt
    jmp .hang
.reset:
    xor eax, eax
    mov [CODEBUF], eax
    ret

hexval:
    cmp al, '0'
    jb .bad
    cmp al, '9'
    ja .alpha
    sub al, '0'
    clc
    ret
.alpha:
    or al, 0x20
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
    sub al, 'a'
    add al, 10
    clc
    ret
.bad:
    stc
    ret

reconstruct:
    mov di, INTEN
    mov cx, 8192
    xor al, al
.zloop:
    mov [di], al
    inc di
    dec cx
    jnz .zloop

    xor bp, bp
.splane:
    mov eax, ebp
    and eax, 0xff
    inc eax
    mov ecx, 0x01000193
    imul eax, ecx
    xor eax, [RKEY]
    mov [LCG], eax

    mov si, bp
    shl si, 10
    add si, PLANES
    xor bx, bx
.dxloop:
    mov eax, [LCG]
    mov ecx, 1664525
    imul eax, ecx
    add eax, 1013904223
    mov [LCG], eax
    shr eax, 24
    mov ah, al
    mov al, [si+bx]
    xor al, ah
    mov [STORED+bx], al
    inc bx
    cmp bx, 1024
    jne .dxloop

    movzx ax, byte [PERM+bp]
    mov [BITPOS], ax
    movsx ax, byte [OFFX+bp]
    mov [DXV], ax
    movsx ax, byte [OFFY+bp]
    mov [DYV], ax
    movzx ax, byte [INV+bp]
    mov [INVB], ax

    mov word [YY], 0
.yl:
    mov word [XX], 0
.xl:
    mov ax, [XX]
    add ax, [DXV]
    and ax, 0xff
    mov di, ax
    mov ax, [YY]
    add ax, [DYV]
    and ax, 31
    shl ax, 8
    add ax, di
    mov si, ax
    mov bx, si
    shr bx, 3
    mov al, [STORED+bx]
    mov bx, si
    and bx, 7
    mov cl, 7
    sub cl, bl
    shr al, cl
    xor al, byte [INVB]
    and al, 1
    jz .skip
    mov ax, [YY]
    shl ax, 8
    add ax, [XX]
    add ax, INTEN
    mov si, ax
    mov cl, byte [BITPOS]
    mov ah, 1
    shl ah, cl
    or [si], ah
.skip:
    mov ax, [XX]
    inc ax
    mov [XX], ax
    cmp ax, 256
    jne .xl
    mov ax, [YY]
    inc ax
    mov [YY], ax
    cmp ax, 32
    jne .yl

    inc bp
    cmp bp, 8
    jne .splane
    ret

render_flag:
    push es
    mov ax, 0xa000
    mov es, ax
    mov word [YY], 0
.rrow:
    mov word [XX], 0
.rcol:
    mov si, [YY]
    shl si, 8
    add si, [XX]
    add si, INTEN
    mov al, [si]
    mov di, [YY]
    add di, FLAGROW
    imul di, di, 320
    add di, XOFF
    add di, [XX]
    mov [es:di], al
    mov ax, [XX]
    inc ax
    mov [XX], ax
    cmp ax, 256
    jne .rcol
    mov ax, [YY]
    inc ax
    mov [YY], ax
    cmp ax, 32
    jne .rrow
    pop es
    ret

SEED_SRC equ panel_data + 12

LCG:    dd 0
DXV:     dw 0
DYV:     dw 0
BITPOS: dw 0
INVB:   dw 0
XX:     dw 0
YY:     dw 0
ROWV:   dw 0
WBASE:  dw 0

panel_data:
    incbin "paneldata.bin"
