bits 16
org 0x7c00

start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    mov [drive], dl

    mov ah, 0x02
    mov al, 63
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov dl, [drive]
    mov bx, 0x8000
    int 0x13
    jc halt

    jmp 0x0000:0x8000

halt:
    hlt
    jmp halt

drive: db 0

times 510-($-$$) db 0
dw 0xaa55
