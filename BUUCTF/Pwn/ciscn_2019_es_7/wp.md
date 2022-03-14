虽然有mov rax 0x3b; ret和syscall的gadget，但是控制不了rdx，所以无法ret2syscall

这题是SROP吧？