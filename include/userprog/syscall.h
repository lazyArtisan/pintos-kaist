#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

int process_exec(void *f_name, int fd_idx);

#endif /* userprog/syscall.h */
