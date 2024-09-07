#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "lib/string.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) - 1)

/* Map region identifier. */
typedef int off_t;
#define MAP_FAILED ((void *)NULL)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0 /* Successful execution. */
#define EXIT_FAILURE 1 /* Unsuccessful execution. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
	// TODO: Your implementation goes here.
	// printf("system call!\n");
	// printf("begin");

	int number = f->R.rax;
	// printf("number: %d", number); // 출력되는건 확인

	switch (number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		fork(f->R.rdi);
		break;
	case SYS_EXEC:
		halt();
		break;
	case SYS_WAIT:
		halt();
		break;
	case SYS_CREATE:
		halt();
		break;
	case SYS_REMOVE:
		halt();
		break;
	case SYS_OPEN:
		halt();
		break;
	case SYS_FILESIZE:
		halt();
		break;
	case SYS_READ:
		halt();
		break;
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		halt();
		break;
	case SYS_TELL:
		halt();
		break;
	case SYS_CLOSE:
		halt();
		break;

	default:
		break;
	}

	// thread_exit();
}

// power_off()를 호출해서 Pintos를 종료합니다.
void halt(void)
{
	power_off();
}

// 현재 동작중인 유저 프로그램을 종료합니다.
void exit(int status)
{
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->dying_status = status;
	// printf("exit(%d)", status);
	thread_exit();
}

/* THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제본인 새 프로세스를 만듭니다. */
pid_t fork(const char *thread_name)
{
	process_fork(thread_name, &thread_current()->tf);
}

/* 현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경됩니다. */
int exec(const char *file)
{
}

/* 자식 프로세스 (pid) 를 기다려서 자식의 종료 상태(exit status)를 가져옵니다. */
int wait(pid_t pid)
{
}

/*  file(첫 번째 인자)를 이름으로 하고 크기가 initial_size(두 번째 인자)인 새로운 파일을 생성합니다 */
bool create(const char *file, unsigned initial_size)
{
}

/* file(첫 번째)라는 이름을 가진 파일을 삭제합니다.  */
bool remove(const char *file)
{
}

/* file(첫 번째 인자)이라는 이름을 가진 파일을 엽니다. */
int open(const char *file)
{
}

/* fd(첫 번째 인자)로서 열려 있는 파일의 크기가 몇 바이트인지 반환합니다. */
int filesize(int fd)
{
}

/* buffer 안에 fd 로 열려있는 파일로부터 size 바이트를 읽습니다. */
int read(int fd, void *buffer, unsigned length)
{
}

/* buffer로부터 open file fd로 size 바이트를 적어줍니다. */
int write(int fd, const void *buffer, unsigned length)
{
	// strlcpy(fd, buffer, length);
	if (fd == 1)
		putbuf(buffer, length);
}

/* open file fd에서 읽거나 쓸 다음 바이트를 position으로 변경합니다. */
void seek(int fd, unsigned position)
{
}

/* 열려진 파일 fd에서 읽히거나 써질 다음 바이트의 위치를 반환합니다.  */
unsigned tell(int fd)
{
}

/* 파일 식별자 fd를 닫습니다. */
void close(int fd)
{
}

int dup2(int oldfd, int newfd)
{
}
