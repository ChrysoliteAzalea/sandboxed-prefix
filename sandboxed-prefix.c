#define _GNU_SOURCE
#define USE_APPARMOR
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <string.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/landlock.h>
#ifdef USE_APPARMOR
#include <sys/apparmor.h>
#endif
#include <errno.h>
#include "ll_wrapper.h"
#include "add_rule.h"

void stop_error(int error_class) {
	if (error_class==1) {
		printf("Failed to add a syscall rule to the filter. Exiting...\n");
		exit(3);
	}
	if (error_class==2) {
		printf("Failed to add a path to the ruleset. Exiting...\n");
		exit(4);
	}
#ifdef USE_APPARMOR
	if (error_class==3) {
		printf("Failed to schedule an AppArmor profile transition. Exiting...\n");
		exit(5);
	}
#endif
	if (error_class==4) {
		printf("Failed to enable the \"No New Privileges\" restriction. Exiting...\n");
		exit(6);
	}
	if (error_class==5) {
		printf("Failed to enable Landlock self-restriction. Exiting...\n");
		exit(7);
	}
	if (error_class==6) {
		printf("Failed to load the seccomp filter to the kernel. Exiting...\n");
		exit(8);
	}
	printf("Unknown error. Exiting...\n");
	exit(1);
}

void populate_landlock_ruleset(int ruleset_fd) {
	int current_fd;
	current_fd = open("/sys",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	close(current_fd);
	current_fd = open("/run",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	if (add_write_access_rule(ruleset_fd,current_fd,1)!=0) stop_error(2);
	close(current_fd);
	current_fd = open("/usr",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	if (add_execute_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	close(current_fd);
	current_fd = open("/opt",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	if (add_execute_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	close(current_fd);
	current_fd = open("/run",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	if (add_write_access_rule(ruleset_fd,current_fd,0)!=0) stop_error(2);
	close(current_fd);
// Currently the entire /etc is accessible, should be more fine-grained later
	current_fd = open("/etc",O_PATH | O_CLOEXEC);
	if (add_read_access_rule(ruleset_fd,current_fd)!=0) stop_error(2);
	close(current_fd);
	return;
}

void populate_seccomp_filter(scmp_filter_ctx *filter) {
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(read),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(futex),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(poll),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(_newselect),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(select),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(pselect6),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clock_gettime),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(write),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(rt_sigprocmask),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(epoll_wait),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(nanosleep),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(recvmsg),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(writev),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(ioctl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getpid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getdents64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(lstat64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(lstat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(openat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(stat64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(close),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(epoll_ctl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fstat64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(mmap2),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(munmap),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(pread64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_yield),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(mprotect),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(_llseek),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(lseek),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(readlink),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(access),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sendmsg),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fstatfs),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fstatfs64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fcntl64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(recv),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(pipe2),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getxattr),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(unlink),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(madvise),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(waitpid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getrandom),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(readlinkat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(dup),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fadvise64_64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fadvise64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(tgkill),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fchdir),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(setsockopt),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(rt_sigaction),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(gettid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clone),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(set_robust_list),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(socket),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(brk),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(set_thread_area),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(rt_sigreturn),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sigaltstack),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_setaffinity),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(connect),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(socketpair),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(uname),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sysinfo),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(pipe),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(ftruncate64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(send),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(kill),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(prctl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getuid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sendto),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getsockname),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(prlimit64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(umask),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(geteuid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getegid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(time),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(ftruncate),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(memfd_create),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getgid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clock_getres),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(pwrite64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getpeername),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(mkdir),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(shmget),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(chdir),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(open),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(shmat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(bind),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(ugetrlimit),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(set_tid_address),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(accept),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(shutdown),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getcwd),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fstatat64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(dup2),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getsockopt),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(shmdt),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(shmctl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getresuid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getresuid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getresgid32),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getresgid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(timerfd_create),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(execve),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_setscheduler),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_get_priority_max),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_get_priority_min),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sched_getaffinity),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(chmod),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(rename),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(setsid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(symlink),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(epoll_create),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(listen),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(utimensat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(wait4),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(removexattr),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getppid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(sigreturn),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(faccessat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(faccessat2),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(exit),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(gettimeofday),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(restart_syscall),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fsync),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fdatasync),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(recvfrom),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(times),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fstat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(stat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getuid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(geteuid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getgid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getegid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(getppid),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(mmap),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fcntl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(arch_prctl),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clock_getres_time64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clock_nanosleep_time64),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clock_nanosleep),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(newfstatat),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(statx),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(rseq),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(fork),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clone),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(clone3),0)!=0) stop_error(1);
	if (seccomp_rule_add(*filter,SCMP_ACT_ALLOW,SCMP_SYS(ptrace),0)!=0) stop_error(1);
	return;
}

int main(int argc,char *argv[]) {
	if (argc<2) {
#ifdef USE_APPARMOR
		printf("Usage: wine-sandbox [--allow-syscall=<syscall>] [--allow-log-syscall=<syscall>] [--disallow-syscall-silent=<syscall>] [--disallow-syscall-failure=<syscall>] [--disallow-syscall-kill=<syscall>] [--allow-path=<path>] [--allow-read-only=<path>] [--wine-binary=<path>] [--apparmor=<profile>] <command-line arguments for Wine>\n");
#endif
#ifndef USE_APPARMOR
		printf("Usage: wine-sandbox [--allow-syscall=<syscall>] [--allow-log-syscall=<syscall>] [--disallow-syscall-silent=<syscall>] [--disallow-syscall-failure=<syscall>] [--disallow-syscall-kill=<syscall>] [--allow-path=<path>] [--allow-read-only=<path>] [--wine-binary=<path>] <command-line arguments for Wine>\n");
#endif
		return 2;
	}
	uint32_t d_action;
	char *find_mode=secure_getenv("SECCOMP_MODE");
	if (find_mode!=NULL && strncmp(find_mode,"SILENT",6)==0) d_action=SCMP_ACT_ERRNO(0);
	else if (find_mode!=NULL && strncmp(find_mode,"ERROR",5)==0) d_action=SCMP_ACT_ERRNO(-EDEADLOCK);
	else if (find_mode!=NULL && strncmp(find_mode,"LOG",3)==0) d_action=SCMP_ACT_LOG;
	else d_action=SCMP_ACT_KILL;
	scmp_filter_ctx syscall_filter = seccomp_init(d_action);
	unsetenv("SECCOMP_MODE");
	struct landlock_ruleset_attr current_attr;
	current_attr.handled_access_fs = 8191;
	seccomp_arch_add(syscall_filter,SCMP_ARCH_X86);
	int path_ruleset = landlock_create_ruleset(&current_attr,sizeof(current_attr),0);
	char *new_arg[argc];
	new_arg[0] = "wine\0";
	int new_arg_count = 1;
	int def_bin = 1;
	int bin_arg = -1;
	int opt_nnp = 1;
	int opt_seccomp = 1;
	int opt_landlock = 1;
	char wine_bin[50] = "/usr/bin/wine";
	populate_landlock_ruleset(path_ruleset);
	populate_seccomp_filter(&syscall_filter);
	for (int i=1;i<argc;i++) {
		if (strncmp(argv[i],"--allow-syscall=",16)==0) {
			if (seccomp_rule_add(syscall_filter,SCMP_ACT_ALLOW,seccomp_syscall_resolve_name(&argv[i][16]),0)!=0) stop_error(1);
		}
		else if (strncmp(argv[i],"--allow-log-syscall=",20)==0) {
			if (seccomp_rule_add(syscall_filter,SCMP_ACT_LOG,seccomp_syscall_resolve_name(&argv[i][16]),0)!=0) stop_error(1);
		}
		else if (strncmp(argv[i],"--disallow-syscall-silent=",26)==0) {
			if (seccomp_rule_add(syscall_filter,SCMP_ACT_ERRNO(0),seccomp_syscall_resolve_name(&argv[i][16]),0)!=0) stop_error(1);
		}
		else if (strncmp(argv[i],"--disallow-syscall-failure=",27)==0) {
			if (seccomp_rule_add(syscall_filter,SCMP_ACT_ERRNO(-EDEADLOCK),seccomp_syscall_resolve_name(&argv[i][16]),0)!=0) stop_error(1);
		}
		else if (strncmp(argv[i],"--disallow-syscall-kill=",24)==0) {
			if (seccomp_rule_add(syscall_filter,SCMP_ACT_KILL,seccomp_syscall_resolve_name(&argv[i][16]),0)!=0) stop_error(1);
		}
		else if (strncmp(argv[i],"--allow-path=",13)==0) {
			int temp_fd = open(&argv[i][13],O_PATH | O_CLOEXEC);
			if (add_read_access_rule(path_ruleset,temp_fd)!=0) stop_error(2);
			if (add_write_access_rule(path_ruleset,temp_fd,1)!=0) stop_error(2);
			close(temp_fd);
		}
		else if (strncmp(argv[i],"--allow-read-only-path=",21)==0) {
			int temp_fd = open(&argv[i][21],O_PATH | O_CLOEXEC);
			if (add_read_access_rule(path_ruleset,temp_fd)!=0) stop_error(2);
			close(temp_fd);
		}
		else if (strncmp(argv[i],"--wine-binary=",14)==0) {
			def_bin = 0;
			bin_arg = i;
		}
		else if (strncmp(argv[i],"--skip-nnp",11)==0) {
			opt_nnp = 0;
		}
		else if (strncmp(argv[i],"--skip-seccomp",15)==0) {
			opt_seccomp = 0;
		}
		else if (strncmp(argv[i],"--skip-landlock",16)==0) {
			opt_landlock = 0;
		}
#ifdef USE_APPARMOR
		else if (strncmp(argv[i],"--apparmor=",11)==0) {
			if (aa_stack_onexec(argv[11])!=0) stop_error(3);
		}
#endif
		else {
			new_arg[new_arg_count]=argv[i];
			new_arg_count++;
		}
	}
//	printf("%d\n",argc);
	new_arg[new_arg_count+1] = NULL;
// Debug code
//	for (int i=0;i<new_arg_count;i++) printf("%s\n",new_arg[i]);
	if (opt_nnp == 1) {
		if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0) stop_error(4);
	}
	if (opt_landlock == 1) {
		if (landlock_restrict_self(path_ruleset,0)!=0) stop_error(5);
	}
	if (opt_seccomp == 1) {
		if (seccomp_load(syscall_filter)!=0) stop_error(6);
	}
	if (def_bin==1) execve(wine_bin,new_arg,environ);
	else execve(argv[bin_arg][14],new_arg,environ);
	stop_error(7);
	return 124;
}
