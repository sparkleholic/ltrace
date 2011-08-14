#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <error.h>
#include <errno.h>

#include "common.h"

#ifdef __powerpc__
#include <sys/ptrace.h>
#endif

static void handle_signal(Event *event);
static void handle_exit(Event *event);
static void handle_exit_signal(Event *event);
static void handle_syscall(Event *event);
static void handle_arch_syscall(Event *event);
static void handle_sysret(Event *event);
static void handle_arch_sysret(Event *event);
static void handle_clone(Event *event);
static void handle_exec(Event *event);
static void handle_breakpoint(Event *event);
static void handle_new(Event *event);
static void remove_proc(Process *proc);

static void callstack_push_syscall(Process *proc, int sysnum);

static char * shortsignal(Process *proc, int signum);
static char * sysname(Process *proc, int sysnum);
static char * arch_sysname(Process *proc, int sysnum);

void
handle_event(Event *event) {
	debug(DEBUG_FUNCTION, "handle_event(pid=%d, type=%d)", event->proc ? event->proc->pid : -1, event->type);
	switch (event->type) {
	case EVENT_NONE:
		debug(1, "event: none");
		return;
	case EVENT_SIGNAL:
		debug(1, "event: signal (%s [%d])",
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_signal(event);
		return;
	case EVENT_EXIT:
		debug(1, "event: exit (%d)", event->e_un.ret_val);
		handle_exit(event);
		return;
	case EVENT_EXIT_SIGNAL:
		debug(1, "event: exit signal (%s [%d])",
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_exit_signal(event);
		return;
	case EVENT_SYSCALL:
		debug(1, "event: syscall (%s [%d])",
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_syscall(event);
		return;
	case EVENT_SYSRET:
		debug(1, "event: sysret (%s [%d])",
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_sysret(event);
		return;
	case EVENT_ARCH_SYSCALL:
		debug(1, "event: arch_syscall (%s [%d])",
				arch_sysname(event->proc, event->e_un.sysnum),
				event->e_un.sysnum);
		handle_arch_syscall(event);
		return;
	case EVENT_ARCH_SYSRET:
		debug(1, "event: arch_sysret (%s [%d])",
				arch_sysname(event->proc, event->e_un.sysnum),
				event->e_un.sysnum);
		handle_arch_sysret(event);
		return;
	case EVENT_CLONE:
		debug(1, "event: clone (%u)", event->e_un.newpid);
		handle_clone(event);
		return;
	case EVENT_EXEC:
		debug(1, "event: exec()");
		handle_exec(event);
		return;
	case EVENT_BREAKPOINT:
		debug(1, "event: breakpoint");
		handle_breakpoint(event);
		return;
	case EVENT_NEW:
		debug(1, "event: new process");
		handle_new(event);
		return;
	default:
		fprintf(stderr, "Error! unknown event?\n");
		exit(1);
	}
}

/* TODO */
static void *
address_clone(void * addr) {
	debug(DEBUG_FUNCTION, "address_clone(%p)", addr);
	return addr;
}

static void *
breakpoint_clone(void * bp) {
	return clone_breakpoint((Breakpoint *)bp);
}

typedef struct Pending_New Pending_New;
struct Pending_New {
	pid_t pid;
	Pending_New * next;
};
static Pending_New * pending_news = NULL;

static int
pending_new(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new(%d)", pid);

	p = pending_news;
	while (p) {
		if (p->pid == pid) {
			return 1;
		}
		p = p->next;
	}
	return 0;
}

static void
pending_new_insert(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new_insert(%d)", pid);

	p = malloc(sizeof(Pending_New));
	if (!p) {
		perror("malloc()");
		exit(1);
	}
	p->pid = pid;
	p->next = pending_news;
	pending_news = p;
}

static void
pending_new_remove(pid_t pid) {
	Pending_New *p, *pred;

	debug(DEBUG_FUNCTION, "pending_new_remove(%d)", pid);

	p = pending_news;
	if (p->pid == pid) {
		pending_news = p->next;
		free(p);
	} else {
		while (p) {
			if (p->pid == pid) {
				pred->next = p->next;
				free(p);
			}
			pred = p;
			p = p->next;
		}
	}
}

static void
handle_clone(Event * event) {
	Process *p;

	debug(DEBUG_FUNCTION, "handle_clone(pid=%d)", event->proc->pid);

	p = malloc(sizeof(Process));
	if (!p) {
		perror("malloc()");
		exit(1);
	}
	memcpy(p, event->proc, sizeof(Process));
	p->breakpoints = dict_clone(event->proc->breakpoints, address_clone, breakpoint_clone);
	p->pid = event->e_un.newpid;
	p->parent = event->proc;
	int i;
	for (i = 0; i < p->callstack_depth; ++i) {
		struct callstack_element * elem = &p->callstack[i];
		elem->data = callstack_element_copy_data(p, elem);
	}

	if (pending_new(p->pid)) {
		pending_new_remove(p->pid);
		if (p->breakpoint_being_enabled) {
			enable_breakpoint(p, p->breakpoint_being_enabled);
			p->breakpoint_being_enabled = NULL;
		}
		if (event->proc->state == STATE_ATTACHED && options.follow) {
			p->state = STATE_ATTACHED;
		} else {
			p->state = STATE_IGNORED;
		}
		continue_process(p->pid);
		p->next = list_of_processes;
		list_of_processes = p;
	} else {
		p->state = STATE_BEING_CREATED;
		p->next = list_of_processes;
		list_of_processes = p;
	}
	continue_process(event->proc->pid);
}

static void
handle_new(Event * event) {
	Process * proc;

	debug(DEBUG_FUNCTION, "handle_new(pid=%d)", event->e_un.newpid);

	proc = pid2proc(event->e_un.newpid);
	if (!proc) {
		pending_new_insert(event->e_un.newpid);
	} else {
		assert(proc->state == STATE_BEING_CREATED);
		if (proc->breakpoint_being_enabled) {
			enable_breakpoint(proc, proc->breakpoint_being_enabled);
			proc->breakpoint_being_enabled = NULL;
		}
		if (options.follow) {
			proc->state = STATE_ATTACHED;
		} else {
			proc->state = STATE_IGNORED;
		}
		continue_process(proc->pid);
	}
}

static char *
shortsignal(Process *proc, int signum) {
	static char *signalent0[] = {
#include "signalent.h"
	};
	static char *signalent1[] = {
#include "signalent1.h"
	};
	static char **signalents[] = { signalent0, signalent1 };
	int nsignals[] = { sizeof signalent0 / sizeof signalent0[0],
		sizeof signalent1 / sizeof signalent1[0]
	};

	debug(DEBUG_FUNCTION, "shortsignal(pid=%d, signum=%d)", proc->pid, signum);

	if (proc->personality > sizeof signalents / sizeof signalents[0])
		abort();
	if (signum < 0 || signum >= nsignals[proc->personality]) {
		return "UNKNOWN_SIGNAL";
	} else {
		return signalents[proc->personality][signum];
	}
}

static char *
sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *syscalent0[] = {
#include "syscallent.h"
	};
	static char *syscalent1[] = {
#include "syscallent1.h"
	};
	static char **syscalents[] = { syscalent0, syscalent1 };
	int nsyscals[] = { sizeof syscalent0 / sizeof syscalent0[0],
		sizeof syscalent1 / sizeof syscalent1[0]
	};

	debug(DEBUG_FUNCTION, "sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (proc->personality > sizeof syscalents / sizeof syscalents[0])
		abort();
	if (sysnum < 0 || sysnum >= nsyscals[proc->personality]) {
		sprintf(result, "SYS_%d", sysnum);
		return result;
	} else {
		sprintf(result, "SYS_%s",
			syscalents[proc->personality][sysnum]);
		return result;
	}
}

static char *
arch_sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *arch_syscalent[] = {
#include "arch_syscallent.h"
	};
	int nsyscals = sizeof arch_syscalent / sizeof arch_syscalent[0];

	debug(DEBUG_FUNCTION, "arch_sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (sysnum < 0 || sysnum >= nsyscals) {
		sprintf(result, "ARCH_%d", sysnum);
		return result;
	} else {
		sprintf(result, "ARCH_%s",
				arch_syscalent[sysnum]);
		return result;
	}
}

static void
handle_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (exiting && event->e_un.signum == SIGSTOP) {
		pid_t pid = event->proc->pid;
		disable_all_breakpoints(event->proc);
		untrace_pid(pid);
		remove_proc(event->proc);
		return;
	}
	if (event->proc->state != STATE_IGNORED && !options.no_signals) {
		output_line(event->proc, "--- %s (%s) ---",
				shortsignal(event->proc, event->e_un.signum),
				strsignal(event->e_un.signum));
	}
	continue_after_signal(event->proc->pid, event->e_un.signum);
}

static void
handle_exit(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit(pid=%d, status=%d)", event->proc->pid, event->e_un.ret_val);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ exited (status %d) +++",
				event->e_un.ret_val);
	}
	remove_proc(event->proc);
}

static void
handle_exit_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ killed by %s +++",
				shortsignal(event->proc, event->e_un.signum));
	}
	remove_proc(event->proc);
}

static void
remove_proc(Process *proc) {
	Process *tmp, *tmp2;

	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (list_of_processes == proc) {
		tmp = list_of_processes;
		list_of_processes = list_of_processes->next;
		free(tmp);
		return;
	}
	tmp = list_of_processes;
	while (tmp->next) {
		if (tmp->next == proc) {
			tmp2 = tmp->next;
			tmp->next = tmp->next->next;
			free(tmp2);
			continue;
		}
		tmp = tmp->next;
	}
}

static void
handle_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, event->e_un.sysnum);
		if (options.syscalls) {
			output_left(LT_TOF_SYSCALL, event->proc,
					sysname(event->proc, event->e_un.sysnum));
		}
		if (event->proc->breakpoints_enabled == 0) {
			enable_all_breakpoints(event->proc);
		}
	}
	continue_process(event->proc->pid);
}

static void
handle_exec(Event * event) {
	Process * proc = event->proc;
	pid_t saved_pid;

	debug(DEBUG_FUNCTION, "handle_exec(pid=%d)", proc->pid);
	if (proc->state == STATE_IGNORED) {
		untrace_pid(proc->pid);
		remove_proc(proc);
		return;
	}
	output_line(proc, "--- Called exec() ---");
	proc->mask_32bit = 0;
	proc->personality = 0;
	proc->arch_ptr = NULL;
	free(proc->filename);
	proc->filename = pid2name(proc->pid);
	saved_pid = proc->pid;
	proc->pid = 0;
	breakpoints_init(proc);
	proc->pid = saved_pid;
	proc->callstack_depth = 0;
	continue_process(proc->pid);
}

static void
handle_arch_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, 0xf0000 + event->e_un.sysnum);
		if (options.syscalls) {
			output_left(LT_TOF_SYSCALL, event->proc,
					arch_sysname(event->proc, event->e_un.sysnum));
		}
		if (event->proc->breakpoints_enabled == 0) {
			enable_all_breakpoints(event->proc);
		}
	}
	continue_process(event->proc->pid);
}

struct timeval current_time_spent;

void
calc_time_spent(Process *proc) {
	struct timeval tv;
	struct timezone tz;
	struct timeval diff;
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "calc_time_spent(pid=%d)", proc->pid);
	elem = &proc->callstack[proc->callstack_depth - 1];

	gettimeofday(&tv, &tz);

	diff.tv_sec = tv.tv_sec - elem->time_spent.tv_sec;
	if (tv.tv_usec >= elem->time_spent.tv_usec) {
		diff.tv_usec = tv.tv_usec - elem->time_spent.tv_usec;
	} else {
		diff.tv_sec++;
		diff.tv_usec = 1000000 + tv.tv_usec - elem->time_spent.tv_usec;
	}
	current_time_spent = diff;
}

static void
handle_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls) {
			output_right(LT_TOF_SYSCALLR, event->proc,
					sysname(event->proc, event->e_un.sysnum));
		}
		callstack_pop(event->proc);
	}
	continue_process(event->proc->pid);
}

static void
handle_arch_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls) {
			output_right(LT_TOF_SYSCALLR, event->proc,
					arch_sysname(event->proc, event->e_un.sysnum));
		}
		callstack_pop(event->proc);
	}
	continue_process(event->proc->pid);
}

#ifdef __powerpc__
void *get_count_register (Process *proc);
#endif

static void
handle_breakpoint(Event *event) {
	Breakpoint *sbp;

	debug(DEBUG_FUNCTION, "handle_breakpoint(pid=%d, addr=%p)", event->proc->pid, event->e_un.brk_addr);
	debug(2, "event: breakpoint (%p)", event->e_un.brk_addr);

#ifdef __powerpc__
	/* Need to skip following NOP's to prevent a fake function from being stacked.  */
	long stub_addr = (long) get_count_register(event->proc);
	Breakpoint *stub_bp = NULL;
	char nop_instruction[] = PPC_NOP;

	stub_bp = address2bpstruct (event->proc, event->e_un.brk_addr);

	if (stub_bp) {
		unsigned char *bp_instruction = stub_bp->orig_value;

		if (memcmp(bp_instruction, nop_instruction,
			    PPC_NOP_LENGTH) == 0) {
			if (stub_addr != (long) event->e_un.brk_addr) {
				set_instruction_pointer (event->proc, event->e_un.brk_addr + 4);
				continue_process(event->proc->pid);
				return;
			}
		}
	}
#endif
	if ((sbp = event->proc->breakpoint_being_enabled) != 0) {
		/* Reinsert breakpoint */
		continue_enabling_breakpoint(event->proc, sbp);
		event->proc->breakpoint_being_enabled = NULL;
		return;
	}

	sbp = address2bpstruct(event->proc, event->e_un.brk_addr);
	if (sbp != NULL) {
		SymBreakpoint * symbp;
		for (symbp = sbp->symbps; symbp != NULL; ) {
			/* Protect against removal during on_hit.  */
			SymBreakpoint * next = symbp->next;
			symbp_on_hit(symbp, sbp, event->proc);
			symbp = next;
		}
	}

	if (sbp != NULL) {
		continue_after_breakpoint(event->proc, sbp);
		return;
	}

	output_line(event->proc, "unexpected breakpoint at %p",
		    (void *)event->e_un.brk_addr);
	continue_process(event->proc->pid);
}

static void
callstack_push_syscall(Process *proc, int sysnum) {
	struct callstack_element elem = {};
	elem.is_syscall = 1;
	elem.c_un.syscall = sysnum;
	elem.return_addr = NULL;
	callstack_push(proc, &elem);
}
