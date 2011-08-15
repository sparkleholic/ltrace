#include "config.h"

#if defined(HAVE_LIBUNWIND)
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <assert.h>

#include "common.h"

Process *
open_program(char *filename, pid_t pid) {
	Process *proc;
	assert(pid != 0);
	proc = calloc(sizeof(Process), 1);
	if (!proc) {
		perror("malloc");
		exit(1);
	}
	proc->filename = strdup(filename);
	proc->breakpoints_enabled = -1;
	proc->pid = pid;
#if defined(HAVE_LIBUNWIND)
	proc->unwind_priv = _UPT_create(pid);
	proc->unwind_as = unw_create_addr_space(&_UPT_accessors, 0);
#endif /* defined(HAVE_LIBUNWIND) */

	breakpoints_init(proc);

	proc->next = list_of_processes;
	list_of_processes = proc;

	return proc;
}

void
open_pid(pid_t pid) {
	Process *proc;
	char *filename;

	if (trace_pid(pid) < 0) {
		fprintf(stderr, "Cannot attach to pid %u: %s\n", pid,
			strerror(errno));
		return;
	}

	filename = pid2name(pid);

	if (!filename) {
		fprintf(stderr, "Cannot trace pid %u: %s\n", pid,
				strerror(errno));
		return;
	}

	proc = open_program(filename, pid);
	continue_process(pid);
	proc->breakpoints_enabled = 1;
}

Process *
pid2proc(pid_t pid) {
	Process *tmp;

	tmp = list_of_processes;
	while (tmp) {
		if (pid == tmp->pid) {
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}

TracePoint *
tracepoint_add(Process * proc, TracePoint * tp)
{
	TracePoint * ntp = malloc(sizeof(*tp));
	if (ntp == NULL) {
		error(0, errno, "tracepoint_add");
		return NULL;
	}
	*ntp = *tp;
	ntp->next = proc->tracepoints;
	proc->tracepoints = ntp;
	return ntp;
}

int
tracepoint_inst(TracePoint * self, Process * proc)
{
	assert(self->inst_cb != NULL);
	return self->inst_cb(self, proc);
}

void
tracepoint_free_data(TracePoint * self)
{
	if (self->free_data_cb != NULL)
		self->free_data_cb(self);
}

const char *
tracepoint_name(TracePoint * tp)
{
	/* Enough space for format string and three addrs.  */
	static char buf[14 + 3*(2*sizeof(void *) + 2)];
	const char * name = NULL;

	if (tp->name_cb != NULL)
		name = tp->name_cb(tp);

	if (name == NULL && tp->libsym != NULL)
		name = tp->libsym->name;

	/* As the last resort, we try to provide at least _some_ data
	 * that could be retrospectively used to identify what the
	 * tracepoint was.  */
	if (name == NULL) {
		if (sprintf(buf, "tracepoint %p-%p@%p",
			    tp->inst_cb, tp->data, tp) > 0)
			name = buf;
		else
			name = "???";
	}

	assert(name != NULL);
	return name;
}
