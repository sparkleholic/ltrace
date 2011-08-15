#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <error.h>

#ifdef __powerpc__
#include <sys/ptrace.h>
#endif

#include "common.h"

/*****************************************************************************/

Breakpoint *
address2bpstruct(Process *proc, void *addr) {
	debug(DEBUG_FUNCTION, "address2bpstruct(pid=%d, addr=%p)", proc->pid, addr);
	return dict_find_entry(proc->breakpoints, addr);
}

void
insert_breakpoint(Process *proc, void *addr, SymBreakpoint * symbp) {
	Breakpoint *sbp;
	struct library_symbol * libsym = symbp->libsym;

#ifdef __arm__
	int thumb_mode = (int)addr & 1;
	if (thumb_mode)
		addr = (void *)((int)addr & ~1);
#endif

	debug(DEBUG_FUNCTION, "insert_breakpoint(pid=%d, addr=%p, symbol=%s)", proc->pid, addr, libsym ? libsym->name : "NULL");
	debug(1, "symbol=%s, addr=%p", libsym?libsym->name:"(nil)", addr);

	if (!addr)
		return;

	if (libsym)
		libsym->needs_init = 0;

	sbp = dict_find_entry(proc->breakpoints, addr);
	if (!sbp) {
		sbp = calloc(1, sizeof(*sbp));
		if (!sbp) {
			int err;
		memerr:
			err = errno;
			free(sbp);
			error(0, err, "insert_breakpoint");
			return;
		}

		sbp->addr = addr;
		if (dict_enter(proc->breakpoints, sbp->addr, sbp))
			goto memerr;
	}

	symbp->next = sbp->symbps;
	sbp->symbps = symbp;

#ifdef __arm__
	sbp->thumb_mode = thumb_mode | proc->thumb_mode;
	proc->thumb_mode = 0;
#endif

	sbp->enabled++;
	if (sbp->enabled == 1 && proc->pid)
		enable_breakpoint(proc, sbp);
}

void
delete_breakpoint(Process *proc, void *addr) {
	Breakpoint *sbp;

	debug(DEBUG_FUNCTION, "delete_breakpoint(pid=%d, addr=%p)", proc->pid, addr);

	sbp = dict_find_entry(proc->breakpoints, addr);
	assert(sbp);		/* FIXME: remove after debugging has been done. */
	/* This should only happen on out-of-memory conditions. */
	if (sbp == NULL)
		return;

	/*
	while (sbp->symbps != NULL) {
		SymBreakpoint * tmp = sbp->symbps;
		sbp->symbps = tmp->next;
		sympb_destroy(tmp);
	}
	*/

	sbp->enabled--;
	if (sbp->enabled == 0)
		disable_breakpoint(proc, sbp);
	assert(sbp->enabled >= 0);
}

/* Find a name that can be used to describe the breakpoint.  */
const char *
breakpoint_name(const Breakpoint * bp)
{
	SymBreakpoint * symbp;

	if (bp != NULL)
		for (symbp = bp->symbps; symbp != NULL; symbp = symbp->next)
			if (symbp->libsym != NULL
			    && symbp->libsym->name != NULL)
				return symbp->libsym->name;

	return "(??""?)";
}

SymBreakpoint *
create_symbp(struct library_symbol * libsym,
	     const SymBreakpoint_Callbacks * cbs)
{
	SymBreakpoint * symbp = calloc(1, sizeof(*symbp));
	if (symbp == NULL)
		return NULL;
	symbp->libsym = libsym;
	symbp->cbs = cbs;
	return symbp;
}

void
delete_symbp(Process * proc, Breakpoint * bp, SymBreakpoint * symbp)
{
	SymBreakpoint * it, ** nextp = &bp->symbps;
	for (it = *nextp; it != NULL; it = *(nextp = &it->next)) {
		if (it == symbp) {
			*nextp = it->next;
			symbp_free_data(it);
			/*
			if (bp->symbps == NULL) {
				printf("last handler gone, deleting %p\n", bp->addr);
				delete_breakpoint(proc, bp->addr);
			}
			*/
			return;
		}
	}
	assert(0);
}

Breakpoint *
clone_breakpoint(const Breakpoint * bp) {
	Breakpoint * copy;
	int err;

	debug(DEBUG_FUNCTION, "breakpoint_clone(%p)", bp);
	copy = malloc(sizeof(*copy));
	if (copy == NULL) {
		err = errno;
	memerr:
		free(copy);
		error(1, errno, "clone_breakpoint");
	}
	memcpy(copy, bp, sizeof(*copy));

	copy->symbps = NULL;
	SymBreakpoint * symbp;
	for (symbp = bp->symbps; symbp != NULL; symbp = symbp->next) {
		SymBreakpoint * copy_symbp = malloc(sizeof(*copy_symbp));
		if (copy_symbp == NULL) {
			err = errno;
			for (copy_symbp = copy->symbps; copy_symbp != NULL; ) {
				SymBreakpoint * next = copy_symbp->next;
				free(copy_symbp);
				copy_symbp = next;
			}
			goto memerr;
		}

		memcpy(copy_symbp, symbp, sizeof(*copy_symbp));
		copy_symbp->data = symbp_copy_data(symbp);
		copy_symbp->next = copy->symbps;
		copy->symbps = copy_symbp;
	}

	return copy;
}

static void
enable_bp_cb(void *addr, void *sbp, void *proc) {
	debug(DEBUG_FUNCTION, "enable_bp_cb(pid=%d)", ((Process *)proc)->pid);
	if (((Breakpoint *)sbp)->enabled) {
		enable_breakpoint(proc, sbp);
	}
}

void
enable_all_breakpoints(Process *proc) {
	debug(DEBUG_FUNCTION, "enable_all_breakpoints(pid=%d)", proc->pid);
	if (proc->breakpoints_enabled <= 0) {
#ifdef __powerpc__
		unsigned long a;

		/*
		 * PPC HACK! (XXX FIXME TODO)
		 * If the dynamic linker hasn't populated the PLT then
		 * dont enable the breakpoints
		 */
		if (options.libcalls) {
			a = ptrace(PTRACE_PEEKTEXT, proc->pid,
				   sym2addr(proc, proc->list_of_symbols),
				   0);
			if (a == 0x0)
				return;
		}
#endif

		debug(1, "Enabling breakpoints for pid %u...", proc->pid);
		if (proc->breakpoints) {
			dict_apply_to_all(proc->breakpoints, enable_bp_cb,
					  proc);
		}
#ifdef __mips__
		{
			/*
			 * I'm sure there is a nicer way to do this. We need to
			 * insert breakpoints _after_ the child has been started.
			 */
			struct library_symbol *sym;
			struct library_symbol *new_sym;
			sym=proc->list_of_symbols;
			while(sym){
				void *addr= sym2addr(proc,sym);
				if(!addr){
					sym=sym->next;
					continue;
				}
				if(dict_find_entry(proc->breakpoints,addr)){
					sym=sym->next;
					continue;
				}
				debug(2,"inserting bp %p %s",addr,sym->name);
				new_sym=malloc(sizeof(*new_sym) + strlen(sym->name) + 1);
				memcpy(new_sym,sym,sizeof(*new_sym) + strlen(sym->name) + 1);
				new_sym->next=proc->list_of_symbols;
				proc->list_of_symbols=new_sym;
				insert_breakpoint(proc, addr, new_sym);
				sym=sym->next;
			}
		}
#endif
	}
	proc->breakpoints_enabled = 1;
}

static void
disable_bp_cb(void *addr, void *sbp, void *proc) {
	debug(DEBUG_FUNCTION, "disable_bp_cb(pid=%d)", ((Process *)proc)->pid);
	if (((Breakpoint *)sbp)->enabled) {
		disable_breakpoint(proc, sbp);
	}
}

void
disable_all_breakpoints(Process *proc) {
	debug(DEBUG_FUNCTION, "disable_all_breakpoints(pid=%d)", proc->pid);
	if (proc->breakpoints_enabled) {
		debug(1, "Disabling breakpoints for pid %u...", proc->pid);
		dict_apply_to_all(proc->breakpoints, disable_bp_cb, proc);
	}
	proc->breakpoints_enabled = 0;
}

static void
free_bp_cb(void *addr, void *sbp, void *data) {
	debug(DEBUG_FUNCTION, "free_bp_cb(sbp=%p)", sbp);
	assert(sbp);
	free(sbp);
}

struct return_reclev_t {
	struct return_reclev_t * next;
	int callstack_depth;
};

void callstack_pop(Process *proc);
void calc_time_spent(Process *proc);

static void
return_on_hit_cb(SymBreakpoint * symbp,
		 Breakpoint * bp, Process * proc)
{
	/* symbp->data contains recursion levels.  */
	if (symbp->data == NULL)
		return;

	/* XXX we need to remove the handler if this was the last
	 * recursion level.  This should also eventually lead to
	 * breakpoint removal.  */

#ifdef __powerpc__
			/*
			 * PPC HACK! (XXX FIXME TODO)
			 * The PLT gets modified during the first call,
			 * so be sure to re-enable the breakpoint.
			 */
			unsigned long a;
			struct library_symbol *libsym =
			    event->proc->callstack[i].c_un.libfunc;
			void *addr = sym2addr(event->proc, libsym);

			if (libsym->plt_type != LS_TOPLT_POINT) {
				unsigned char break_insn[] = BREAKPOINT_VALUE;

				sbp = address2bpstruct(event->proc, addr);
				assert(sbp);
				a = ptrace(PTRACE_PEEKTEXT, event->proc->pid,
					   addr);

				if (memcmp(&a, break_insn, BREAKPOINT_LENGTH)) {
					sbp->enabled--;
					// XXX rewrite
					insert_breakpoint(event->proc, addr,
							  libsym);
				}
			} else {
				sbp = dict_find_entry(event->proc->breakpoints, addr);
				/* On powerpc, the breakpoint address
				   may end up being actual entry point
				   of the library symbol, not the PLT
				   address we computed.  In that case,
				   sbp is NULL.  */
				if (sbp == NULL || addr != sbp->addr) {
					// XXX rewrite
					insert_breakpoint(event->proc, addr,
							  libsym);
				}
			}
#elif defined(__mips__)
			void *addr = NULL;
			struct library_symbol *sym= event->proc->callstack[i].c_un.libfunc;
			struct library_symbol *new_sym;
			assert(sym);
			addr=sym2addr(event->proc,sym);
			sbp = dict_find_entry(event->proc->breakpoints, addr);
			if (sbp) {
				if (addr != sbp->addr) {
					// XXX rewrite
					insert_breakpoint(event->proc, addr, sym);
				}
			} else {
				new_sym=malloc(sizeof(*new_sym) + strlen(sym->name) + 1);
				memcpy(new_sym,sym,sizeof(*new_sym) + strlen(sym->name) + 1);
				new_sym->next=event->proc->list_of_symbols;
				event->proc->list_of_symbols=new_sym;
				// XXX rewrite
				insert_breakpoint(event->proc, addr, new_sym);
			}
#endif

	struct return_reclev_t * reclev = symbp->data;
	int callstack_depth = reclev->callstack_depth;
	int j;
	for (j = proc->callstack_depth - 1; j > callstack_depth; j--)
		callstack_pop(proc);

	proc->return_addr = bp->addr;

	if (proc->state != STATE_IGNORED) {
		struct library_symbol * libsym
			= proc->callstack[callstack_depth].c_un.libsym;
		output_right(LT_TOF_FUNCTIONR, proc, libsym->name);
	}

	callstack_pop(proc);
}

static void
return_free_data_cb(SymBreakpoint * symbp)
{
	while (symbp->data != NULL) {
		struct return_reclev_t * reclev = symbp->data;
		symbp->data = reclev->next;
		free(reclev);
	}
}

static void *
return_copy_data_cb(SymBreakpoint * symbp)
{
	struct return_reclev_t * copy = NULL;
	struct return_reclev_t * it;
	for (it = symbp->data; it != NULL; it = it->next) {
		struct return_reclev_t * tmp = malloc(sizeof(*tmp));
		if (tmp == NULL) {
			error(0, errno, "probe_copy_data");
			for (tmp = copy; tmp != NULL; ) {
				it = tmp->next;
				free(tmp);
				tmp = it;
			}
			return NULL;
		}
		memcpy(tmp, it, sizeof(*tmp));
		tmp->next = copy;
		copy = tmp;
	}

	for (it = copy; it != NULL; ) {
		struct return_reclev_t * next = it->next;
		if (next != NULL)
			next->next = it;
		else
			copy = it;
		it = next;
	}

	return copy;
}

static SymBreakpoint_Callbacks return_symbp_callbacks = {
	.on_hit_cb = return_on_hit_cb,
	.free_data_cb = return_free_data_cb,
	.copy_data_cb = return_copy_data_cb,
};

static SymBreakpoint *
lookup_return_symbp(Breakpoint * bp)
{
	SymBreakpoint * symbp;
	if (bp != NULL)
		for (symbp = bp->symbps; symbp != NULL;
		     symbp = symbp->next)
			if (symbp->cbs == &return_symbp_callbacks)
				return symbp;
	return NULL;
}

static void
return_callstack_element_free_data(Process * proc,
				   struct callstack_element * elem)
{
	if (elem->return_addr == NULL)
		return;

	Breakpoint * bp = address2bpstruct(proc, elem->return_addr);
	SymBreakpoint * symbp = lookup_return_symbp(bp);

	/* Unchain one recursion level.  */
	struct return_reclev_t * reclev = symbp->data;
	symbp->data = reclev->next;
	free(reclev);

	/* Remove the handler, if this was the last recursion
	 * level.  */
	if (symbp->data == NULL)
		delete_symbp(proc, bp, symbp);
}

static void *
return_callstack_element_copy_data(Process * proc,
				   struct callstack_element * elem)
{
	assert(elem->data == NULL);
	return elem->data;
}

static void
callstack_push_pltbp(Process *proc,
		     SymBreakpoint * symbp, SymBreakpoint * ret_symbp)
{
	struct callstack_element elem = {};
	elem.is_syscall = 0;
	elem.return_addr = proc->return_addr;
	elem.c_un.libsym = symbp->libsym;
	elem.free_data_cb = &return_callstack_element_free_data;
	elem.copy_data_cb = &return_callstack_element_copy_data;
	callstack_push(proc, &elem);
}

static void
pltbp_on_hit_cb(SymBreakpoint * symbp, Breakpoint * bp, Process * proc)
{
	if (proc->state == STATE_IGNORED)
		return;

	void * sp;
	proc->stack_pointer = sp = get_stack_pointer(proc);
	proc->return_addr = get_return_addr(proc, sp);

	/* Create new return handler if there's no other.  */
	Breakpoint * ret_bp = address2bpstruct(proc, proc->return_addr);
	SymBreakpoint * ret_symbp = lookup_return_symbp(ret_bp);
	if (ret_symbp == NULL) {
		ret_symbp = create_symbp(symbp->libsym,
					 &return_symbp_callbacks);
		if (ret_symbp == NULL) {
			error(0, errno, "pltbp_on_hit_cb");
			return;
		}
		insert_breakpoint(proc, proc->return_addr, ret_symbp);
	}

	/* Chain on the new recursion level.  */
	struct return_reclev_t * reclev = malloc(sizeof(*reclev));
	reclev->callstack_depth = proc->callstack_depth;
	reclev->next = ret_symbp->data;
	ret_symbp->data = reclev;

	/* Push new callstack entry.  */
	callstack_push_pltbp(proc, symbp, ret_symbp);
	output_left(LT_TOF_FUNCTION, proc, symbp->libsym->name);

#ifdef PLT_REINITALISATION_BP
	if (proc->need_to_reinitialize_breakpoints
	    && (strcmp(symbp->libsym->name, PLTs_initialized_by_here) == 0))
		reinitialize_breakpoints(event->proc);
#endif
}

SymBreakpoint_Callbacks pltbp_symbp_callbacks = {
	.on_hit_cb = pltbp_on_hit_cb,
};

/* XXX should be hidden.  */
int
pltbp_tracepoint_inst(TracePoint * tp, Process * proc)
{
	SymBreakpoint * symbp
		= create_symbp(tp->libsym, &pltbp_symbp_callbacks);
	if (symbp == NULL) {
		error(0, errno, "pltbp_tracepoint_inst");
		return 0;
	}

	insert_breakpoint(proc, sym2addr(proc, tp->libsym), symbp);
	return 1;
}

static void
probe_on_hit_cb(SymBreakpoint * symbp, Breakpoint * bp, Process * proc)
{
	arg_type_info void_t = {
		ARGTYPE_VOID
	};
	Function prot = {
		.name = symbp->libsym->name,
		.return_info = &void_t,
		.num_params = 0,
		.arg_info = {},
		.params_right = 0,
		.next = NULL
	};
	output_left_prot(LT_TOF_NONE, proc, symbp->libsym->name, &prot);
	output_right_prot(LT_TOF_NONE, proc, symbp->libsym->name, &prot);
}

static void
probe_on_enable_cb(SymBreakpoint * symbp, Breakpoint * bp, Process * proc)
{
	/* Bump the probe semaphore.  */
	void * sema_addr = symbp->data;
	if (sema_addr != NULL) {
		uint16_t sema = 0;
		umovebytes(proc, sema_addr, &sema, sizeof(sema));
		++sema;
		ustorebytes(proc, sema_addr, &sema, sizeof(sema));
	}
}

static void
probe_on_disable_cb(SymBreakpoint * symbp, Breakpoint * bp, Process * proc)
{
	/* Decrease the probe semaphore.  */
	void * sema_addr = symbp->data;
	if (sema_addr != NULL) {
		uint16_t sema = 1;
		umovebytes(proc, sema_addr, &sema, sizeof(sema));
		--sema;
		ustorebytes(proc, sema_addr, &sema, sizeof(sema));
	}
}

SymBreakpoint_Callbacks probe_symbp_callbacks = {
	.on_hit_cb = probe_on_hit_cb,
	.on_enable_cb = probe_on_enable_cb,
	.on_disable_cb = probe_on_disable_cb,
};

/* XXX should be hidden.  */
int
probe_tracepoint_inst(TracePoint * tp, Process * proc)
{
	SymBreakpoint * symbp
		= create_symbp(tp->libsym, &probe_symbp_callbacks);
	if (symbp == NULL) {
		error(0, errno, "probe_tracepoint_inst");
		return 0;
	}

	/* Copy over the semaphore address.  */
	symbp->data = tp->data;

	/* XXX we don't call sym2addr here, because that's only
	 * relevant for PLT entries.  Really, that interface should be
	 * renamed to reflect that.  */
	insert_breakpoint(proc, tp->libsym->enter_addr, symbp);
	return 1;
}

void
breakpoints_init(Process *proc) {
	debug(DEBUG_FUNCTION, "breakpoints_init(pid=%d)", proc->pid);
	if (proc->breakpoints) {	/* let's remove that struct */
		dict_apply_to_all(proc->breakpoints, free_bp_cb, NULL);
		dict_clear(proc->breakpoints);
		proc->breakpoints = NULL;
	}
	proc->breakpoints = dict_init(dict_key2hash_int, dict_key_cmp_int);

	if (options.libcalls && proc->filename) {
		TracePoint * tp;
		for (tp = proc->tracepoints; tp != NULL; ) {
			TracePoint * next = tp->next;
			tracepoint_free_data(tp);
			free(tp);
			tp = next;
		}
		proc->tracepoints = NULL;

		/* FIXME: memory leak when called by exec(): */
		proc->list_of_symbols = read_elf(proc);
		if (opt_e) {
			struct library_symbol **tmp1 = &(proc->list_of_symbols);
			while (*tmp1) {
				struct opt_e_t *tmp2 = opt_e;
				int keep = !opt_e_enable;

				while (tmp2) {
					if (!strcmp((*tmp1)->name, tmp2->name)) {
						keep = opt_e_enable;
					}
					tmp2 = tmp2->next;
				}
				if (!keep) {
					*tmp1 = (*tmp1)->next;
				} else {
					tmp1 = &((*tmp1)->next);
				}
			}
		}
	} else {
		proc->list_of_symbols = NULL;
	}

	TracePoint * tp;
	for (tp = proc->tracepoints; tp != NULL; tp = tp->next)
		if (!tracepoint_inst(tp, proc))
			error(0, 0, "Can't trace %s", tracepoint_name(tp));

	proc->callstack_depth = 0;
	proc->breakpoints_enabled = -1;
}

void
reinitialize_breakpoints(Process *proc) {
	struct library_symbol *sym;

	debug(DEBUG_FUNCTION, "reinitialize_breakpoints(pid=%d)", proc->pid);

	sym = proc->list_of_symbols;

	puts("XXXXXXX reinitialize_breakpoints");
	/* This assumes that we have one breakpoint per address.  It
	 * needs to be adapted to the new world.  */

#if 0
	while (sym) {
		if (sym->needs_init) {
			insert_breakpoint(proc, sym2addr(proc, sym),
					  sym);
			if (sym->needs_init && !sym->is_weak) {
				fprintf(stderr,
					"could not re-initialize breakpoint for \"%s\" in file \"%s\"\n",
					sym->name, proc->filename);
				exit(1);
			}
		}
		sym = sym->next;
	}
#endif
}

void
symbp_on_hit(SymBreakpoint * self, Breakpoint * bp, Process * proc)
{
	if (self->cbs != NULL && self->cbs->on_hit_cb != NULL)
		self->cbs->on_hit_cb(self, bp, proc);
}

void
symbp_on_enable(SymBreakpoint * self, Breakpoint * bp, Process * proc)
{
	if (self->cbs != NULL && self->cbs->on_enable_cb != NULL)
		self->cbs->on_enable_cb(self, bp, proc);
}

void
symbp_on_disable(SymBreakpoint * self, Breakpoint * bp, Process * proc)
{
	if (self->cbs != NULL && self->cbs->on_disable_cb != NULL)
		self->cbs->on_disable_cb(self, bp, proc);
}

void
symbp_free_data(SymBreakpoint * self)
{
	if (self->cbs != NULL && self->cbs->free_data_cb != NULL)
		self->cbs->free_data_cb(self);
	free(self);
}

void *
symbp_copy_data(SymBreakpoint * self)
{
	if (self->cbs != NULL && self->cbs->copy_data_cb != NULL)
		return self->cbs->copy_data_cb(self);
	else
		return self->data;
}

void
callstack_element_free_data(Process * proc, struct callstack_element * self)
{
	if (self->free_data_cb != NULL)
		self->free_data_cb(proc, self);
}

void *
callstack_element_copy_data(Process * proc, struct callstack_element * self)
{
	if (self->copy_data_cb != NULL)
		return self->copy_data_cb(proc, self);
	else
		return self->data;
}

void
callstack_push(Process *proc, struct callstack_element * elem)
{
	debug(DEBUG_FUNCTION, "callstack_push(pid=%d)", proc->pid);

	/* FIXME: not good -- should use dynamic allocation. 19990703 mortene. */
	if (proc->callstack_depth == MAX_CALLDEPTH - 1) {
		fprintf(stderr, "%s: Error: call nesting too deep!\n", __func__);
		abort();
		return;
	}

	if (proc->state != STATE_IGNORED && (opt_T || options.summary)) {
		struct timezone tz;
		gettimeofday(&elem->time_spent, &tz);
	}

	proc->callstack[proc->callstack_depth++] = *elem;
}

void
callstack_pop(Process *proc) {
	struct callstack_element *elem;
	assert(proc->callstack_depth > 0);

	debug(DEBUG_FUNCTION, "callstack_pop(pid=%d)", proc->pid);

	if (proc->state != STATE_IGNORED && (opt_T || options.summary))
		calc_time_spent(proc);

	elem = &proc->callstack[--proc->callstack_depth];
	callstack_element_free_data(proc, elem);

	if (elem->arch_ptr != NULL) {
		free(elem->arch_ptr);
		elem->arch_ptr = NULL;
	}
}
