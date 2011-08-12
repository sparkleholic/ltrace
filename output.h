void output_line(Process *proc, char *fmt, ...);
void output_left(enum tof type, Process *proc, const char *function_name);
void output_left_prot(enum tof type, Process *proc, const char *function_name,
		      Function * function);
void output_right(enum tof type, Process *proc, const char *function_name);
void output_right_prot(enum tof type, Process *proc, const char *function_name,
		       Function * function);
