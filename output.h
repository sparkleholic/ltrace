void output_line(Process *proc, char *fmt, ...);
void output_left(enum tof type, Process *proc, char *function_name);
void output_right(enum tof type, Process *proc, char *function_name);

void report_error(char const *file, unsigned line_no, char *fmt, ...);
void report_global_error(char *fmt, ...);
