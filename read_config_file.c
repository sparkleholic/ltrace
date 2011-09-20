#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "common.h"

static int line_no;
static char *filename;

static arg_type_info *parse_type(char **str);

Function *list_of_functions = NULL;

/* Map of strings to type names. These do not need to be in any
 * particular order */
static struct list_of_pt_t {
	char *name;
	enum arg_type pt;
} list_of_pt[] = {
	{
	"void", ARGTYPE_VOID}, {
	"int", ARGTYPE_INT}, {
	"uint", ARGTYPE_UINT}, {
	"long", ARGTYPE_LONG}, {
	"ulong", ARGTYPE_ULONG}, {
	"octal", ARGTYPE_OCTAL}, {
	"char", ARGTYPE_CHAR}, {
	"short", ARGTYPE_SHORT}, {
	"ushort", ARGTYPE_USHORT}, {
	"float", ARGTYPE_FLOAT}, {
	"double", ARGTYPE_DOUBLE}, {
	"addr", ARGTYPE_ADDR}, {
	"file", ARGTYPE_FILE}, {
	"format", ARGTYPE_FORMAT}, {
	"string", ARGTYPE_STRING}, {
	"array", ARGTYPE_ARRAY}, {
	"struct", ARGTYPE_STRUCT}, {
	"enum", ARGTYPE_ENUM}, {
	NULL, ARGTYPE_UNKNOWN}	/* Must finish with NULL */
};

/* Array of prototype objects for each of the types. The order in this
 * array must exactly match the list of enumerated values in
 * common.h */
static arg_type_info arg_type_prototypes[] = {
	{ ARGTYPE_VOID },
	{ ARGTYPE_INT },
	{ ARGTYPE_UINT },
	{ ARGTYPE_LONG },
	{ ARGTYPE_ULONG },
	{ ARGTYPE_OCTAL },
	{ ARGTYPE_CHAR },
	{ ARGTYPE_SHORT },
	{ ARGTYPE_USHORT },
	{ ARGTYPE_FLOAT },
	{ ARGTYPE_DOUBLE },
	{ ARGTYPE_ADDR },
	{ ARGTYPE_FILE },
	{ ARGTYPE_FORMAT },
	{ ARGTYPE_STRING },
	{ ARGTYPE_STRING_N },
	{ ARGTYPE_ARRAY },
	{ ARGTYPE_ENUM },
	{ ARGTYPE_STRUCT },
	{ ARGTYPE_POINTER },
	{ ARGTYPE_UNKNOWN }
};

arg_type_info *
lookup_prototype(enum arg_type at) {
	if (at >= 0 && at <= ARGTYPE_COUNT)
		return &arg_type_prototypes[at];
	else
		return &arg_type_prototypes[ARGTYPE_COUNT]; /* UNKNOWN */
}

static arg_type_info *
str2type(char **name) {
	struct list_of_pt_t *tmp;
	for (tmp = &list_of_pt[0]; tmp->name != NULL; ++tmp) {
		size_t tmp_len = strlen(tmp->name);
		if (strncmp(*name, tmp->name, tmp_len) == 0) {
			char next = (*name)[tmp_len];
			if (next == 0 || index(" ,()#*;012345[", next) != 0) {
				*name += tmp_len;
				return lookup_prototype(tmp->pt);
			}
		}
	}
	return NULL;
}

static void
eat_spaces(char **str) {
	while (**str == ' ') {
		(*str)++;
	}
}

static char *
xstrndup(char *str, size_t len)
{
	char *ret = (char *)malloc(len + 1);
	if (ret == NULL) {
		report_global_error("malloc: %s", strerror(errno));
		return NULL;
	}
	strncpy(ret, str, len);
	ret[len] = 0;
	return ret;
}

static char *
parse_ident(char **str) {
	char *ident = *str;

	if (!isalpha(**str) && **str != '_') {
		puts(*str);
		report_error(filename, line_no, "bad identifier");
		return NULL;
	}

	while (**str && (isalnum(**str) || **str == '_')) {
		++(*str);
	}

	/* N.B. xstrndup reports errors.  */
	return xstrndup(ident, *str - ident);
}

/*
  Returns position in string at the left parenthesis which starts the
  function's argument signature. Returns NULL on error.
*/
static char *
start_of_arg_sig(char *str) {
	char *pos;
	int stacked = 0;

	if (!strlen(str))
		return NULL;

	pos = &str[strlen(str)];
	do {
		pos--;
		if (pos < str)
			return NULL;
		while ((pos > str) && (*pos != ')') && (*pos != '('))
			pos--;

		if (*pos == ')')
			stacked++;
		else if (*pos == '(')
			stacked--;
		else
			return NULL;

	} while (stacked > 0);

	return (stacked == 0) ? pos : NULL;
}

static int
parse_int(char **str, long *ret)
{
	char *end;
	long n = strtol(*str, &end, 0);
	if (end == *str) {
		report_error(filename, line_no, "bad number");
		return -1;
	}

	*str = end;
	if (ret != NULL)
	    *ret = n;
	return 0;
}

static int
check_nonnegative(long l)
{
	if (l < 0) {
		report_error(filename, line_no,
			     "expected non-negative value, got %ld", l);
		return -1;
	}
	return 0;
}

static void
arg_expr_init_const(arg_expr_t *ret, size_t value)
{
	ret->kind = ARGEXPR_CONST;
	ret->u.value = value;
}

/*
 * Input:
 *  argN   : The value of argument #N, counting from 1 (arg0 = retval)
 *  eltN   : The value of element #N of the containing structure
 *  retval : The return value
 *  0      : Error
 *  N      : The numeric value N, if N > 0
 *
 * Output:
 * > 0   actual numeric value
 * = 0   return value
 * < 0   (arg -n), counting from one
 */
static int
parse_argnum(char **str, arg_expr_t *ret)
{
	if (isdigit(**str)) {
		long l;
		if (parse_int(str, &l) < 0
		    || check_nonnegative(l) < 0)
			return -1;
		arg_expr_init_const(ret, (unsigned long)l);

	} else {
		char *name = parse_ident(str);
		if (name == NULL)
			return -1;

		if (strcmp(name, "zero") == 0) {
			ret->kind = ARGEXPR_ZERO;
		} else {
			ret->kind = ARGEXPR_REF;
			ret->u.ref_name = name;
		}
	}

	return 0;
}

struct typedef_node_t {
	char *name;
	arg_type_info *info;
	struct typedef_node_t *next;
} *typedefs = NULL;

static arg_type_info *
lookup_typedef(char **str) {
	struct typedef_node_t *node;
	char *end = *str;
	while (*end && (isalnum(*end) || *end == '_'))
		++end;
	if (end == *str)
		return NULL;

	for (node = typedefs; node != NULL; node = node->next) {
		if (strncmp(*str, node->name, end - *str) == 0) {
			(*str) += strlen(node->name);
			return node->info;
		}
	}

	return NULL;
}

static void
parse_typedef(char **str) {
	char *name;
	arg_type_info *info;
	struct typedef_node_t *binding;

	(*str) += strlen("typedef");
	eat_spaces(str);

	// Grab out the name of the type
	name = parse_ident(str);
	if (name == NULL)
		return;

	// Skip = sign
	eat_spaces(str);
	if (**str != '=') {
		report_error(filename, line_no,
			     "expected '=', got '%c'", **str);
		return;
	}
	(*str)++;
	eat_spaces(str);

	// Parse the type
	info = parse_type(str);

	// Insert onto beginning of linked list
	binding = malloc(sizeof(*binding));
	binding->name = name;
	binding->info = info;
	binding->next = typedefs;
	typedefs = binding;
}

static size_t
arg_sizeof(arg_type_info * arg) {
	switch (arg->type) {
	case ARGTYPE_CHAR:
		return sizeof(char);
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return sizeof(short);
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_OCTAL:
		return sizeof(int);
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
		return sizeof(long);
	case ARGTYPE_FLOAT:
		return sizeof(float);
	case ARGTYPE_DOUBLE:
		return sizeof(double);
	case ARGTYPE_ENUM:
		return sizeof(int);
	case ARGTYPE_STRUCT:
		return arg->u.struct_info.size;

	case ARGTYPE_ARRAY:
		if (arg->u.info.len_spec.kind == ARGEXPR_CONST)
			return arg->u.info.len_spec.u.value
				* arg->u.info.elt_size;
		/* fall-through */
	case ARGTYPE_POINTER:
	case ARGTYPE_ADDR:
	case ARGTYPE_FILE:
	case ARGTYPE_STRING:
	case ARGTYPE_STRING_N:
	case ARGTYPE_FORMAT:
		return sizeof(void*);

	case ARGTYPE_UNKNOWN:
		assert (arg->type != ARGTYPE_UNKNOWN);
	case ARGTYPE_VOID:
		assert (arg->type != ARGTYPE_VOID);
	case ARGTYPE_COUNT:
		assert (arg->type != ARGTYPE_COUNT);
	};
	abort ();
}

#undef alignof
#define alignof(field,st) ((size_t) ((char*) &st.field - (char*) &st))
static size_t
arg_align(arg_type_info * arg) {
	struct { char c; char C; } cC;
	struct { char c; short s; } cs;
	struct { char c; int i; } ci;
	struct { char c; long l; } cl;
	struct { char c; void* p; } cp;
	struct { char c; float f; } cf;
	struct { char c; double d; } cd;

	static size_t char_alignment = alignof(C, cC);
	static size_t short_alignment = alignof(s, cs);
	static size_t int_alignment = alignof(i, ci);
	static size_t long_alignment = alignof(l, cl);
	static size_t ptr_alignment = alignof(p, cp);
	static size_t float_alignment = alignof(f, cf);
	static size_t double_alignment = alignof(d, cd);

	switch (arg->type) {
		case ARGTYPE_LONG:
		case ARGTYPE_ULONG:
			return long_alignment;
		case ARGTYPE_CHAR:
			return char_alignment;
		case ARGTYPE_SHORT:
		case ARGTYPE_USHORT:
			return short_alignment;
		case ARGTYPE_FLOAT:
			return float_alignment;
		case ARGTYPE_DOUBLE:
			return double_alignment;
		case ARGTYPE_ADDR:
		case ARGTYPE_FILE:
		case ARGTYPE_FORMAT:
		case ARGTYPE_STRING:
		case ARGTYPE_STRING_N:
		case ARGTYPE_POINTER:
			return ptr_alignment;

		case ARGTYPE_ARRAY:
			return arg_align(&arg->u.info.type[0]);

		case ARGTYPE_STRUCT:
			return arg_align(arg->u.struct_info.fields[0]);

		default:
			return int_alignment;
	}
}

static size_t
align_skip(size_t alignment, size_t offset) {
	if (offset % alignment)
		return alignment - (offset % alignment);
	else
		return 0;
}

/* I'm sure this isn't completely correct, but just try to get most of
 * them right for now. */
static void
align_struct(arg_type_info* info) {
	size_t offset;
	size_t i;

	if (info->u.struct_info.size != 0)
		return;			// Already done

	// Compute internal padding due to alignment constraints for
	// various types.
	offset = 0;
	for (i = 0; i < info->u.struct_info.num_fields; i++) {
		arg_type_info *field = info->u.struct_info.fields[i];
		offset += align_skip(arg_align(field), offset);
		info->u.struct_info.offset[i] = offset;
		offset += arg_sizeof(field);
	}

	info->u.struct_info.size = offset;
}

static void
destroy_type(arg_type_info *info)
{
	size_t i;

	if (info == NULL)
		return;

	if (!info->is_clone)
		switch (info->type) {
		case ARGTYPE_ENUM:
			free(info->u.enum_info.keys);
			free(info->u.enum_info.values);
			break;

		case ARGTYPE_STRUCT:
			for (i = 0; i < info->u.struct_info.num_fields; ++i)
				destroy_type(info->u.struct_info.fields[i]);
			free(info->u.struct_info.fields);
			free(info->u.struct_info.offset);
			break;

		case ARGTYPE_ARRAY:
		case ARGTYPE_POINTER:
			destroy_type(info->u.info.type);
			break;

		case ARGTYPE_VOID:
		case ARGTYPE_INT:
		case ARGTYPE_UINT:
		case ARGTYPE_LONG:
		case ARGTYPE_ULONG:
		case ARGTYPE_OCTAL:
		case ARGTYPE_CHAR:
		case ARGTYPE_SHORT:
		case ARGTYPE_USHORT:
		case ARGTYPE_FLOAT:
		case ARGTYPE_DOUBLE:
		case ARGTYPE_ADDR:
		case ARGTYPE_FILE:
		case ARGTYPE_FORMAT:
		case ARGTYPE_STRING:
		case ARGTYPE_STRING_N:
			break;

		case ARGTYPE_UNKNOWN:
			assert(info->type != ARGTYPE_UNKNOWN);
		case ARGTYPE_COUNT:
			assert(info->type != ARGTYPE_COUNT);
		}

	free(info);
}

static void
destroy_fun(Function *fun)
{
	size_t i;
	if (fun == NULL)
		return;
	destroy_type(fun->return_info);
	for (i = 0; i < fun->num_params; ++i)
		destroy_type(fun->param_info[i]);
}

static int
parse_array(char **str, arg_type_info *info)
{
	(*str)++;		// Get past open paren
	eat_spaces(str);
	if ((info->u.info.type = parse_type(str)) == NULL) {
	err:
		free(info);
		return -1;
	}
	info->u.info.elt_size =
		arg_sizeof(info->u.info.type);
	(*str)++;		// Get past comma
	eat_spaces(str);
	int st = parse_argnum(str, &info->u.info.len_spec);
	(*str)++;		// Get past close paren
	if (st < 0)
		goto err;
	return 0;
}

static int
parse_struct(char **str, arg_type_info *info)
{
	(*str)++;        // Get past open paren
	eat_spaces(str); // Empty arg list with whitespace inside

	size_t allocd = 0;
	info->u.struct_info.fields = NULL;
	info->u.struct_info.offset = NULL;
	info->u.struct_info.size = 0;
	info->u.struct_info.num_fields = 0;

#define SI u.struct_info

	while (**str && **str != ')') {
		eat_spaces(str);
		if (info->SI.num_fields != 0) {
			(*str)++;	// Get past comma
			eat_spaces(str);
		}

		/* Make space for next field.  */
		if (info->u.struct_info.num_fields >= allocd) {
			allocd = allocd > 0 ? 2 * allocd : 4;
			void *nf, *no;

			nf = realloc(info->SI.fields,
				     sizeof(*info->SI.fields) * allocd);
			if (nf == NULL) {
			err:
				destroy_type(info);
				return -1;
			}

			no = realloc(info->SI.offset,
				     sizeof(*info->SI.offset) * allocd);
			if (no == NULL)
				goto err;

			info->SI.fields = nf;
			info->SI.offset = no;
		}

		arg_type_info *type = parse_type(str);
		if (type == NULL)
			goto err;
		info->SI.fields[info->SI.num_fields++] = type;

		// Must trim trailing spaces so the check for
		// the closing paren is simple
		eat_spaces(str);
	}
	if (**str != ')') {
		report_error(filename, line_no,
			     "expected ')', got '%c'", **str);
		goto err;
	}
	(*str)++;		// Get past closing paren

	memset(info->SI.offset, 0,
	       sizeof(*info->SI.offset) * info->SI.num_fields);

#undef SI

	align_struct(info);
	return 0;
}

static int
parse_string(char **str, arg_type_info *info)
{
	/* Backwards compatibility for string0, string1, ... */
	if (isdigit(**str)) {
		info->type = ARGTYPE_STRING_N;

		long l;
		if (parse_int(str, &l) < 0
		    || check_nonnegative(l) < 0) {
		err:
			destroy_type(info);
			return -1;
		}

		char buf[23];
		int len = snprintf(buf, sizeof buf, "arg%ld", l);
		assert(len < (int)sizeof buf); /* 128-bit long??? */
		if (len < 0) {
			/* Um, what?  */
			report_error(filename, line_no,
				     "can't render name of aux arg");
			goto err;
		}

		char *name = xstrndup(buf, len);
		if (name == NULL)
			goto err;

		info->u.info.len_spec.kind = ARGEXPR_REF;
		info->u.info.len_spec.u.ref_name = name;
		return 0;

	} else if (**str == '[') {
		long l;

		(*str)++;		// Skip past opening [
		eat_spaces(str);

		if (parse_int(str, &l) < 0
		    || check_nonnegative(l) < 0)
			goto err;

		eat_spaces(str);
		if (**str != ']') {
			report_error(filename, line_no,
				     "expected ']', got '%c'", **str);
			goto err;
		}
		(*str)++;		// Skip past closing ]

		arg_expr_init_const(&info->u.info.len_spec, (unsigned long)l);
		return 0;

	} else {
		/* It was just a simple string after all.  */
		return 0;
	}
}

static arg_type_info *
parse_nonpointer_type(char **str)
{
	int is_typedef = 0;
	arg_type_info *simple = str2type(str);

	if (simple == NULL) {
		simple = lookup_typedef(str);
		if (simple == NULL)
			return NULL;
		is_typedef = 1;
	}

	/* XXX We used to do sharing of primitive types with the type
	 * catalog above.  It's simpler to just malloc everything, so
	 * that per-type is_in and is_out are easy to deal with, but
	 * sharing is still possible in principle, at least for input
	 * parameters, which will most likely be the majority.  */
	arg_type_info *info = malloc(sizeof(*info));
	if (info == NULL) {
		report_global_error("malloc: %s", strerror(errno));
		return NULL;
	}

	if (is_typedef) {
		memcpy(info, simple, sizeof(*info));
		info->is_clone = 1;
		return info;
	}

	memset(info, 0, sizeof(*info));
	info->type = simple->type;

	/* Code to parse parameterized types will go into the following
	   switch statement. */

	switch (info->type) {
	/* Syntax: array ( type, N|argN ) */
	case ARGTYPE_ARRAY:
		if (parse_array(str, info) == 0)
			return info;
		else
			return NULL;

	/* Syntax: enum ( keyname=value,keyname=value,... ) */
	case ARGTYPE_ENUM:{
		struct enum_opt {
			char *key;
			int value;
			struct enum_opt *next;
		};
		struct enum_opt *list = NULL;
		struct enum_opt *p;
		int entries = 0;
		int ii;

		eat_spaces(str);
		(*str)++;		// Get past open paren
		eat_spaces(str);

		while (**str && **str != ')') {
			p = (struct enum_opt *) malloc(sizeof(*p));
			eat_spaces(str);
			p->key = parse_ident(str);
			if (p->key == NULL) {
			err:
				free(p->key);
				free(p);
				return NULL;
			}
			eat_spaces(str);
			if (**str != '=') {
				report_error(filename, line_no,
					     "expected '=', got '%c'", **str);
				goto err;
			}
			++(*str);
			eat_spaces(str);

			long l;
			if (parse_int(str, &l) < 0
			    || check_nonnegative(l) < 0)
				goto err;
			p->value = l;

			p->next = list;
			list = p;
			++entries;

			// Skip comma
			eat_spaces(str);
			if (**str == ',') {
				(*str)++;
				eat_spaces(str);
			}
		}

		info->u.enum_info.entries = entries;
		info->u.enum_info.keys =
			(char **) malloc(entries * sizeof(char *));
		info->u.enum_info.values =
			(int *) malloc(entries * sizeof(int));
		for (ii = 0, p = NULL; list; ++ii, list = list->next) {
			if (p)
				free(p);
			info->u.enum_info.keys[ii] = list->key;
			info->u.enum_info.values[ii] = list->value;
			p = list;
		}
		if (p)
			free(p);

		return info;
	}

	case ARGTYPE_STRING:
		if (parse_string(str, info) == 0)
			return info;
		else
			return NULL;

	// Syntax: struct ( type,type,type,... )
	case ARGTYPE_STRUCT:
		if (parse_struct(str, info) == 0)
			return info;
		else
			return NULL;

	default:
		if (info->type == ARGTYPE_UNKNOWN) {
			report_error(filename, line_no,
				     "unknown type at '%s'", *str);
			free(info);
			return NULL;
		} else {
			return info;
		}
	}
}

static arg_type_info *
parse_type(char **str)
{
	arg_type_info *info = parse_nonpointer_type(str);
	if (info == NULL)
		return NULL;

	while (1) {
		eat_spaces(str);
		if (**str == '*') {
			arg_type_info *outer = malloc(sizeof(*outer));
			if (outer == NULL) {
				destroy_type(info);
				report_error(filename, line_no,
					     "malloc: %s", strerror(errno));
				return NULL;
			}
			outer->type = ARGTYPE_POINTER;
			outer->u.info.type = info;
			(*str)++;
			info = outer;

		} else
			break;
	}
	return info;
}

static int
token_follows_p(char **str, char *token, size_t len)
{
	if (strncmp(*str, token, len) == 0
	    && !isalnum((*str)[len])) {
		*str += len;
		return 1;
	}
	return 0;
}

static arg_type_info *
parse_inout_type(char **str)
{
	int is_in = 0;
	int is_out = 0;

	/* This macro assumes that TOKEN is a string literal.  That's
	 * too fragile for general consumption, so keep it local.  */
#define TOKEN_FOLLOWS_P(STR, TOKEN) \
	(token_follows_p(STR, TOKEN, sizeof(TOKEN) - 1))

	/* Parse in/out/inout modifier.  */
	if (**str == '+') {
		is_out = 1;
		++*str;
	} else if (TOKEN_FOLLOWS_P(str, "in")) {
		is_in = 1;
	} else if (TOKEN_FOLLOWS_P(str, "out")) {
		is_out = 1;
	} else if (TOKEN_FOLLOWS_P(str, "inout")) {
		is_in = 1;
		is_out = 1;
	}
#undef TOKEN_FOLLOWS_P

	/* If unspecified, the default is 'in'.  */
	if (!is_in && !is_out)
		is_in = 1;
	else
		eat_spaces(str);

	arg_type_info *type = parse_type(str);
	if (type == NULL)
		return NULL;

	type->is_in = is_in;
	type->is_out = is_out;
	return type;
}

static Function *
process_line(char *buf) {
	char *str = buf;
	char *tmp;

	line_no++;
	debug(3, "Reading line %d of `%s'", line_no, filename);
	eat_spaces(&str);

	/* A comment or empty line.  */
	if (*str == '#' || *str == 0)
		return NULL;

	if (strncmp(str, "typedef", 7) == 0) {
		parse_typedef(&str);
		return NULL;
	}

	Function *fun = calloc(1, sizeof(*fun));
	if (fun == NULL) {
		report_global_error("alloc function: %s", strerror(errno));
		return NULL;
	}

	fun->return_info = parse_type(&str);
	if (fun->return_info == NULL
	    || fun->return_info->type == ARGTYPE_UNKNOWN) {
	err:
		debug(3, " Skipping line %d", line_no);
		destroy_fun(fun);
		return NULL;
	}
	debug(4, " return_type = %d", fun->return_info->type);

	eat_spaces(&str);
	tmp = start_of_arg_sig(str);
	if (tmp == NULL) {
		report_error(filename, line_no, "syntax error");
		goto err;
	}
	*tmp = '\0';
	fun->name = strdup(str);
	str = tmp + 1;
	debug(3, " name = %s", fun->name);
	fun->params_right = 0;

	size_t allocd = 0;
	fun->num_params = 0;
	while (1) {
		eat_spaces(&str);
		if (*str == ')')
			break;

		if (fun->num_params >= allocd) {
			allocd = allocd > 0 ? 2 * allocd : 8;
			void * na = realloc(fun->param_info,
					    sizeof(*fun->param_info) * allocd);
			if (na == NULL) {
				report_global_error("(re)alloc params: %s",
						    strerror(errno));
				goto err;
			}

			fun->param_info = na;
		}

		arg_type_info *type = parse_inout_type(&str);
		if (type == NULL) {
			report_error(filename, line_no,
				     "unknown parameter type");
			goto err;
		}

		fun->param_info[fun->num_params++] = type;

		eat_spaces(&str);
		if (*str == ',') {
			str++;
			continue;
		} else if (*str == ')') {
			continue;
		} else {
			if (str[strlen(str) - 1] == '\n')
				str[strlen(str) - 1] = '\0';
			report_error(filename, line_no,
				     "syntax error before \"%s\"", str);
			goto err;
		}
	}

	return fun;
}

void
read_config_file(char *file) {
	FILE *stream;
	char buf[1024];

	filename = file;
	stream = fopen(filename, "r");
	if (!stream) {
		return;
	}

	debug(1, "Reading config file `%s'...", filename);

	line_no = 0;
	while (fgets(buf, 1024, stream)) {
		Function *tmp = process_line(buf);

		if (tmp != NULL) {
			debug(2, "New function: `%s'", tmp->name);
			tmp->next = list_of_functions;
			list_of_functions = tmp;
		}
	}
	fclose(stream);
}
