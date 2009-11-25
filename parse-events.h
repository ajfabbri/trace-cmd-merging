#ifndef _PARSE_EVENTS_H
#define _PARSE_EVENTS_H

#include <stdarg.h>

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

/* ----------------------- trace_seq ----------------------- */


#ifndef TRACE_SEQ_SIZE
#define TRACE_SEQ_SIZE 4096
#endif

/*
 * Trace sequences are used to allow a function to call several other functions
 * to create a string of data to use (up to a max of PAGE_SIZE).
 */

struct trace_seq {
	char			buffer[TRACE_SEQ_SIZE];
	unsigned int		len;
	unsigned int		readpos;
};

static inline void
trace_seq_init(struct trace_seq *s)
{
	s->len = 0;
	s->readpos = 0;
}

extern int trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int trace_seq_vprintf(struct trace_seq *s, const char *fmt, va_list args)
	__attribute__ ((format (printf, 2, 0)));

extern int trace_seq_puts(struct trace_seq *s, const char *str);
extern int trace_seq_putc(struct trace_seq *s, unsigned char c);

extern int trace_seq_do_printf(struct trace_seq *s);


/* ----------------------- pevent ----------------------- */

struct event;

typedef int (*pevent_event_handler_func)(struct trace_seq *s,
					 void *data, int size,
					 struct event *event);

typedef int (*pevent_plugin_load_func)(void);

#define PEVENT_PLUGIN_LOADER pevent_plugin_loader
#define MAKE_STR(x) #x
#define PEVENT_PLUGIN_LOADER_NAME MAKE_STR(pevent_plugin_loader)

#define NSECS_PER_SEC		1000000000ULL
#define NSECS_PER_USEC		1000ULL

enum format_flags {
	FIELD_IS_ARRAY		= 1,
	FIELD_IS_POINTER	= 2,
	FIELD_IS_SIGNED		= 4,
	FIELD_IS_STRING		= 8,
	FIELD_IS_DYNAMIC	= 16,
};

struct format_field {
	struct format_field	*next;
	char			*type;
	char			*name;
	int			offset;
	int			size;
	unsigned long		flags;
};

struct format {
	int			nr_common;
	int			nr_fields;
	struct format_field	*common_fields;
	struct format_field	*fields;
};

struct print_arg_atom {
	char			*atom;
};

struct print_arg_string {
	char			*string;
	int			offset;
};

struct print_arg_field {
	char			*name;
	struct format_field	*field;
};

struct print_flag_sym {
	struct print_flag_sym	*next;
	char			*value;
	char			*str;
};

struct print_arg_typecast {
	char 			*type;
	struct print_arg	*item;
};

struct print_arg_flags {
	struct print_arg	*field;
	char			*delim;
	struct print_flag_sym	*flags;
};

struct print_arg_symbol {
	struct print_arg	*field;
	struct print_flag_sym	*symbols;
};

struct print_arg_dynarray {
	struct format_field	*field;
	struct print_arg	*index;
};

struct print_arg;

struct print_arg_op {
	char			*op;
	int			prio;
	struct print_arg	*left;
	struct print_arg	*right;
};

struct print_arg_func {
	char			*name;
	struct print_arg	*args;
};

enum print_arg_type {
	PRINT_NULL,
	PRINT_ATOM,
	PRINT_FIELD,
	PRINT_FLAGS,
	PRINT_SYMBOL,
	PRINT_TYPE,
	PRINT_STRING,
	PRINT_DYNAMIC_ARRAY,
	PRINT_OP,
};

struct print_arg {
	struct print_arg		*next;
	enum print_arg_type		type;
	union {
		struct print_arg_atom		atom;
		struct print_arg_field		field;
		struct print_arg_typecast	typecast;
		struct print_arg_flags		flags;
		struct print_arg_symbol		symbol;
		struct print_arg_func		func;
		struct print_arg_string		string;
		struct print_arg_op		op;
		struct print_arg_dynarray	dynarray;
	};
};

struct print_fmt {
	char			*format;
	struct print_arg	*args;
};

struct event {
	struct event		*next;
	char			*name;
	int			id;
	int			flags;
	struct format		format;
	struct print_fmt	print_fmt;
	char			*system;
	pevent_event_handler_func handler;
};

enum {
	EVENT_FL_ISFTRACE	= 0x01,
	EVENT_FL_ISPRINT	= 0x02,
	EVENT_FL_ISBPRINT	= 0x04,
	EVENT_FL_ISFUNC		= 0x08,
	EVENT_FL_ISFUNCENT	= 0x10,
	EVENT_FL_ISFUNCRET	= 0x20,

	EVENT_FL_FAILED		= 0x80000000
};

struct record {
	unsigned long long ts;
	int size;
	void *data;
};

struct record *trace_peek_data(int cpu);
struct record *trace_read_data(int cpu);

extern int old_format;

void parse_set_info(int nr_cpus, int long_sz);

void die(char *fmt, ...);
void *malloc_or_die(unsigned int size);
void warning(char *fmt, ...);

extern int file_bigendian;
extern int host_bigendian;

int bigendian(void);

static inline unsigned short __data2host2(unsigned short data)
{
	unsigned short swap;

	if (host_bigendian == file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 8) |
		((data & (0xffULL << 8)) >> 8);

	return swap;
}

static inline unsigned int __data2host4(unsigned int data)
{
	unsigned int swap;

	if (host_bigendian == file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 24) |
		((data & (0xffULL << 8)) << 8) |
		((data & (0xffULL << 16)) >> 8) |
		((data & (0xffULL << 24)) >> 24);

	return swap;
}

static inline unsigned long long __data2host8(unsigned long long data)
{
	unsigned long long swap;

	if (host_bigendian == file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 56) |
		((data & (0xffULL << 8)) << 40) |
		((data & (0xffULL << 16)) << 24) |
		((data & (0xffULL << 24)) << 8) |
		((data & (0xffULL << 32)) >> 8) |
		((data & (0xffULL << 40)) >> 24) |
		((data & (0xffULL << 48)) >> 40) |
		((data & (0xffULL << 56)) >> 56);

	return swap;
}

#define data2host2(ptr)		__data2host2(*(unsigned short *)ptr)
#define data2host4(ptr)		__data2host4(*(unsigned int *)ptr)
#define data2host8(ptr)		__data2host8(*(unsigned long long *)ptr)

extern int header_page_ts_offset;
extern int header_page_ts_size;
extern int header_page_size_offset;
extern int header_page_size_size;
extern int header_page_data_offset;
extern int header_page_data_size;

extern int latency_format;

/* taken from kernel/trace/trace.h */
enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF		= 0x01,
	TRACE_FLAG_IRQS_NOSUPPORT	= 0x02,
	TRACE_FLAG_NEED_RESCHED		= 0x04,
	TRACE_FLAG_HARDIRQ		= 0x08,
	TRACE_FLAG_SOFTIRQ		= 0x10,
};

int pevent_register_comm(char *comm, int pid);
int pevent_register_function(char *name, unsigned long long addr, char *mod);
int pevent_register_print_string(char *fmt, unsigned long long addr);

void pevent_print_event(struct trace_seq *s,
			int cpu, void *data, int size, unsigned long long nsecs);

int pevent_parse_header_page(char *buf, unsigned long size);

int pevent_parse_event(char *buf, unsigned long size, char *sys);

int pevent_register_event_handler(int id, char *sys_name, char *event_name,
				  pevent_event_handler_func func);

struct format_field *pevent_find_field(struct event *event, const char *name);


/* for debugging */
void pevent_print_funcs(void);
void pevent_print_printk(void);


#endif /* _PARSE_EVENTS_H */
