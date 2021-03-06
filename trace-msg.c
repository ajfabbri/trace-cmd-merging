/*
 * trace-msg.c : define message protocol for communication between clients and
 *               a server
 *
 * Copyright (C) 2013 Hitachi, Ltd.
 * Created by Yoshihiro YUNOMAE <yoshihiro.yunomae.ez@hitachi.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/types.h>

#include "trace-cmd-local.h"
#include "trace-msg.h"

typedef __u32 u32;
typedef __be32 be32;

#define TRACECMD_MSG_MAX_LEN		BUFSIZ

					/* size + cmd */
#define TRACECMD_MSG_HDR_LEN		((sizeof(be32)) + (sizeof(be32)))

					/* + size of the metadata */
#define TRACECMD_MSG_META_MIN_LEN	\
				((TRACECMD_MSG_HDR_LEN) + (sizeof(be32)))

					/* - header size for error msg */
#define TRACECMD_MSG_META_MAX_LEN	\
((TRACECMD_MSG_MAX_LEN) - (TRACECMD_MSG_META_MIN_LEN) - TRACECMD_MSG_HDR_LEN)

					/* size + opt_cmd + size of str */
#define TRACECMD_OPT_MIN_LEN		\
			((sizeof(be32)) + (sizeof(be32)) +(sizeof(be32)))


#define CPU_MAX				256

/* use CONNECTION_MSG as a protocol version of trace-msg */
#define MSG_VERSION		"V2"
#define CONNECTION_MSG		"tracecmd-" MSG_VERSION
#define CONNECTION_MSGSIZE	sizeof(CONNECTION_MSG)

/* for both client and server */
bool use_tcp;
int cpu_count;

/* for client */
static int psfd;
unsigned int page_size;
int *client_ports;
int *virt_sfds;
bool send_metadata;

/* for server */
static int *port_array;
bool done;

struct tracecmd_msg_str {
	be32 size;
	char *buf;
} __attribute__((packed));

struct tracecmd_msg_rconnect {
	struct tracecmd_msg_str str;
};

struct tracecmd_msg_opt {
	be32 size;
	be32 opt_cmd;
	struct tracecmd_msg_str str;
};

struct tracecmd_msg_tinit {
	be32 cpus;
	be32 page_size;
	be32 opt_num;
	struct tracecmd_msg_opt *opt;
} __attribute__((packed));

struct tracecmd_msg_rinit {
	be32 cpus;
	be32 port_array[CPU_MAX];
} __attribute__((packed));

struct tracecmd_msg_meta {
	struct tracecmd_msg_str str;
};

struct tracecmd_msg_error {
	be32 size;
	be32 cmd;
	union {
		struct tracecmd_msg_rconnect rconnect;
		struct tracecmd_msg_tinit tinit;
		struct tracecmd_msg_rinit rinit;
		struct tracecmd_msg_meta meta;
	} data;
} __attribute__((packed));

enum tracecmd_msg_cmd {
	MSG_ERROR	= 0,
	MSG_CLOSE	= 1,
	MSG_TCONNECT	= 2,
	MSG_RCONNECT	= 3,
	MSG_TINIT	= 4,
	MSG_RINIT	= 5,
	MSG_SENDMETA	= 6,
	MSG_FINMETA	= 7,
};

struct tracecmd_msg {
	be32 size;
	be32 cmd;
	union {
		struct tracecmd_msg_rconnect rconnect;
		struct tracecmd_msg_tinit tinit;
		struct tracecmd_msg_rinit rinit;
		struct tracecmd_msg_meta meta;
		struct tracecmd_msg_error err;
	} data;
} __attribute__((packed));

struct tracecmd_msg *errmsg;

static ssize_t msg_do_write_check(int fd, struct tracecmd_msg *msg)
{
	return __do_write_check(fd, msg, ntohl(msg->size));
}

static struct tracecmd_msg *tracecmd_msg_alloc(u32 size)
{
	size += TRACECMD_MSG_HDR_LEN;
	return malloc(size);
}

static void tracecmd_msg_init(u32 cmd, u32 size, struct tracecmd_msg *msg)
{
	size += TRACECMD_MSG_HDR_LEN;
	memset(msg, 0, size);
	msg->size = htonl(size);
	msg->cmd = htonl(cmd);
}

static void bufcpy(void *dest, u32 offset, const void *buf, u32 buflen)
{
	memcpy(dest+offset, buf, buflen);
}

static int make_rconnect(const char *buf, int buflen, struct tracecmd_msg *msg)
{
	u32 offset = offsetof(struct tracecmd_msg, data.rconnect.str.buf);

	msg->data.rconnect.str.size = htonl(buflen);
	bufcpy(msg, offset, buf, buflen);

	return 0;
}

enum msg_opt_command {
	MSGOPT_USETCP = 1,
};

static struct tracecmd_msg_opt *tracecmd_msg_opt_alloc(u32 len)
{
	len += TRACECMD_OPT_MIN_LEN;
	return malloc(len);
}

static void make_option(int opt_cmd, const char *buf,
		       struct tracecmd_msg_opt *opt)
{
	u32 buflen = 0;
	u32 size = TRACECMD_OPT_MIN_LEN;

	if (buf) {
		buflen = strlen(buf);
		size += buflen;
	}

	opt->size = htonl(size);
	opt->opt_cmd = htonl(opt_cmd);
	opt->str.size = htonl(buflen);

	if (buf)
		bufcpy(opt, TRACECMD_OPT_MIN_LEN, buf, buflen);
}

static int add_options_to_tinit(u32 len, struct tracecmd_msg *msg)
{
	struct tracecmd_msg_opt *opt;
	int offset = offsetof(struct tracecmd_msg, data.tinit.opt);

	if (use_tcp) {
		opt = tracecmd_msg_opt_alloc(0);
		if (!opt)
			return -ENOMEM;

		make_option(MSGOPT_USETCP, NULL, opt);
		/* add option */
		bufcpy(msg, offset, opt, ntohl(opt->size));
		free(opt);
	}

	return 0;
}

static int make_tinit(u32 len, struct tracecmd_msg *msg)
{
	int opt_num = 0;
	int ret = 0;

	if (use_tcp)
		opt_num++;

	if (opt_num) {
		ret = add_options_to_tinit(len, msg);
		if (ret < 0)
			return ret;
	}

	msg->data.tinit.cpus = htonl(cpu_count);
	msg->data.tinit.page_size = htonl(page_size);
	msg->data.tinit.opt_num = htonl(opt_num);

	return 0;
}

static int make_rinit(struct tracecmd_msg *msg)
{
	int i;
	u32 offset = TRACECMD_MSG_HDR_LEN;
	be32 port;

	msg->data.rinit.cpus = htonl(cpu_count);

	if (port_array) {
		for (i = 0; i < cpu_count; i++) {
			/* + rrqports->cpus or rrqports->port_array[i] */
			offset += sizeof(be32);
			port = htonl(port_array[i]);
			bufcpy(msg, offset, &port, sizeof(be32) * cpu_count);
		}
	}

	return 0;
}

static int make_error_msg(u32 len, struct tracecmd_msg *msg)
{
	bufcpy(msg, TRACECMD_MSG_HDR_LEN, errmsg, len);
	return 0;
}

static u32 tracecmd_msg_get_body_length(u32 cmd)
{
	struct tracecmd_msg *msg;
	u32 len = 0;

	switch (cmd) {
	case MSG_ERROR:
		return ntohl(errmsg->size);
	case MSG_RCONNECT:
		return sizeof(msg->data.rconnect.str.size) + CONNECTION_MSGSIZE;
	case MSG_TINIT:
		len = sizeof(msg->data.tinit.cpus)
		      + sizeof(msg->data.tinit.page_size)
		      + sizeof(msg->data.tinit.opt_num);

		/*
		 * If we are using IPV4 and our page size is greater than
		 * or equal to 64K, we need to punt and use TCP. :-(
		 */

		/* TODO, test for ipv4 */
		if (page_size >= UDP_MAX_PACKET) {
		        warning("page size too big for UDP using TCP "
				"in live read");
		        use_tcp = true;
		}

		if (use_tcp)
			len += TRACECMD_OPT_MIN_LEN;

		return len;
	case MSG_RINIT:
		return sizeof(msg->data.rinit.cpus)
		       + sizeof(msg->data.rinit.port_array);
	case MSG_SENDMETA:
		return TRACECMD_MSG_MAX_LEN - TRACECMD_MSG_HDR_LEN;
	case MSG_TCONNECT:
	case MSG_CLOSE:
	case MSG_FINMETA:
		break;
	}

	return 0;
}

static int tracecmd_msg_make_body(u32 cmd, u32 len, struct tracecmd_msg *msg)
{
	switch (cmd) {
	case MSG_ERROR:
		return make_error_msg(len, msg);
	case MSG_RCONNECT:
		return make_rconnect(CONNECTION_MSG, CONNECTION_MSGSIZE, msg);
	case MSG_TINIT:
		return make_tinit(len, msg);
	case MSG_RINIT:
		return make_rinit(msg);
	case MSG_TCONNECT:
	case MSG_CLOSE:
	case MSG_SENDMETA: /* meta data is not stored here. */
	case MSG_FINMETA:
		break;
	}

	return 0;
}

static int tracecmd_msg_create(u32 cmd, struct tracecmd_msg **msg)
{
	u32 len = 0;
	int ret = 0;

	len = tracecmd_msg_get_body_length(cmd);
	if (len > (TRACECMD_MSG_MAX_LEN - TRACECMD_MSG_HDR_LEN)) {
		plog("Exceed maximum message size cmd=%d\n", cmd);
		return -EINVAL;
	}

	*msg = tracecmd_msg_alloc(len);
	if (!*msg)
		return -ENOMEM;
	tracecmd_msg_init(cmd, len, *msg);

	ret = tracecmd_msg_make_body(cmd, len, *msg);
	if (ret < 0)
		free(*msg);

	return ret;
}

static int tracecmd_msg_send(int fd, u32 cmd)
{
	struct tracecmd_msg *msg = NULL;
	int ret = 0;

	if (cmd > MSG_FINMETA) {
		plog("Unsupported command: %d\n", cmd);
		return -EINVAL;
	}

	ret = tracecmd_msg_create(cmd, &msg);
	if (ret < 0)
		return ret;

	ret = msg_do_write_check(fd, msg);
	if (ret < 0) {
		free(msg);
		return -ECOMM;
	}

	return 0;
}

static void tracecmd_msg_send_error(int fd, struct tracecmd_msg *msg)
{
	errmsg = msg;
 	tracecmd_msg_send(fd, MSG_ERROR);
}

static int tracecmd_msg_read_extra(int fd, char *buf, u32 size, int *n)
{
	int r = 0;

	do {
		r = read(fd, buf+*n, size);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		} else if (!r)
			return -ENOTCONN;
		size -= r;
		*n += r;
	} while (size);

	return 0;
}

/*
 * Read header information of msg first, then read all data
 */
static int tracecmd_msg_recv(int fd, char *buf)
{
	struct tracecmd_msg *msg;
	u32 size = 0;
	int n = 0;
	int ret;

	ret = tracecmd_msg_read_extra(fd, buf, TRACECMD_MSG_HDR_LEN, &n);
	if (ret < 0)
		return ret;

	msg = (struct tracecmd_msg *)buf;
	size = ntohl(msg->size);
	if (size > TRACECMD_MSG_MAX_LEN)
		/* too big */
		goto error;
	else if (size < TRACECMD_MSG_HDR_LEN)
		/* too small */
		goto error;
	else if (size > TRACECMD_MSG_HDR_LEN) {
		size -= TRACECMD_MSG_HDR_LEN;
		return tracecmd_msg_read_extra(fd, buf, size, &n);
	}

	return 0;
error:
	plog("Receive an invalid message(size=%d)\n", size);
	return -ENOMSG;
}

#define MSG_WAIT_MSEC	5000

/*
 * A return value of 0 indicates time-out
 */
static int tracecmd_msg_recv_wait(int fd, char *buf, struct tracecmd_msg **msg)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, MSG_WAIT_MSEC);
	if (ret < 0) {
		return -errno;
	} else if (ret == 0)
		return -ETIMEDOUT;

	return tracecmd_msg_recv(fd, buf);
}

static void *tracecmd_msg_buf_access(struct tracecmd_msg *msg, int offset)
{
	return (void *)msg + offset;
}

static int tracecmd_msg_wait_for_msg(int fd, struct tracecmd_msg **msg)
{
	char msg_tmp[TRACECMD_MSG_MAX_LEN];
	char *buf;
	int offset = TRACECMD_MSG_HDR_LEN;
	u32 cmd;
	int ret;

	ret = tracecmd_msg_recv_wait(fd, msg_tmp, msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	*msg = (struct tracecmd_msg *)msg_tmp;
	cmd = ntohl((*msg)->cmd);
	switch (cmd) {
	case MSG_RCONNECT:
		offset += sizeof((*msg)->data.rconnect.str.size);
		buf = tracecmd_msg_buf_access(*msg, offset);
		/* Make sure the server is the tracecmd server */
		if (memcmp(buf, CONNECTION_MSG,
		    ntohl((*msg)->data.rconnect.str.size) - 1) != 0) {
			warning("server not tracecmd server");
			return -EPROTONOSUPPORT;
		}
		break;
	case MSG_CLOSE:
		return -ECONNABORTED;
	}

	return 0;
}

static int tracecmd_msg_send_and_wait_for_msg(int fd, u32 cmd, struct tracecmd_msg **msg)
{
 	int ret;
 
	ret = tracecmd_msg_send(fd, cmd);
 	if (ret < 0)
		return ret;
 
	ret = tracecmd_msg_wait_for_msg(fd, msg);
 	if (ret < 0) 
 		return ret;
 
	return 0;
}

static int tracecmd_msg_send_init_data(int fd, bool nw)
{
	struct tracecmd_msg *msg = NULL;
	int i, cpus;
	int ret;
	char buf[PATH_MAX];

	ret = tracecmd_msg_send_and_wait_for_msg(fd, MSG_TINIT, &msg);
	if (ret < 0)
		return ret;

	cpus = ntohl(msg->data.rinit.cpus);
	if (nw) {
		client_ports = malloc_or_die(sizeof(int) * cpus);
		for (i = 0; i < cpus; i++)
			client_ports[i] =
					ntohl(msg->data.rinit.port_array[i]);
	} else {
		virt_sfds = malloc_or_die(sizeof(int) * cpus);

		/* Open data paths of virtio-serial */
		for (i = 0; i < cpus; i++) {
			snprintf(buf, PATH_MAX, TRACE_PATH_CPU, i);
			virt_sfds[i] = open(buf, O_WRONLY);
			if (virt_sfds[i] < 0) {
				warning("Cannot open %s", TRACE_PATH_CPU, i);
				return -errno;
			}
		}
	}

	/* Next, send meta data */
	send_metadata = true;

	return 0;
}

int tracecmd_msg_send_init_data_nw(int fd)
{
	return tracecmd_msg_send_init_data(fd, true);
}

static int tracecmd_msg_send_init_data_virt(int fd)
{
	return tracecmd_msg_send_init_data(fd, false);
}

int tracecmd_msg_connect_to_server(int fd)
{
	struct tracecmd_msg *msg = NULL;
	int ret;

	/* connect to a server */
	ret = tracecmd_msg_send_and_wait_for_msg(fd, MSG_TCONNECT, &msg);
	if (ret < 0) {
		if (ret == -EPROTONOSUPPORT)
			goto error;
		return ret;
	}

	ret = tracecmd_msg_send_init_data_virt(fd);
	if (ret < 0)
		return ret;

	return 0;

error:
	tracecmd_msg_send_error(fd, msg);
	return ret;
}

static bool process_option(struct tracecmd_msg_opt *opt)
{
	/* currently the only option we have is to us TCP */
	if (ntohl(opt->opt_cmd) == MSGOPT_USETCP) {
		use_tcp = true;
		return true;
	}
	return false;
}

static void error_operation_for_server(struct tracecmd_msg *msg)
{
	u32 cmd;

	cmd = ntohl(msg->cmd);

	if (cmd == MSG_ERROR)
		plog("Receive error message: cmd=%d size=%d\n",
		     ntohl(msg->data.err.cmd), ntohl(msg->data.err.size));
	else
		warning("Message: cmd=%d size=%d\n", cmd, ntohl(msg->size));
}

int tracecmd_msg_set_connection(int fd, const char *domain)
{
	struct tracecmd_msg *msg;
	char buf[TRACECMD_MSG_MAX_LEN] = {};
	u32 cmd;
	int ret;

	/*
	 * Wait for connection msg by a client first.
	 * If a client uses virtio-serial, a connection message will
	 * not be sent immediately after accept(). connect() is called
	 * in QEMU, so the client can send the connection message
	 * after guest boots. Therefore, the virt-server patiently
	 * waits for the connection request of a client.
	 */ 
	ret = tracecmd_msg_recv(fd, buf);
	if (ret < 0) {
		if (!buf[0]) {
			/* No data means QEMU has already died. */
			close(fd);
			die("Connection refuesd: %s", domain);
		}
		return -ENOMSG;
	}

	msg = (struct tracecmd_msg *)buf;
	cmd = ntohl(msg->cmd);
	if (cmd == MSG_CLOSE)
		return -ECONNABORTED;
	else if (cmd != MSG_TCONNECT)
		return -EINVAL;

	ret = tracecmd_msg_send(fd, MSG_RCONNECT);
	if (ret < 0)
		goto error;

	return 0;

error:
	error_operation_for_server(msg);
	return ret;
}

#define MAX_OPTION_SIZE 4096

int tracecmd_msg_initial_setting(int fd, int *cpus, int *pagesize)
{
	struct tracecmd_msg *msg;
	struct tracecmd_msg_opt *opt;
	char buf[TRACECMD_MSG_MAX_LEN];
	int offset = offsetof(struct tracecmd_msg, data.tinit.opt);
	int options, i, s;
	int ret;
	u32 size = 0;
	u32 cmd;

	ret = tracecmd_msg_recv_wait(fd, buf, &msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	msg = (struct tracecmd_msg *)buf;
	cmd = ntohl(msg->cmd);
	if (cmd != MSG_TINIT) {
		ret = -EINVAL;
		goto error;
	}

	*cpus = ntohl(msg->data.tinit.cpus);
	plog("cpus=%d\n", *cpus);
	if (*cpus < 0) {
		ret = -EINVAL;
		goto error;
	}
	
	*pagesize = ntohl(msg->data.tinit.page_size);
	plog("pagesize=%d\n", *pagesize);
	if (*pagesize <= 0) {
		ret = -EINVAL;
		goto error;
	}

	options = ntohl(msg->data.tinit.opt_num);
	for (i = 0; i < options; i++) {
		offset += size;
		opt = tracecmd_msg_buf_access(msg, offset);
		size = ntohl(opt->size);
		/* prevent a client from killing us */
		if (size > MAX_OPTION_SIZE) {
			plog("Exceed MAX_OPTION_SIZE\n");
			ret = -EINVAL;
			goto error;
		}
		s = process_option(opt);
		/* do we understand this option? */
		if (!s) {
			plog("Cannot understand(%d:%d:%d)\n",
			     i, ntohl(opt->size), ntohl(opt->opt_cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(msg);
	return ret;
}

int tracecmd_msg_send_port_array(int fd, int total_cpus, int *ports)
{
	int ret;

	cpu_count = total_cpus;
	port_array = ports;

	ret = tracecmd_msg_send(fd, MSG_RINIT);
	if (ret < 0)
		return ret;

	return 0;
}

void tracecmd_msg_send_close_msg()
{
	tracecmd_msg_send(psfd, MSG_CLOSE);
}

static void make_meta(const char *buf, int buflen, struct tracecmd_msg *msg)
{
	int offset = offsetof(struct tracecmd_msg, data.meta.str.buf);

	msg->data.meta.str.size = htonl(buflen);
	bufcpy(msg, offset, buf, buflen);
}

int tracecmd_msg_metadata_send(int fd, char *buf, int size)
{
	struct tracecmd_msg *msg;
	int n, len;
	int ret;
	int count = 0;

	ret = tracecmd_msg_create(MSG_SENDMETA, &msg);
	if (ret < 0)
		return ret;

	n = size;
	do {
		if (n > TRACECMD_MSG_META_MAX_LEN) {
			make_meta(buf+count, TRACECMD_MSG_META_MAX_LEN, msg);
			n -= TRACECMD_MSG_META_MAX_LEN;
			count += TRACECMD_MSG_META_MAX_LEN;
		} else {
			make_meta(buf+count, n, msg);
			/*
			 * TRACECMD_MSG_META_MAX_LEN is stored in msg->size,
			 * so update the size to the correct value.
			 */
			len = TRACECMD_MSG_META_MIN_LEN + n;
			msg->size = htonl(len);
			n = 0;
		}

		ret = msg_do_write_check(fd, msg);
		if (ret < 0)
			return ret;
	} while (n);

	return 0;
}

int tracecmd_msg_finish_sending_metadata(int fd)
{
	int ret;

	ret = tracecmd_msg_send(fd, MSG_FINMETA);
	if (ret < 0)
		return ret;

	/* psfd will be used for closing */
	psfd = fd;
	return 0;
}

int tracecmd_msg_collect_metadata(int ifd, int ofd)
{
	struct tracecmd_msg *msg;
	char buf[TRACECMD_MSG_MAX_LEN];
	u32 s, t, n, cmd;
	int offset = TRACECMD_MSG_META_MIN_LEN;
	int ret;

	do {
		ret = tracecmd_msg_recv_wait(ifd, buf, &msg);
		if (ret < 0) {
			if (ret == -ETIMEDOUT)
				warning("Connection timed out\n");
			else
				warning("reading client");
			return ret;
		}

		msg = (struct tracecmd_msg *)buf;
		cmd = ntohl(msg->cmd);
		if (cmd == MSG_FINMETA) {
			/* Finish receiving meta data */
			break;
		} else if (cmd != MSG_SENDMETA)
			goto error;

		n = ntohl(msg->data.meta.str.size);
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s+offset, t);
			if (s < 0) {
				if (errno == EINTR)
					continue;
				warning("writing to file");
				return -errno;
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (cmd == MSG_SENDMETA);

	/* check the finish message of the client */
	while(!done) {
		ret = tracecmd_msg_recv(ifd, buf);
		if (ret < 0) {
			warning("reading client");
			return ret;
		}

		msg = (struct tracecmd_msg *)buf;
		cmd = ntohl(msg->cmd);
		if (cmd == MSG_CLOSE)
			/* Finish this connection */
			break;
		else {
			warning("Not accept the message %d", ntohl(msg->cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(msg);
	return ret;
}
