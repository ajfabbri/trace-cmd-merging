/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-msg.h"

#define MAX_OPTION_SIZE 4096

static char *default_output_dir = ".";
static char *output_dir;
static char *default_output_file = "trace";
static char *output_file;

static FILE *logfp;

static int debug;

static int backlog = 5;

static int proto_ver;

#define  TEMP_FILE_STR_NW "%s.%s:%s.cpu%d", output_file, host, port, cpu
#define  TEMP_FILE_STR_VIRT "%s.%s:%d.cpu%d", output_file, domain, virtpid, cpu
static char *get_temp_file(const char *host, const char *port,
			   const char *domain, int virtpid, int cpu)
{
	char *file = NULL;
	int size;

	if (host) {
		size = snprintf(file, 0, TEMP_FILE_STR_NW);
		file = malloc_or_die(size + 1);
		sprintf(file, TEMP_FILE_STR_NW);
	} else {
		size = snprintf(file, 0, TEMP_FILE_STR_VIRT);
		file = malloc_or_die(size + 1);
		sprintf(file, TEMP_FILE_STR_VIRT);
	}

	return file;
}

static void put_temp_file(char *file)
{
	free(file);
}

#define MAX_PATH 1024

static void signal_setup(int sig, sighandler_t handle)
{
	struct sigaction action;

	sigaction(sig, NULL, &action);
	/* Make accept return EINTR */
	action.sa_flags &= ~SA_RESTART;
	action.sa_handler = handle;
	sigaction(sig, &action, NULL);
}

static void delete_temp_file(const char *host, const char *port,
			     const char *domain, int virtpid, int cpu)
{
	char file[MAX_PATH];

	if (host)
		snprintf(file, MAX_PATH, TEMP_FILE_STR_NW);
	else
		snprintf(file, MAX_PATH, TEMP_FILE_STR_VIRT);
	unlink(file);
}

static int read_string(int fd, char *buf, size_t size)
{
	size_t i;
	int n;

	for (i = 0; i < size; i++) {
		n = read(fd, buf+i, 1);
		if (!buf[i] || n <= 0)
			break;
	}

	return i;
}

static int process_option(char *option)
{
	/* currently the only option we have is to us TCP */
	if (strcmp(option, "TCP") == 0) {
		use_tcp = 1;
		return 1;
	}
	return 0;
}

static struct tracecmd_recorder *recorder;

static void finish(int sig)
{
	if (recorder)
		tracecmd_stop_recording(recorder);
	done = true;
}

#define LOG_BUF_SIZE 1024
static void __plog(const char *prefix, const char *fmt, va_list ap,
		   FILE *fp)
{
	static int newline = 1;
	char buf[LOG_BUF_SIZE];
	int r;

	r = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

	if (r > LOG_BUF_SIZE)
		r = LOG_BUF_SIZE;

	if (logfp) {
		if (newline)
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		else
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		newline = buf[r - 1] == '\n';
		fflush(logfp);
		return;
	}

	fprintf(fp, "%.*s", r, buf);
}

void plog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__plog("", fmt, ap, stdout);
	va_end(ap);
}

void pdie(const char *fmt, ...)
{
	va_list ap;
	char *str = "";

	va_start(ap, fmt);
	__plog("Error: ", fmt, ap, stderr);
	va_end(ap);
	if (errno)
		str = strerror(errno);
	if (logfp)
		fprintf(logfp, "\n%s\n", str);
	else
		fprintf(stderr, "\n%s\n", str);
	exit(-1);
}

static void process_udp_child(int sfd, const char *host, const char *port,
			      int cpu, int page_size)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	char buf[page_size];
	char *tempfile;
	int cfd;
	int fd;
	int n;
	int once = 0;

	signal_setup(SIGUSR1, finish);

	tempfile = get_temp_file(host, port, NULL, 0, cpu);
	fd = open(tempfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		pdie("creating %s", tempfile);

	if (use_tcp) {
		if (listen(sfd, backlog) < 0)
			pdie("listen");
		peer_addr_len = sizeof(peer_addr);
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
		if (cfd < 0 && errno == EINTR)
			goto done;
		if (cfd < 0)
			pdie("accept");
		close(sfd);
		sfd = cfd;
	}

	do {
		/* TODO, make this copyless! */
		n = read(sfd, buf, page_size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading client");
		}
		if (!n)
			break;
		/* UDP requires that we get the full size in one go */
		if (!use_tcp && n < page_size && !once) {
			once = 1;
			warning("read %d bytes, expected %d", n, page_size);
		}
		write(fd, buf, n);
	} while (!done);

 done:
	put_temp_file(tempfile);
	exit(0);
}

#define SLEEP_DEFAULT	1000

static void process_virt_child(int fd, int cpu, int pagesize,
			       const char *domain, int virtpid)
{
	char *tempfile;

	signal_setup(SIGUSR1, finish);
	tempfile = get_temp_file(NULL, NULL, domain, virtpid, cpu);

	recorder = tracecmd_create_recorder_virt(tempfile, cpu, fd);

	do {
		if (tracecmd_start_recording(recorder, SLEEP_DEFAULT) < 0)
			break;
	} while (!done);

	tracecmd_free_recorder(recorder);
	put_temp_file(tempfile);
	exit(0);
}

#define START_PORT_SEARCH 1500
#define MAX_PORT_SEARCH 6000

static int udp_bind_a_port(int start_port, int *sfd)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char buf[BUFSIZ];
	int s;
	int num_port = start_port;

 again:
	snprintf(buf, BUFSIZ, "%d", num_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, buf, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening udp socket");

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		*sfd = socket(rp->ai_family, rp->ai_socktype,
			      rp->ai_protocol);
		if (*sfd < 0)
			continue;

		if (bind(*sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(*sfd);
	}

	if (rp == NULL) {
		freeaddrinfo(result);
		if (++num_port > MAX_PORT_SEARCH)
			pdie("No available ports to bind");
		goto again;
	}

	freeaddrinfo(result);

	return num_port;
}

static void fork_reader(int sfd, const char *node, const char *port,
			int *pid, int cpu, int pagesize, const char *domain,
			int virtpid)
{
	*pid = fork();

	if (*pid < 0)
		pdie("creating reader");

	if (!*pid) {
		if (node)
			process_udp_child(sfd, node, port, cpu, pagesize);
		else
			process_virt_child(sfd, cpu, pagesize, domain, virtpid);
	}

	close(sfd);
}

static void fork_udp_reader(int sfd, const char *node, const char *port,
			    int *pid, int cpu, int pagesize)
{
	fork_reader(sfd, node, port, pid, cpu, pagesize, NULL, 0);
}

static void fork_virt_reader(int sfd, int *pid, int cpu, int pagesize,
			     const char *domain, int virtpid)
{
	fork_reader(sfd, NULL, NULL, pid, cpu, pagesize, domain, virtpid);
}

static int open_udp(const char *node, const char *port, int *pid,
		    int cpu, int pagesize, int start_port)
{
	int sfd;
	int num_port;

	/*
	 * udp_bind_a_port() currently does not return an error, but if that
	 * changes in the future, we have a check for it now. 
	 */
	num_port = udp_bind_a_port(start_port, &sfd);
	if (num_port < 0)
		return num_port;

	fork_udp_reader(sfd, node, port, pid, cpu, pagesize);

	return num_port;
}

#define TRACE_CMD_DIR		"/tmp/trace-cmd/"
#define VIRT_DIR		TRACE_CMD_DIR "virt/"
#define VIRT_TRACE_CTL_SOCK	VIRT_DIR "agent-ctl-path"
#define TRACE_PATH_DOMAIN_CPU	VIRT_DIR "%s/trace-path-cpu%d.out"

static int open_virtio_serial_pipe(int *pid, int cpu, int pagesize,
				   const char *domain, int virtpid)
{
	char buf[PATH_MAX];
	int fd;

	snprintf(buf, PATH_MAX, TRACE_PATH_DOMAIN_CPU, domain, cpu);
	fd = open(buf, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		warning("open %s", buf);
		return fd;
	}

	fork_virt_reader(fd, pid, cpu, pagesize, domain, virtpid);

	return fd;
}

static int communicate_with_client_nw(int fd, int *cpus, int *pagesize)
{
	char buf[BUFSIZ];
	char *option;
	int options;
	int size;
	int n, s, t, i;

	/* Let the client know what we are */
	write(fd, "tracecmd", 8);

	/* read back the CPU count */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return -1;

	*cpus = atoi(buf);

	/* Is the client using the new protocol? */
	if (!*cpus) {
		if (memcmp(buf, "V2", 2) != 0) {
			plog("Cannot handle the protocol %s", buf);
			return -1;
		}

		/* read the rest of dummy data, but not use */
		read(fd, buf, sizeof(V2_MAGIC)+1);

		proto_ver = V2_PROTOCOL;

		/* Let the client know we use v2 protocol */
		write(fd, "V2", 2);

		/* read the CPU count, the page size, and options */
		if (tracecmd_msg_initial_setting(fd, cpus, pagesize) < 0)
			return -1;
	} else {
		/* The client is using the v1 protocol */

		plog("cpus=%d\n", *cpus);
		if (*cpus < 0)
			return -1;

		/* next read the page size */
		n = read_string(fd, buf, BUFSIZ);
		if (n == BUFSIZ)
			/** ERROR **/
			return -1;

		*pagesize = atoi(buf);

		plog("pagesize=%d\n", *pagesize);
		if (*pagesize <= 0)
			return -1;

		/* Now the number of options */
		n = read_string(fd, buf, BUFSIZ);
		if (n == BUFSIZ)
			/** ERROR **/
			return -1;

		options = atoi(buf);

		for (i = 0; i < options; i++) {
			/* next is the size of the options */
			n = read_string(fd, buf, BUFSIZ);
			if (n == BUFSIZ)
				/** ERROR **/
				return -1;
			size = atoi(buf);
			/* prevent a client from killing us */
			if (size > MAX_OPTION_SIZE)
				return -1;
			option = malloc_or_die(size);
			do {
				t = size;
				s = 0;
				s = read(fd, option+s, t);
				if (s <= 0)
					return -1;
				t -= s;
				s = size - t;
			} while (t);

			s = process_option(option);
			free(option);
			/* do we understand this option? */
			if (!s)
				return -1;
		}
	}

	if (use_tcp)
		plog("Using TCP for live connection\n");

	return 0;
}

static int communicate_with_client_virt(int fd, const char *domain,  int *cpus, int *pagesize)
{
	proto_ver = V2_PROTOCOL;

	if (tracecmd_msg_set_connection(fd, domain) < 0)
		return -1;

	/* read the CPU count, the page size, and options */
	if (tracecmd_msg_initial_setting(fd, cpus, pagesize) < 0)
		return -1;

	return 0;
}

static int create_client_file(const char *node, const char *port,
			      const char *domain, int pid)
{
	char buf[BUFSIZ];
	int ofd;

	if (node)
		snprintf(buf, BUFSIZ, "%s.%s:%s.dat", output_file, node, port);
	else
		snprintf(buf, BUFSIZ, "%s.%s:%d.dat", output_file, domain, pid);

	ofd = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		pdie("Can not create file %s", buf);
	return ofd;
}

static void destroy_all_readers(int cpus, int *pid_array, const char *node,
				const char *port, const char *domain,
				int virtpid)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0) {
			kill(pid_array[cpu], SIGKILL);
			waitpid(pid_array[cpu], NULL, 0);
			delete_temp_file(node, port, domain, virtpid, cpu);
			pid_array[cpu] = 0;
		}
	}
}

static int *create_all_readers(int cpus, const char *node, const char *port,
			       const char *domain, int virtpid, int pagesize, int fd)
{
	char buf[BUFSIZ];
	int *port_array = NULL;
	int *pid_array;
	int start_port;
	int udp_port;
	int cpu;
	int pid;

	if (node) {
		port_array = malloc_or_die(sizeof(int) * cpus);
		start_port = START_PORT_SEARCH;
	}
	pid_array = malloc_or_die(sizeof(int) * cpus);
	memset(pid_array, 0, sizeof(int) * cpus);

	/* Now create a reader for each CPU */
	for (cpu = 0; cpu < cpus; cpu++) {
		if (node) {
			udp_port = open_udp(node, port, &pid, cpu,
					    pagesize, start_port);
			if (udp_port < 0)
				goto out_free;
			port_array[cpu] = udp_port;
			/*
			 * due to some bugging finding ports,
			 * force search after last port
			 */
			start_port = udp_port + 1;
		} else {
			if (open_virtio_serial_pipe(&pid, cpu, pagesize,
						    domain, virtpid) < 0)
				goto out_free;
		}
		pid_array[cpu] = pid;
		/*
		 * Due to some bugging finding ports,
		 * force search after last port
		 */
		start_port = udp_port + 1;
	}

	if (proto_ver == V2_PROTOCOL) {
		/* send set of port numbers to the client */
		if (tracecmd_msg_send_port_array(fd, cpus, port_array) < 0)
			goto out_free;
	} else {
		/* send the client a comma deliminated set of port numbers */
		for (cpu = 0; cpu < cpus; cpu++) {
			snprintf(buf, BUFSIZ, "%s%d",
				 cpu ? "," : "", port_array[cpu]);
			write(fd, buf, strlen(buf));
		}
		/* end with null terminator */
		write(fd, "\0", 1);
	}

	return pid_array;

 out_free:
	destroy_all_readers(cpus, pid_array, node, port, domain, virtpid);
	return NULL;
}

static void collect_metadata_from_client(int ifd, int ofd)
{
	char buf[BUFSIZ];
	int n, s, t;

	do {
		n = read(ifd, buf, BUFSIZ);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading client");
		}
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					break;
				pdie("writing to file");
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (n > 0 && !done);
}

static void stop_all_readers(int cpus, int *pid_array)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0)
			kill(pid_array[cpu], SIGUSR1);
	}
}

static void put_together_file(int cpus, int ofd, const char *node,
			      const char *port, const char *domain, int virtpid)
{
	char **temp_files;
	int cpu;

	/* Now put together the file */
	temp_files = malloc_or_die(sizeof(*temp_files) * cpus);

	for (cpu = 0; cpu < cpus; cpu++)
		temp_files[cpu] = get_temp_file(node, port, domain,
						virtpid, cpu);

	tracecmd_attach_cpu_data_fd(ofd, cpus, temp_files);
	free(temp_files);
}

static void process_client(const char *node, const char *port,
			   const char *domain, int virtpid, int fd)
{
	int *pid_array;
	int pagesize;
	int cpus;
	int ofd;

	if (node) {
		if (communicate_with_client_nw(fd, &cpus, &pagesize) < 0)
			return;
	} else {
		if (communicate_with_client_virt(fd, domain, &cpus, &pagesize) < 0)
			return;
	}

	ofd = create_client_file(node, port, domain, virtpid);
	pid_array = create_all_readers(cpus, node, port, domain, virtpid, pagesize, fd);
	if (!pid_array)
		return;

	/* Now we are ready to start reading data from the client */
	if (proto_ver == V2_PROTOCOL)
		tracecmd_msg_collect_metadata(fd, ofd);
	else
		collect_metadata_from_client(fd, ofd);

	/* wait a little to let our readers finish reading */
	sleep(1);

	/* stop our readers */
	stop_all_readers(cpus, pid_array);

	/* wait a little to have the readers clean up */
	sleep(1);

	put_together_file(cpus, ofd, node, port, domain, virtpid);

	destroy_all_readers(cpus, pid_array, node, port, domain, virtpid);
}

static void process_client_nw(const char *node, const char *port, int fd)
{
	process_client(node, port, NULL, 0, fd);
}

static void process_client_virt(const char *domain, int virtpid, int fd)
{
	/* keep connection to qemu if clients on guests finish operation */
	do {
		process_client(NULL, NULL, domain, virtpid, fd);
	} while (!done);
}

static int do_fork(int cfd)
{
	pid_t pid;

	/* in debug mode, we do not fork off children */
	if (debug)
		return 0;

	pid = fork();
	if (pid < 0) {
		warning("failed to create child");
		return -1;
	}

	if (pid > 0) {
		close(cfd);
		return pid;
	}

	signal_setup(SIGINT, finish);

	return 0;
}

static int do_connection(int cfd, struct sockaddr *peer_addr,
			 socklen_t *peer_addr_len, const char *domain, int virtpid)
{
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s;
	int ret;

	ret = do_fork(cfd);
	if (ret)
		return ret;

	if (peer_addr) {
		s = getnameinfo(peer_addr, *peer_addr_len, host, NI_MAXHOST,
				service, NI_MAXSERV, NI_NUMERICSERV);
	
		if (s == 0)
			plog("Connected with %s:%s\n",
			       host, service);
		else {
			plog("Error with getnameinfo: %s\n",
			       gai_strerror(s));
			close(cfd);
			return -1;
		}
		process_client_nw(host, service, cfd);
	} else
		process_client_virt(domain, virtpid, cfd);

	close(cfd);

	if (!debug)
		exit(0);

	return 0;
}

static int do_connection_nw(int cfd, struct sockaddr *addr, socklen_t *addrlen)
{
	return do_connection(cfd, addr, addrlen, NULL, 0);
}

#define LIBVIRT_DOMAIN_PATH     "/var/run/libvirt/qemu/"

/* We can convert pid to domain name of a guest when we use libvirt. */
static char *get_guest_domain_from_pid(int pid)
{
	struct dirent *dirent;
	char file_name[NAME_MAX];
	char *file_name_ret, *domain;
	char buf[BUFSIZ];
	DIR *dir;
	size_t doml;
	int fd;

	dir = opendir(LIBVIRT_DOMAIN_PATH);
	if (!dir) {
		if (errno == ENOENT)
			warning("Only support for using libvirt");
		return NULL;
	}

	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
		snprintf(file_name, NAME_MAX, LIBVIRT_DOMAIN_PATH"%s",
			 dirent->d_name);
		file_name_ret = strstr(file_name, ".pid");
		if (file_name_ret) {
			fd = open(file_name, O_RDONLY);
			if (fd < 0)
				return NULL;
			if (read(fd, buf, BUFSIZ) < 0)
				return NULL;

			if (pid == atoi(buf)) {
				/* not include /var/run/libvirt/qemu */
				doml = (size_t)(file_name_ret - file_name)
					- strlen(LIBVIRT_DOMAIN_PATH);
				domain = strndup(file_name +
						 strlen(LIBVIRT_DOMAIN_PATH),
						 doml);
				plog("start %s:%d\n", domain, pid);
				return domain;
			}
		}
	}

	return NULL;
}

static int do_connection_virt(int cfd)
{
	struct ucred cr;
	socklen_t cl;
	int ret;
	char *domain;

	cl = sizeof(cr);
	ret = getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl);
	if (ret < 0)
		return ret;

	domain = get_guest_domain_from_pid(cr.pid);
	if (!domain)
		return -1;

	return do_connection(cfd, NULL, NULL, domain, cr.pid);
}

static int *client_pids;
static int saved_pids;
static int size_pids;
#define PIDS_BLOCK 32

static void add_process(int pid)
{
	if (!client_pids) {
		size_pids = PIDS_BLOCK;
		client_pids = malloc_or_die(sizeof(*client_pids) * size_pids);
	} else if (!(saved_pids % PIDS_BLOCK)) {
		size_pids += PIDS_BLOCK;
		client_pids = realloc(client_pids,
				      sizeof(*client_pids) * size_pids);
		if (!client_pids)
			pdie("realloc of pids");
	}
	client_pids[saved_pids++] = pid;
}

static void remove_process(int pid)
{
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (client_pids[i] == pid)
			break;
	}

	if (i == saved_pids)
		return;

	saved_pids--;

	if (saved_pids == i)
		return;

	memmove(&client_pids[i], &client_pids[i+1],
		sizeof(*client_pids) * (saved_pids - i));

}

static void kill_clients(void)
{
	int i;

	for (i = 0; i < saved_pids; i++) {
		kill(client_pids[i], SIGINT);
		waitpid(client_pids[i], NULL, 0);
	}

	saved_pids = 0;
}

static void clean_up(int sig)
{
	int status;
	int ret;

	/* Clean up any children that has started before */
	do {
		ret = waitpid(0, &status, WNOHANG);
		if (ret > 0)
			remove_process(ret);
	} while (ret > 0);
}

static void do_accept_loop(int sfd, bool nw, struct sockaddr *addr,
			   socklen_t *addrlen)
{
	int cfd, pid;

	do {
		cfd = accept(sfd, addr, addrlen);
		printf("connected!\n");
		if (cfd < 0 && errno == EINTR)
			continue;
		if (cfd < 0)
			pdie("connecting");

		if (nw)
			pid = do_connection_nw(cfd, addr, addrlen);
		else
			pid = do_connection_virt(cfd);
		if (pid > 0)
			add_process(pid);

	} while (!done);
}

static void do_accept_loop_nw(int sfd)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;

	peer_addr_len = sizeof(peer_addr);

	do_accept_loop(sfd, true, (struct sockaddr *)&peer_addr,
		       &peer_addr_len);
}

static void do_accept_loop_virt(int sfd)
{
	struct sockaddr_un un_addr;
	socklen_t un_addrlen;

	un_addrlen = sizeof(un_addr);

	do_accept_loop(sfd, false, (struct sockaddr *)&un_addr, &un_addrlen);
}

static void do_listen_nw(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;

	if (!debug)
		signal_setup(SIGCHLD, clean_up);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening %s", port);

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd < 0)
			continue;

		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		pdie("Could not bind");

	freeaddrinfo(result);

	if (listen(sfd, backlog) < 0)
		pdie("listen");

	do_accept_loop_nw(sfd);

	kill_clients();
}

static void make_virt_if_dir(void)
{
	struct group *group;

	if (mkdir(TRACE_CMD_DIR, 0710) < 0) {
		if (errno != EEXIST)
			pdie("mkdir %s", TRACE_CMD_DIR);
	}

	/* TODO - add command line arg for group?   It varies by distro.*/
#define QEMU_GROUP	"libvirtd"
	chmod(TRACE_CMD_DIR, 0710);
	errno = 0;
	group = getgrnam(QEMU_GROUP);
	if (group == NULL) 
		pdie("getgrnam(QEMU_GROUP)");

	if (chown(TRACE_CMD_DIR, -1, group->gr_gid) < 0)
		pdie("chown %s", TRACE_CMD_DIR);

	if (mkdir(VIRT_DIR, 0710) < 0) {
		if (errno != EEXIST)
			pdie("mkdir %s", VIRT_DIR);
	}
	chmod(VIRT_DIR, 0710);
	if (chown(VIRT_DIR, -1, group->gr_gid) < 0)
		pdie("chown %s", VIRT_DIR);
}

static void do_listen_virt(void)
{
	struct sockaddr_un un_server;
	struct group *group;
	socklen_t slen;
	int sfd;

	make_virt_if_dir();

	slen = sizeof(un_server);
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		pdie("socket");

	un_server.sun_family = AF_UNIX;
	snprintf(un_server.sun_path, PATH_MAX, VIRT_TRACE_CTL_SOCK);

	if (bind(sfd, (struct sockaddr *)&un_server, slen) < 0)
		pdie("bind");
	chmod(VIRT_TRACE_CTL_SOCK, 0660);
	group = getgrnam("qemu");
	if (chown(VIRT_TRACE_CTL_SOCK, -1, group->gr_gid) < 0)
		pdie("fchown %s", VIRT_TRACE_CTL_SOCK);

	if (listen(sfd, backlog) < 0)
		pdie("listen");

	do_accept_loop_virt(sfd);

	unlink(VIRT_TRACE_CTL_SOCK);
	kill_clients();
}

static void start_daemon(void)
{
	if (daemon(1, 0) < 0)
		die("starting daemon");
}

enum {
	OPT_debug	= 255,
};

void trace_listen(int argc, char **argv)
{
	char *logfile = NULL;
	char *port = NULL;
	int daemon = 0;
	int c;
	int nw = 0;
	int virt = 0;

	if (argc < 2)
		usage(argv);

	if ((nw = (strcmp(argv[1], "listen") == 0)))
		; /* do nothing */
	else if ((virt = (strcmp(argv[1], "virt-server") == 0)))
		; /* do nothing */
	else
		usage(argv);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"port", required_argument, NULL, 'p'},
			{"help", no_argument, NULL, '?'},
			{"debug", no_argument, NULL, OPT_debug},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hp:o:d:l:D",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'p':
			if (virt)
				die("-p only available with listen");
			port = optarg;
			break;
		case 'd':
			output_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'D':
			daemon = 1;
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if (!port && nw)
		usage(argv);

	if ((argc - optind) >= 2)
		usage(argv);

	if (!output_file)
		output_file = default_output_file;

	if (!output_dir)
		output_dir = default_output_dir;

	if (logfile) {
		/* set the writes to a logfile instead */
		logfp = fopen(logfile, "w");
		if (!logfp)
			die("creating log file %s", logfile);
	}

	if (chdir(output_dir) < 0)
		die("Can't access directory %s", output_dir);

	if (daemon)
		start_daemon();

	signal_setup(SIGINT, finish);
	signal_setup(SIGTERM, finish);

	if (nw)
		do_listen_nw(port);
	else
		do_listen_virt();

	return;
}
