#include "cache.h"
#include "pkt-line.h"
#include "exec_cmd.h"
#include "chimera.h"
#include "gidit.h"

#include <syslog.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif


static int log_syslog;
static int verbose;
static int reuseaddr;

static const char daemon_usage[] =
"git-gidit-daemon [--key|--key=key] [--host=bootstrap] [--host-port=n]\n"
"           [--chimera-port=n] [--verbose] [--syslog] \n"
"           [--timeout=n] [--max-connections=n]\n"
"           [--base-path=path] [--reuseaddr] [--pid-file=file]\n"
"           [[--listen=host_or_ipaddr] [--port=n]]\n"
"           [directory...]";

/* List of acceptable pathname prefixes */
static char **ok_paths;

/* If this is set, git-daemon-export-ok is not required */
static int export_all_trees;

/* Take all paths relative to this one if non-NULL */
static char *base_path;

/* Timeout, and initial timeout */
static unsigned int timeout;

static char *hostname;
static char *canon_hostname;
static char *ip_address;
static char *tcp_port;

static void logreport(int priority, const char *err, va_list params)
{
	if (log_syslog) {
		char buf[1024];
		vsnprintf(buf, sizeof(buf), err, params);
		syslog(priority, "%s", buf);
	} else {
		/*
		 * Since stderr is set to linebuffered mode, the
		 * logging of different processes will not overlap
		 */
		fprintf(stderr, "[%"PRIuMAX"] ", (uintmax_t)getpid());
		vfprintf(stderr, err, params);
		fputc('\n', stderr);
	}
}

static void logerror(const char *err, ...)
{
	va_list params;
	va_start(params, err);
	logreport(LOG_ERR, err, params);
	va_end(params);
}

static void loginfo(const char *err, ...)
{
	va_list params;
	if (!verbose)
		return;
	va_start(params, err);
	logreport(LOG_INFO, err, params);
	va_end(params);
}

static void NORETURN daemon_die(const char *err, va_list params)
{
	logreport(LOG_ERR, err, params);
	exit(1);
}

//GIDIT-UPCALLS
#define TEST_CHAT 15
#define RETURN_CHAT 16
static ChimeraState * chimera_state;
volatile sig_atomic_t return_interrupt = 0;

void signal_fun(int sig){
	return_interrupt = 1;
}

static void test_fwd (Key ** kp, Message ** mp, ChimeraHost ** hp)
{
	Key *k = *kp;
	Message *m = *mp;
	chat_message message;
	message = *((chat_message *)m->payload);

	if (m->type == TEST_CHAT) {
		logerror("Routing TEST ((%s)%u:%s) To %s\n",message.message,message.pid,get_key_string(&(message.source)),get_key_string(k));
		//chimera_send(chimera_state, message.source, RETURN_CHAT, sizeof(message), (char*)&message);
	}if (m->type == RETURN_CHAT){
		logerror("Routing RETURN ((%s)%u:%s) To %s\n",message.message,message.pid,get_key_string(&(message.source)),get_key_string(k));
		//logerror("Routing RETURN (%s) to %u:%s\n",message.message,message.pid,get_key_string(&(message.source)));
		//chimera_send(chimera_state, *k, RETURN_CHAT, sizeof(message), (char*)&message);
	}
}

static void test_del (Key * k, Message * m)
{
	chat_message message;
	message = *((chat_message *)m->payload);
	if (m->type == TEST_CHAT) {
		logerror("Delivered TEST (%s) from %u:%s\n",message.message,message.pid,get_key_string(&(message.source)));
		chimera_send(chimera_state, message.source, RETURN_CHAT, sizeof(message), (char*)&message);
	} else if (m->type == RETURN_CHAT) {
		logerror("Delivered RETURN (%s) from %u:%s\n",message.message,message.pid,get_key_string(&(message.source)));
		kill(message.pid, SIGUSR1);
	}
}

static void test_update (Key * k, ChimeraHost * h, int joined)
{
	if (joined) {
		fprintf(stderr, "Node %s:%s:%d joined neighbor set\n", k->keystr,
				h->name, h->port);
	} else {
		fprintf(stderr, "Node %s:%s:%d leaving neighbor set\n",
				k->keystr, h->name, h->port);
	}

}


static void gidit_daemon_init(char * bootstrap_addr, int bootstrap_port, int local_port, char * key_str)
{
	Key key;
	ChimeraHost * host = NULL;
	struct sigaction usr_action;
	sigset_t block_mask;

	//Debug, remove later
	export_all_trees = 1;
	//Initialize Chimera nonsense
	chimera_state = chimera_init(local_port);
	if (bootstrap_addr){
		host = host_get(chimera_state, bootstrap_addr, bootstrap_port);
	}

	str_to_key(key_str, &key);
	logerror("Initializing key %s",key.keystr);
	//Set up signal handler
	sigfillset (&block_mask);
	usr_action.sa_handler = signal_fun;
	usr_action.sa_mask = block_mask;
	usr_action.sa_flags = 0;
	sigaction(SIGUSR1, &usr_action, NULL);

	/*    Place upcalls here    */
	chimera_forward (chimera_state, test_fwd);
	chimera_deliver (chimera_state, test_del);
	chimera_update (chimera_state, test_update);
	chimera_setkey (chimera_state, key);
	chimera_register (chimera_state, TEST_CHAT, 1);
	chimera_register (chimera_state, RETURN_CHAT, 1);
	chimera_join(chimera_state, host);
}


static int send_service(void)
{
	char key[256];
	int pktlen;
	Key chimera_key;
	chat_message message;
	ChimeraGlobal *chblob = (ChimeraGlobal *) chimera_state->chimera;

	pktlen = packet_read_line(0, key, sizeof(key));
	if(pktlen==-1)
		die("error reading key");
	message.pid = getpid();
	//memcpy(message,&pid,sizeof(int));
	pktlen = packet_read_line(0, message.message, sizeof(message.message));
	if(pktlen==-1)
		die("error reading message");
	str_to_key (key, &chimera_key);
	key_assign(&(message.source),(chblob->me->key));
	logerror("Sending TEST ((%s)%u:%s) To %s\n",message.message,message.pid,get_key_string(&(message.source)),get_key_string(&chimera_key));
	chimera_send (chimera_state, chimera_key, TEST_CHAT, sizeof(message), (char*)&message);
			         
	while(!return_interrupt){
		sleep(1);
	}
	logerror("Message Returned");

	return -1;
}

static char *xstrdup_tolower(const char *str)
{
	char *p, *dup = xstrdup(str);
	for (p = dup; *p; p++)
		*p = tolower(*p);
	return dup;
}

static void safe_read(int fd, void *buffer, unsigned size)
{
	ssize_t ret = read_in_full(fd, buffer, size);
	if (ret < 0)
		die("read error (%s)", strerror(errno));
	else if (ret < size)
		die("The remote end hung up unexpectedly");
}

static int execute(struct sockaddr *addr)
{
	char flag;

	if (addr) {
		char addrbuf[256] = "";
		int port = -1;

		if (addr->sa_family == AF_INET) {
			struct sockaddr_in *sin_addr = (void *) addr;
			inet_ntop(addr->sa_family, &sin_addr->sin_addr, addrbuf, sizeof(addrbuf));
			port = ntohs(sin_addr->sin_port);
#ifndef NO_IPV6
		} else if (addr && addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6_addr = (void *) addr;

			char *buf = addrbuf;
			*buf++ = '['; *buf = '\0'; /* stpcpy() is cool */
			inet_ntop(AF_INET6, &sin6_addr->sin6_addr, buf, sizeof(addrbuf) - 1);
			strcat(buf, "]");

			port = ntohs(sin6_addr->sin6_port);
#endif
		}
		loginfo("Connection from %s:%d", addrbuf, port);
		setenv("REMOTE_ADDR", addrbuf, 1);
	}
	else {
		unsetenv("REMOTE_ADDR");
	}

	alarm(timeout);
	safe_read(0,&flag,sizeof(char));
	switch((int)flag){
		case GIDIT_PUSHF_MSG:
			logerror("Force");
		case GIDIT_PUSH_MSG:
			logerror("Push message");
			char * pgp_key;
			struct strbuf project_name = STRBUF_INIT;
			uint32_t pgp_len;

			safe_read(0, &pgp_len, sizeof(uint32_t));

			pgp_len = ntohl(pgp_len);
			pgp_key = (char*)malloc(pgp_len);

			logerror("Saferead");

			safe_read(0, pgp_key, pgp_len);

			logerror("strbufread");

			strbuf_getline(&project_name, stdin, '\0');

			logerror("Pushing project %s",project_name.buf);

			break;
		default:
			die("Invalid input flag %d",(int)flag);
			break;
	}
	alarm(0);

	free(hostname);
	free(canon_hostname);
	free(ip_address);
	free(tcp_port);
	hostname = canon_hostname = ip_address = tcp_port = NULL;

	logerror("Protocol error");
	return -1;
}

static int max_connections = 32;

static unsigned int live_children;

static struct child {
	struct child *next;
	pid_t pid;
	struct sockaddr_storage address;
} *firstborn;

static void add_child(pid_t pid, struct sockaddr *addr, int addrlen)
{
	struct child *newborn, **cradle;

	/*
	 * This must be xcalloc() -- we'll compare the whole sockaddr_storage
	 * but individual address may be shorter.
	 */
	newborn = xcalloc(1, sizeof(*newborn));
	live_children++;
	newborn->pid = pid;
	memcpy(&newborn->address, addr, addrlen);
	for (cradle = &firstborn; *cradle; cradle = &(*cradle)->next)
		if (!memcmp(&(*cradle)->address, &newborn->address,
			    sizeof(newborn->address)))
			break;
	newborn->next = *cradle;
	*cradle = newborn;
}

static void remove_child(pid_t pid)
{
	struct child **cradle, *blanket;

	for (cradle = &firstborn; (blanket = *cradle); cradle = &blanket->next)
		if (blanket->pid == pid) {
			*cradle = blanket->next;
			live_children--;
			free(blanket);
			break;
		}
}

/*
 * This gets called if the number of connections grows
 * past "max_connections".
 *
 * We kill the newest connection from a duplicate IP.
 */
static void kill_some_child(void)
{
	const struct child *blanket, *next;

	if (!(blanket = firstborn))
		return;

	for (; (next = blanket->next); blanket = next)
		if (!memcmp(&blanket->address, &next->address,
			    sizeof(next->address))) {
			kill(blanket->pid, SIGTERM);
			break;
		}
}

static void check_dead_children(void)
{
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		const char *dead = "";
		remove_child(pid);
		if (!WIFEXITED(status) || (WEXITSTATUS(status) > 0))
			dead = " (with error)";
		loginfo("[%"PRIuMAX"] Disconnected%s", (uintmax_t)pid, dead);
	}
}

static void handle(int incoming, struct sockaddr *addr, int addrlen)
{
	pid_t pid;

	if (max_connections && live_children >= max_connections) {
		kill_some_child();
		sleep(1);  /* give it some time to die */
		check_dead_children();
		if (live_children >= max_connections) {
			close(incoming);
			logerror("Too many children, dropping connection");
			return;
		}
	}

	if ((pid = fork())) {
		close(incoming);
		if (pid < 0) {
			logerror("Couldn't fork %s", strerror(errno));
			return;
		}

		add_child(pid, addr, addrlen);
		return;
	}

	dup2(incoming, 0);
	dup2(incoming, 1);
	close(incoming);

	exit(execute(addr));
}

static void child_handler(int signo)
{
	/*
	 * Otherwise empty handler because systemcalls will get interrupted
	 * upon signal receipt
	 * SysV needs the handler to be rearmed
	 */
	signal(SIGCHLD, child_handler);
}

static int set_reuse_addr(int sockfd)
{
	int on = 1;

	if (!reuseaddr)
		return 0;
	return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			  &on, sizeof(on));
}

#ifndef NO_IPV6

static int socksetup(char *listen_addr, int listen_port, int **socklist_p)
{
	int socknum = 0, *socklist = NULL;
	int maxfd = -1;
	char pbuf[NI_MAXSERV];
	struct addrinfo hints, *ai0, *ai;
	int gai;
	long flags;

	sprintf(pbuf, "%d", listen_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(listen_addr, pbuf, &hints, &ai0);
	if (gai)
		die("getaddrinfo() failed: %s", gai_strerror(gai));

	for (ai = ai0; ai; ai = ai->ai_next) {
		int sockfd;

		sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sockfd < 0)
			continue;
		if (sockfd >= FD_SETSIZE) {
			logerror("Socket descriptor too large");
			close(sockfd);
			continue;
		}

#ifdef IPV6_V6ONLY
		if (ai->ai_family == AF_INET6) {
			int on = 1;
			setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				   &on, sizeof(on));
			/* Note: error is not fatal */
		}
#endif

		if (set_reuse_addr(sockfd)) {
			close(sockfd);
			continue;
		}

		if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(sockfd);
			continue;	/* not fatal */
		}
		if (listen(sockfd, 5) < 0) {
			close(sockfd);
			continue;	/* not fatal */
		}

		flags = fcntl(sockfd, F_GETFD, 0);
		if (flags >= 0)
			fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC);

		socklist = xrealloc(socklist, sizeof(int) * (socknum + 1));
		socklist[socknum++] = sockfd;

		if (maxfd < sockfd)
			maxfd = sockfd;
	}

	freeaddrinfo(ai0);

	*socklist_p = socklist;
	return socknum;
}

#else /* NO_IPV6 */

static int socksetup(char *listen_addr, int listen_port, int **socklist_p)
{
	struct sockaddr_in sin;
	int sockfd;
	long flags;

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(listen_port);

	if (listen_addr) {
		/* Well, host better be an IP address here. */
		if (inet_pton(AF_INET, listen_addr, &sin.sin_addr.s_addr) <= 0)
			return 0;
	} else {
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return 0;

	if (set_reuse_addr(sockfd)) {
		close(sockfd);
		return 0;
	}

	if ( bind(sockfd, (struct sockaddr *)&sin, sizeof sin) < 0 ) {
		close(sockfd);
		return 0;
	}

	if (listen(sockfd, 5) < 0) {
		close(sockfd);
		return 0;
	}

	flags = fcntl(sockfd, F_GETFD, 0);
	if (flags >= 0)
		fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC);

	*socklist_p = xmalloc(sizeof(int));
	**socklist_p = sockfd;
	return 1;
}

#endif

static int service_loop(int socknum, int *socklist)
{
	struct pollfd *pfd;
	int i;

	pfd = xcalloc(socknum, sizeof(struct pollfd));

	for (i = 0; i < socknum; i++) {
		pfd[i].fd = socklist[i];
		pfd[i].events = POLLIN;
	}

	signal(SIGCHLD, child_handler);

	for (;;) {
		int i;

		check_dead_children();

		if (poll(pfd, socknum, -1) < 0) {
			if (errno != EINTR) {
				logerror("Poll failed, resuming: %s",
				      strerror(errno));
				sleep(1);
			}
			continue;
		}

		for (i = 0; i < socknum; i++) {
			if (pfd[i].revents & POLLIN) {
				struct sockaddr_storage ss;
				unsigned int sslen = sizeof(ss);
				int incoming = accept(pfd[i].fd, (struct sockaddr *)&ss, &sslen);
				if (incoming < 0) {
					switch (errno) {
					case EAGAIN:
					case EINTR:
					case ECONNABORTED:
						continue;
					default:
						die("accept returned %s", strerror(errno));
					}
				}
				handle(incoming, (struct sockaddr *)&ss, sslen);
			}
		}
	}
}

/* if any standard file descriptor is missing open it to /dev/null */
static void sanitize_stdfds(void)
{
	int fd = open("/dev/null", O_RDWR, 0);
	while (fd != -1 && fd < 2)
		fd = dup(fd);
	if (fd == -1)
		die("open /dev/null or dup failed: %s", strerror(errno));
	if (fd > 2)
		close(fd);
}

static void store_pid(const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f)
		die("cannot open pid file %s: %s", path, strerror(errno));
	if (fprintf(f, "%"PRIuMAX"\n", (uintmax_t) getpid()) < 0 || fclose(f) != 0)
		die("failed to write pid file %s: %s", path, strerror(errno));
}

static int serve(char *listen_addr, int listen_port)
{
	int socknum, *socklist;

	socknum = socksetup(listen_addr, listen_port, &socklist);
	if (socknum == 0)
		die("unable to allocate any listen sockets on host %s port %u",
		    listen_addr, listen_port);

	return service_loop(socknum, socklist);
}


int main(int argc, char **argv)
{
	int listen_port = 0;
	char *listen_addr = NULL;
	const char *pid_file = NULL;
	int i;
	char *bootstrap_addr = NULL;
	int bootstrap_port = 0;
	int chimera_port = 0;
	char *key = NULL;

	git_extract_argv0_path(argv[0]);

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--key")) {
			key = "zzzzzzzzzzzzzzzzzzzzzzzz";
			continue;
		}
		if (!prefixcmp(arg, "--key=")) {
			key = arg + 6;
			continue;
		}
		if (!prefixcmp(arg, "--listen=")) {
			listen_addr = xstrdup_tolower(arg + 9);
			continue;
		}
		if (!prefixcmp(arg, "--port=")) {
			char *end;
			unsigned long n;
			n = strtoul(arg+7, &end, 0);
			if (arg[7] && !*end) {
				listen_port = n;
				continue;
			}
		}
		if(!prefixcmp(arg, "--host=")){
			bootstrap_addr = xstrdup_tolower(arg+7);
			continue;
		}
		if(!prefixcmp(arg, "--host-port=")){
			char *end;
			unsigned long n;
			n = strtoul(arg+12, &end, 0);
			if (arg[12] && !*end) {
				bootstrap_port = n;
				continue;
			}
		}
		if(!prefixcmp(arg, "--chimera-port=")){
			char *end;
			unsigned long n;
			n = strtoul(arg+15, &end, 0);
			if (arg[15] && !*end) {
				chimera_port = n;
				continue;
			}
			continue;
		}
		if (!strcmp(arg, "--verbose")) {
			verbose = 1;
			continue;
		}
		if (!strcmp(arg, "--syslog")) {
			log_syslog = 1;
			continue;
		}
		if (!prefixcmp(arg, "--timeout=")) {
			timeout = atoi(arg+10);
			continue;
		}
		if (!prefixcmp(arg, "--max-connections=")) {
			max_connections = atoi(arg+18);
			if (max_connections < 0)
				max_connections = 0;	        /* unlimited */
			continue;
		}
		if (!prefixcmp(arg, "--base-path=")) {
			base_path = arg+12;
			continue;
		}
		if (!strcmp(arg, "--reuseaddr")) {
			reuseaddr = 1;
			continue;
		}
		if (!prefixcmp(arg, "--pid-file=")) {
			pid_file = arg + 11;
			continue;
		}
		if (!strcmp(arg, "--")) {
			ok_paths = &argv[i+1];
			break;
		} else if (arg[0] != '-') {
			ok_paths = &argv[i];
			break;
		}

		usage(daemon_usage);
	}

	if (log_syslog) {
		openlog("git-daemon", LOG_PID, LOG_DAEMON);
		set_die_routine(daemon_die);
	} else
		/* avoid splitting a message in the middle */
		setvbuf(stderr, NULL, _IOLBF, 0);

	if (listen_port == 0)
		listen_port = DEFAULT_GIT_PORT;

	if (base_path && !is_directory(base_path))
		die("base-path '%s' does not exist or is not a directory",
		    base_path);

	if (chimera_port == 0)
		chimera_port = DEFAULT_CHIMERA_PORT;

	if (!key) {
		unsigned char keyBuf[20];
		char shaBuf[41];
		int i;
		srand(time(NULL));
		
		for(i = 0; i < sizeof(keyBuf); i++){
			keyBuf[i] = (unsigned char) (rand()%256);
		}

		sprintf(shaBuf, "%s", sha1_to_hex(keyBuf));
		shaBuf[40] = '\0';
		key = shaBuf;
	}
	gidit_daemon_init(bootstrap_addr, bootstrap_port, chimera_port, key);
	
	sanitize_stdfds();

	if (pid_file)
		store_pid(pid_file);

	return serve(listen_addr, listen_port);
}
