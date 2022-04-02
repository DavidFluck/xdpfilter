// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_skiplist.h>
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "xdpfilter.h"
#include "xdpfilter.skel.h"
#include "xdp/libxdp.h"

#define IFINDEX 2
#define MAX_EVENTS 10

const bool blocked = true;

static struct env {
	bool verbose;
	long num_packets;
        long time_period;
} env;

struct context {
        apr_hash_t *prev;
        apr_hash_t *curr;
        apr_pool_t *prev_pool;
        apr_pool_t *curr_pool;
        int sample_fd;
        int blacklist_fd;
} context;

struct element {
        struct apr_skiplist *list;
        unsigned int dest;
} element;

const char *argp_program_version = "xdpratelimit 0.1.0";
const char *argp_program_bug_address = "<david@davidfluck.com>";
const char argp_program_doc[] =
"XDP rate limiter application.\n"
"\n"
"It watches incoming traffic for SYN requests, and drops packets if it detects "
"more than -n SYN packets in the last -s seconds.\n"
"\n"
"USAGE: ./xdpratelimit [-n <num-SYN-packets>] [-m <time-period-seconds>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "num-packets", 'n', "NUM-PACKETS", 3, "Number of SYN packets to trigger on." },
	{ "time-period", 's', "TIME-PERIOD", 60, "The previous interval, in seconds, to scan."},
        { 0 }
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'n':
		errno = 0;
                env.num_packets = strtol(arg, NULL, 10);
                if (errno || env.num_packets <= 0) {
                        fprintf(stderr, "Invalid number of packets: %s\n", arg);
                        argp_usage(state);
                }
		break;
        case 's':
                errno = 0;
                env.time_period = strtol(arg, NULL, 10);
                if (errno || env.time_period <= 0) {
                        fprintf(stderr, "Invalid time period: %s\n", arg);
                        argp_usage(state);
                }
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose) {
		return 0;
        }
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int skiplist_compare(void *a, void*b)
{
        if (*(unsigned int *)a < *(unsigned int *)b) {
                return -1;
        } else if (*(unsigned int *)a == *(unsigned int *)b) {
                return 0;
        } else {
                return 1;
        }
}

/* This might be bad, but because we don't plan to actually remove anything from
 * the skiplists, and because the pool will take care of cleanup anyway, we
 * don't bother defining a proper free function. This is a NOP to satisfy the
 * interface. */
void skiplist_free(void *elem)
{
        return;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
        const struct context *ctx2 = ctx;
        const struct event *e = data;

        unsigned int *host_addr = (unsigned int *) apr_palloc(ctx2->curr_pool, sizeof(unsigned int));
        *host_addr = e->host;
        unsigned short *port = (unsigned short *) apr_palloc(ctx2->curr_pool, sizeof(unsigned short));
        *port = e->port;

        /* Add host to "current" hash table. */
        void *val = apr_hash_get(ctx2->curr, host_addr, 4);

        struct apr_skiplist *list = (struct apr_skiplist *) apr_palloc(ctx2->curr_pool, sizeof(struct apr_skiplist *));
        struct element *elem = (struct element *) apr_palloc(ctx2->curr_pool, sizeof(struct element));

        elem->list = list;
        elem->dest = e->dest;

        if (!val) {
                /* Create a new skiplist to keep track of ports. */
                apr_skiplist_init(&(elem->list), ctx2->curr_pool);

                /* Add the port to the skiplist if it doesn't already exist
                 * (which it absolutely shouldn't). */
                apr_skiplist_replace_compare(elem->list, port, (apr_skiplist_freefunc)apr_skiplist_free, (apr_skiplist_compare)skiplist_compare);

                /* Add the element as the hash key value. */
                apr_hash_set(ctx2->curr, host_addr, 4, elem);
        } else {
                // apr_skiplist_replace_compare(((struct element *)val)->list, port, (apr_skiplist_freefunc)skiplist_free, (apr_skiplist_compare)skiplist_compare);
                apr_skiplist_replace_compare(((struct element *)val)->list, port, (apr_skiplist_freefunc)apr_skiplist_free, (apr_skiplist_compare)skiplist_compare);
        }

	return 0;
}

unsigned int hash_func(const char *key, apr_ssize_t *klen)
{
        /* APR expects an unsigned integer hash value. Fortunately, that's
         * exactly what an IPv4 address is. */

        return (unsigned int)*key;
}

int do_hash_print(void *rec, const void *key, apr_ssize_t klen, const void *value)
{
        apr_skiplist *list = ((struct element *)value)->list;
        apr_skiplistnode *node = apr_skiplist_getlist(list);

        if (!node) {
                return 1;
        }

        struct in_addr src, dest;

        src.s_addr = htonl(*(unsigned int *)key);
        dest.s_addr = htonl(((struct element *)value)->dest);

        fprintf(stdout, "%s -> ", inet_ntoa(src));
        fprintf(stdout, "%s on ports", inet_ntoa(dest));

        void *val;
        void *next;

        do {
                val = apr_skiplist_element(node);
                fprintf(stdout, " %d", *(unsigned int *)val);

                /* Curiously, apr_skiplist_next doesn't actually use the list
                 * pointer. */
                next = apr_skiplist_next(list, &node);
        } while(next);

        fprintf(stdout, "\n");

        return 1;
}

int calculate_rates(void *rec, const void *key, apr_ssize_t klen, const void *value)
{
        void *val;
        struct context *ctx = (struct context *)rec;
        unsigned int prev_count;
        unsigned int curr_count;
        struct itimerspec *curr_value;
        double rate;

        /* Look up the host in the previous time period, if it exists. */
        val = apr_hash_get(ctx->prev, key, sizeof(unsigned int));
        prev_count = 0;

        if (val) {
                prev_count = apr_skiplist_size(((struct element *)val)->list);
        }

        curr_count = apr_skiplist_size(((struct element *)value)->list);

        curr_value = malloc(sizeof(*curr_value));
        timerfd_gettime(ctx->sample_fd, curr_value);

        rate = prev_count * (((long int)(curr_value->it_value.tv_sec))/60.0) + curr_count;
        void *dummy = malloc(sizeof(void *));
        int lost = bpf_map_lookup_elem(ctx->blacklist_fd, key, dummy);
        
        if (rate > 3 && lost) {
                fprintf(stdout, "Adding host to blacklist.\n");
                bpf_map_update_elem(ctx->blacklist_fd, key, &blocked, BPF_NOEXIST);
        }

        if (rate <= 3 && !lost) {
                fprintf(stdout, "Removing host from blacklist.\n");
                bpf_map_delete_elem(ctx->blacklist_fd, key);
        }

        fprintf(stdout, "Rate: %lf\n", rate);

        free(curr_value);
        free(dummy);

        return 1;
}

int make_ghost(void *rec, const void *key, apr_ssize_t klen, const void *value)
{
        struct context *ctx = (struct context *)rec;
        struct element *old_elem = (struct element *)value;

        /* If the prev list has a nonzero length (i.e. we received requests),
         * create a ghost entry of size 0 so rate calculations work properly. */
        if (apr_skiplist_size(old_elem->list) > 0) {
                unsigned int *host_addr = (unsigned int *) apr_palloc(ctx->curr_pool, sizeof(unsigned int));
                *host_addr = *(unsigned int *)key;

                struct apr_skiplist *list = (struct apr_skiplist *) apr_palloc(ctx->curr_pool, sizeof(struct apr_skiplist *));
                struct element *new_elem = (struct element *) apr_palloc(ctx->curr_pool, sizeof(struct element));

                apr_skiplist_init(&list, ctx->curr_pool);

                new_elem->list = list;
                new_elem->dest = old_elem->dest;

                apr_hash_set(ctx->curr, key, 4, new_elem);
        }

        return 1;
}

int swap_hash(struct context *ctx)
{
        apr_hash_t *temp;
        apr_pool_t *temp_pool;

        fprintf(stdout, "Swapping hash tables.\n");

        /* Swap hash tables. */
        temp = ctx->prev;
        ctx->prev = ctx->curr;
        ctx->curr = temp;

        /* Clear the current hash table. */
        apr_hash_clear(ctx->curr);

        /* TOOD: This logic seems sketchy. Could be the source of the segfaults. */
        
        /* Swap pools. */
        apr_pool_clear(ctx->prev_pool);

        temp_pool = ctx->prev_pool;
        ctx->prev_pool = ctx->curr_pool;
        ctx->curr_pool = temp_pool;

        /* Create "ghost" entries for rate calculation.
         * We copy everything non-zero from prev back
         * into curr and set it to zero. */
        apr_hash_do((apr_hash_do_callback_fn_t *)make_ghost, (void *)ctx, ctx->prev);

        return 1;
}

int main(int argc, char **argv)
{
        apr_pool_t *pool;
	struct ring_buffer *rb = NULL;
	struct xdpfilter_bpf *skel;

        apr_initialize();
        atexit(apr_terminate);

        /* Context for our callback function so it has access to the hash
         * tables and memory pools. */
        struct context ctx;

        /* We create two separate pools for the previous and current hash tables
         * This lets us properly free the memory used by individual hash elements. 
         */
        apr_pool_create(&pool, NULL);
        apr_pool_create(&(ctx.prev_pool), NULL);
        apr_pool_create(&(ctx.curr_pool), NULL);

        /* Create our hash tables. prev is for the previous time period, and
         * curr is for the current time period. When we pass a time boundary, we
         * free prev, set prev to curr, and set curr to a new hash table. */
        apr_hashfunc_t hash_func_cb = hash_func;

        /* We allocate the hash tables themselves from the parent pool. */
        ctx.prev = apr_hash_make_custom(pool, hash_func_cb);
        ctx.curr = apr_hash_make_custom(pool, hash_func_cb);

	/* Parse command line arguments */
	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		return err;
        }

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = xdpfilter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load XDP program from our existing bpf_object struct. */
        struct xdp_program *prog = xdp_program__from_bpf_obj(skel->obj, "xdp_syn");
        err = xdp_program__attach(prog, IFINDEX, XDP_MODE_SKB, 0);

        if (err) {
                goto cleanup;
        }

	/* Set up ring buffer.  */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, &ctx, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

        int ringbuf_fd = ring_buffer__epoll_fd(rb);

        struct epoll_event ev, measure_ev, sample_ev, events[MAX_EVENTS];

        int nfds, epollfd;
        epollfd = epoll_create1(0);
        if (epollfd == -1) {
                fprintf(stderr, "epoll_create1\n");
                goto cleanup;
        }

        ev.events = EPOLLIN;
        ev.data.fd = ringbuf_fd;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ringbuf_fd, &ev) == -1) {
                fprintf(stderr, "ringbuf_fd\n");
                goto cleanup;
        }

        /* We need two timers: one for the sampling interval, and one for the
         * measurement interval. */
        int sample_fd = timerfd_create(CLOCK_MONOTONIC, 0);
        int measure_fd = timerfd_create(CLOCK_MONOTONIC, 0);

        ctx.sample_fd = sample_fd;
        ctx.blacklist_fd = bpf_map__fd(skel->maps.blacklist);
       
        sample_ev.events = EPOLLIN;
        sample_ev.data.fd = sample_fd;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sample_fd, &sample_ev) == -1) {
                fprintf(stderr, "sample_fd\n");
                goto cleanup;
        }

        measure_ev.events = EPOLLIN;
        measure_ev.data.fd = measure_fd;

        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, measure_fd, &measure_ev) == -1) {
                fprintf(stderr, "measure_fd\n");
                goto cleanup;
        }

        struct timespec sample_ts = {
               .tv_sec = 20,
               .tv_nsec = 0
        };

        struct timespec measure_ts = {
               .tv_sec = 1,
               .tv_nsec = 0
        };

        struct itimerspec sample_its = {
                .it_interval = sample_ts,
                .it_value = sample_ts
        };

        struct itimerspec measure_its = {
                .it_interval = measure_ts,
                .it_value = measure_ts
        };

        /* Arm the timers. */
        timerfd_settime(sample_fd, 0, &sample_its, NULL);
        timerfd_settime(measure_fd, 0, &measure_its, NULL);

        apr_hash_do_callback_fn_t *hash_do_func_cb = do_hash_print;
        apr_hash_do_callback_fn_t *calculate_rates_cb = calculate_rates;

        while (!exiting) {
               nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
               if (nfds == -1) {
                       fprintf(stderr, "epoll_wait\n");
                       goto cleanup;
               }

               for (int n = 0; n < nfds; ++n) {
                       if (events[n].data.fd == ringbuf_fd) {
                               /* ring_buffer__consume runs our handler callback
                                * function. */
                               ring_buffer__consume(rb);
                       } else if (events[n].data.fd == sample_fd) {
                               uint64_t buf;
                               err = swap_hash(&ctx);
                               read(events[n].data.fd, &buf, sizeof(uint64_t));

                               /* New hash tables. */
                               fprintf(stdout, "curr:\n");
                               apr_hash_do(hash_do_func_cb, NULL, ctx.curr);

                               fprintf(stdout, "prev:\n");
                               apr_hash_do(hash_do_func_cb, NULL, ctx.prev);    
                       } else if (events[n].data.fd == measure_fd) {
                               /* Calculate rates. */
                               fprintf(stdout, "Calculating rates.\n");

                               uint64_t buf;
                               read(events[n].data.fd, &buf, sizeof(uint64_t));

                               fprintf(stdout, "curr:\n");
                               apr_hash_do(hash_do_func_cb, NULL, ctx.curr);

                               fprintf(stdout, "prev:\n");
                               apr_hash_do(hash_do_func_cb, NULL, ctx.prev);

                               void *ctx2 = (void *)&ctx;
                               apr_hash_do(calculate_rates_cb, ctx2, ctx.curr);
                       }
               }
        }

	/* Process events */
	/* while (!exiting) { */
	/* 	err = ring_buffer__poll(rb, 100 /\* timeout, ms *\/); */
	/* 	/\* Ctrl-C will cause -EINTR *\/ */
	/* 	if (err == -EINTR) { */
	/* 		err = 0; */
	/* 		break; */
	/* 	} */
	/* 	if (err < 0) { */
	/* 		printf("Error polling ring buffer: %d\n", err); */
	/* 		break; */
	/* 	} */
	/* } */

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	xdpfilter_bpf__destroy(skel);
        xdp_program__detach(prog, IFINDEX, XDP_MODE_SKB, 0);
        xdp_program__close(prog);

        apr_pool_destroy(pool);

	return err < 0 ? -err : 0;
}
