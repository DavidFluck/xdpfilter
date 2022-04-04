## Synopsis

```
XDP rate limiter application.

Watches incoming traffic for SYN requests, and drops packets if it detects more
than -n SYN packets in the last -t seconds on -i interface.

USAGE: ./xdpfilter [-n <num-SYN-packets>] [-t <time-period-seconds>] [-i <interface-name> ] [-v]

  -i, --interface=IFNAME     The interface name to attach to (e.g. eth0).
  -n, --num-packets=NUM      Number of SYN packets to trigger on.
  -t, --time-period=SECONDS  The previous interval, in seconds, to scan.
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

## Build

```
sudo apt install build-essential clang gcc-multilib libapr1 libapr1-dev libelf-dev libpcapdev libz-dev linux-tools-$(uname -r) llvm m4 pkg-config
make
sudo ./xdpfilter
```

## Output

```
2022-04-04T03:43:13+0000: Port scan detected: 3.21.196.164 -> 10.0.0.118 on ports 8000 8001 8002 8003
2022-04-04T03:44:19+0000: Port scan detected: 3.21.196.164 -> 10.0.0.118 on ports 8004
```

Note: the output is somewhat misleading. Due to an implementation detail (swapping two hash tables for previous and current time periods), the output seems to suggest that there was a port scan on ports 8000 through 8003, and then again indepently on just 8004. In reality, this just means that in the past minute, a port scan has been detected, and subsequent lines are the ports that pushed the rate back up over the limit.

## Introduction

This application uses XDP to drop packets from hosts that send a certain amount of SYN packets within a certain time period.

## Dependencies

This was developed on an Ubuntu 20.04.1 Amazon EC2 instance, running Linux kernel 5.11.0-1022-aws. It should work on any Linux system running 5.8 or higher (5.8 being [necessary](https://nakryiko.com/posts/bpf-ringbuf/#bpf-ringbuf-vs-bpf-perfbuf) for the BPF ring buffer. See also: [BPF features by kernel version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)).

Libbpf provides a vmlinux.h header file (vmlinux_511.h for us, symlinked to vmlinux.h), which is designed to smooth over differences across kernel versions. Libbpf provides one based on Linux 5.8, but I've generated one based on 5.11. Regardless, the header itself should cause Clang to to generate BPF CO-RE relocations, allowing our libbpf application to run on arbitrary kernel versions.

The package and kernel dependencies are as follows (assume a Debian-ish system):

build-essential\
clang>=10\
gcc-multilib\
libapr1\
libapr1-dev\
libelf-dev (libbpf dependency)\
libpcap-dev\
libz-dev (libbpf dependency)\
linux-tools (provides bpftool, use `$(uname -r)` for a specific release)
linux>=5.8\
llvm\
m4\
make\
pkg-config

To install on Debian-based systems:

```
sudo apt install build-essential clang gcc-multilib libapr1 libapr1-dev libelf-dev libpcapdev libz-dev linux-tools-$(uname -r) llvm m4 pkg-config
```

Some packages are necessary for the application itself, and others are for the vendored dependencies.

The code was tested on both clang-10 and clang-12. (I initially started developing with clang-12, then verified that downgrading to clang-10, the version provided by the `clang` package on Ubuntu, continued to work, which it does.) Presumably, it should work on clang-11, but that is untested.

### libbpf

I vendor libbpf as a submodule. Some package repositories provide it, but vendoring ensures that this code will always use a more up-to-date version.

### xdp-tools

Similarly, I vendor xdp-tools as a submodule, although that's more out of necessity to provide libxdp, because the Ubuntu repositories don't seem to have it packaged. Therefore, building it is required.

## The Algorithm

At first, I explored a few different ways of counting SYN requests and determining how many occurred within a sliding window, such as a ring buffer with a certain number of buckets representing slices of a time period. This works fine, but as I explored it further, I became concerned with the amount of space the bookkeeping would require, especially if a bad actor decided to send a large number of packets.

Instead, I did some more research and found an interesting solution that [Cloudflare had written about](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/), which involves keeping track of packet counts (per host) for just two time periods: a "current" period and a "previous" period. Then, to compute an approximation of the sliding window, you multiply the count of events in the previous time period with the percentage of the previous time period that is no longer "relevant". For example, if the sampling period is one minute, and you're already 20 seconds into the current minute, the previous minute's count would be multiplied by 0.67 (67%). Finally, you add the total count in the current time period to that value, and that's your count approximation for the sliding window. Cloudflare provides a helpful image:

![Sliding window approximation](images/sliding.png)

For Cloudflare's example, the arithmetic looks like this:

```
rate = 42 * ((60-15)/60) + 18
     = 42 * 0.75 + 18
     = 49.5 requests
```

This method rests on a few assumptions, such as expecting that you receive packets relatively uniformly, but Cloudflare notes that, in practice, it works remarkably well. In my opinion, one nice feature of this algorithm is that your time windows can easily be any arbitrary size, and you only ever need two of them, since you only have to maintain a previous and a current count per host.

## The Implementation

### Userland

I decided to do the userland portion in C, partially because it made using libbpf easier, and partially because I haven't written userland C in a while and I really enjoy it.

I leaned heavily on blog posts and reference material by Andrii Nakryiko, who is one of the authors (if not _the_ author) of libbpf. He also maintains a set of tools called [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), which provides skeletons and helpful functionality for getting started with libbpf. I used the `bootstrap` example of libbpf-bootstrap to scaffold out this project, and then tweaked things (Makefile, etc.) as needed.

### Kernel

The kernel part is the most straightforward: I take apart packet headers until I can grab TCP flags and check for SYNs (but not SYN ACKs). Along the way, I grab the source IP, destination IP, and destination port to send to userspace for bookkeeping and output.

One note is that, in the interest of time, I chose to elide handling VLAN and VLAN-within-VLAN Ethernet packets. To make this work for any network traffic, I would have to adjust the IP header offset by a variable amount, depending on the 802.11q/802.11ad header(s).

## Considerations

## Improvements

I definitely want to improve error handling. Admittedly, I'm making certain happy-path assumptions in spots, which are absolutely not guaranteed to be happy paths.

I also do not necessarily trust all of my memory lifetime management (but I tend not to trust my fallible human ability to 100% correctly manipulate pointers anyway). Given the timeboxed nature of things, though, I would definitely want to look at memory use and memory lifetime more closely, especially considering that this is written in C and improper memory management can lead to severe security problems (remote code execution, etc.).

The bit where I have to make "ghost entries" in the `curr`ent hash table so rate calculations succeed feels kind of gross, but I haven't come up with anything better yet. I was hoping to avoid iterating through one of the hash tables for each swap, as that increases time complexity, but I painted myself into a corner somewhat with my "swap the hash table pointers" strategy.

This is not the cleanest C in general. For example, I think I have some useless or unnecessary numeric casts in certain spots. I always like to have evidence for such things, but at first blush, my "some of this code smells a bit" professional spidey senses are tingling.

I really want to write a man page for this. `man <command>` is so natural for me, and it's jarring when command line tools don't provide man pages, because then I have to run the help command again to pipe it through $PAGER.

main() is kind of long. I should break things out into functions or separate files.
