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
sudo apt install build-essential \
                 clang \
                 gcc-multilib \
                 libapr1 \
                 libapr1-dev \
                 libelf-dev \
                 libpcap-dev \
                 libz-dev \
                 linux-tools-$(uname -r) \
                 llvm \
                 m4 \
                 pkg-config
git clone --recurse-submodules https://github.com/DavidFluck/xdpfilter.git
cd xdpfilter
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
linux-tools (provides bpftool, use `$(uname -r)` for a specific release)\
linux>=5.8\
llvm>=10\
m4\
make\
pkg-config

To install on Debian-based systems:

```
sudo apt install build-essential clang gcc-multilib libapr1 libapr1-dev libelf-dev libpcap-dev libz-dev linux-tools-$(uname -r) llvm m4 pkg-config
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

## Questions

1. How would you prove the the code is correct?

   I'm reminded of a Dijkstra quote: "Program testing can be a very effective way to show the presence of bugs, but is hopelessly inadequate for showing their absence." That being said, I would still test! It's easy to say "unit testing", but I have to admit, I don't know how straightforward it would be to do proper unit testing with the way I've written a bunch of my functions (at least without falling into the nightmare of mocking out the entire universe ahead of time). I would also generate various test cases (traffic patterns, Christmas tree TCP packets, etc.), and then throw them all at the program while it's running.

   I would stochastically "trial-by-fire" test the program too: let it run in the wild for a long period of time so people can send all manner of random, naughty traffic to it, and see if it blows up.

1. How would you make this solution better?

   I address various specific concerns under [Improvements](#Improvements), but overall, I would:

   - Improve the logging, including properly segmenting out various debug levels.
   - Provide .deb and .rpm packages.
   - Write a man page.
   - Improve the stability of the program so I could be 100% certain that it work properly.

1. Is it possible for this program to miss a connection?

   Yes, I believe so, if the ring buffer gets too full. If `bpf_ringbuf_reserve` fails, we return `XDP_PASS` (to fail open). This is exploitable, though: if you can overwhelm the system and fill up the ring buffer, then all subsequent SYN packets would be passed through. Of course, if you fail closed, bad actors could also potentially exploit that behavior. (DDoS mitigation is hard.)

1. If you weren't following these requirements, how would you solve the problem of logging every new connection?

   One option is to continue to use BPF, but just instrument the kernel and watch something like socket creation calls.

1. Why did you choose make to write the build automation?

   The code itself is in C, as are its dependencies (which themselves use make), so make was the natural choice. Make is also a workhorse: it's been around forever, it's well-understood, and it works.

1. Is there anything else you would test if you had more time?

   I would throw every last weird combination of bits in a TCP packet at this thing until it stopped falling over. I would also want to properly handle VLAN Ethernet packets, which I cut in the interest of time.

1. What is the most important tool, script, or technique you have for solving problems in production? Explain why this tool/script/technique is the most important.

   I think technique is the most important, if I had to rank them; specifically, the ability to sit down and properly debug things.

   I find it difficult to explain how I go about debugging. Broadly, I would say it's a lot of deductive reasoning: you come up with a testable hypothesis about why something is (or, usually, is not) working the way it is, then you go about (dis)proving it. It's difficult to describe because it feels so automatic by now.

   Sometimes things come out of left field, though. For example, the utility library I'm using, the Apache Portable Runtime (APR), provides a skiplist implementation for list-based operations, which I use to keep track of host ports. Crucially, APR requires you to initialize your skiplists before you use them. I was seeing spooky behavior the other day, and my debugging attempts were fruitless. Then, while looking at one of the functions that instantiated skiplists, I happened to notice that I hadn't initialized the new list I was creating. Some pattern recognition part of my brain looked at the code and said: "wait, shouldn't there be an init() function in here?" Suddenly, my bug was fixed.

   Sometimes things just feel "off", or problems look like other problems you've seen before. Knowing how your system or application works is really important too, because all of those implementation details help inform your ability to debug. For example, I hadn't realized that `inet_ntoa()` uses a static buffer internally, so when I called it twice in a row in the same `fprinf` call, the second call site always "won" because the buffer was overwritten. Re-reading the man page cleared this up, and now I know this for next time, but had I known it before, I could've either avoided the bug entirely, or I could've more easily diagnosed the behavior instead of investigating the wrong things.

   Finally, I don't believe that any system is truly, fundamentally unknowable (at least ones that aren't incomprehensibly overwrought), given the right time and energy. Computers do exactly what you tell them, and bugs are just problems you haven't solved yet. If you sit down, and really think, and come up with hypotheses, and eliminate possibilities, you can usually solve them. We control the machines, they don't control us.

1. If you had to deploy this program to hundreds of servers, what would be your preferred method? Why?

   Especially since libbpf promises CO-RE (Compile Once, Run Everywhere), I'd be tempted to maintain deb/rpm packages and then just `apt/yum/whatever install` them across the fleet with some sort of appropriate automation. Ansible is my favorite for managing state like that, but there are always other contenders, and one should never overlook the simplicity of a `deploy.sh` script. This would let us manage the packages as we manage any other system software. Distros and package managers have already solved the harder parts of software distribution, so I think it makes sense to take advantage of that as much as possible.

   Alternatively, if one managed to get this to work inside Docker, and assuming I'm already using Docker elsewhere (probably Kubernetes, etc.), that would be an option as well. I wouldn't go out of my way to shoehorn Docker into this if I didn't have to, though.

1. What is the hardest technical problem or outage you've had to solve in your career? Explain what made it so difficult?

   I'm not sure this is the hard _est_, but it was definitely a series of interesting challenges. At $dayjob, we have a small HTTP service in Golang that provisions resources inside Kubernetes. Until some months ago, we weren't keeping track of that resultant state anywhere. We have backups, but if something were to happen to a namespace or a cluster, the resources would have to be restored instead of put back into place with a tool like FluxCD. To solve this, we decided to migrate to git-based state storage for this service.

   The hardest part was translating git porcelain commands into git plumbing commands. The git library I used, git2go, provided a Go interface to all of libgit2, which means that I had access to a wide arary of functionality, but most of the git porcelain commands don't correspond one to one with the library functions. I read and re-read the Git Book several times to get a handle on git internals, so I could recreate things like branching. At one point (the details escape me and my notes are scarce), I had to debug a problem buried somewhere in libgit2, in its own dependency, libssh2. I ended up recreating a minimum working example in C (using libgit2) to attempt to reproduce the bug and more easily debug the underlying libraries. I did end up fixing the bug (I believe it came down to libssh2 not supporting SSH config files.)

## Improvements

I definitely want to improve error handling. Admittedly, I'm making certain happy-path assumptions in spots, which are absolutely not guaranteed to be happy paths.

I don't necessarily trust all of my memory lifetime management (but I tend not to trust my fallible human ability to 100% correctly manipulate pointers anyway). Given the timeboxed nature of things, though, I would definitely want to look at memory use and memory lifetime more closely, especially considering that this is written in C and improper memory management can lead to severe security problems (remote code execution, etc.).

The bit where I have to make "ghost entries" in the `curr`ent hash table so rate calculations succeed feels kind of gross, but I haven't come up with anything better yet. I was hoping to avoid iterating through one of the hash tables for each swap, as that increases time complexity, but I painted myself into a corner somewhat with my "swap the hash table pointers" strategy.

This is not the cleanest C in general. For example, I think I have some useless or unnecessary numeric casts in certain spots. I always like to have evidence for such things, but at first blush, my "some of this code smells a bit" professional spidey senses are tingling.

I really want to write a man page for this. `man <command>` is so natural for me, and it's jarring when command line tools don't provide man pages, because then I have to run the help command again to pipe it through $PAGER.

main() is kind of long. I should break things out into functions or separate files.

My normal git use involves more feature branches and informative commit messages.
