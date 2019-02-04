# The discRete event protocol emulatIon vesseL (gRaIL)

The gRaIL architecture allows loading binary protocol implementations into a discrete event simulator.
This repository contains a proof-of-concept implementation as a module for the ns-3 simulator and the Linux/amd64 platform.
Our gRaIL implementation is in an early development stage, but already supports loading some common network protocols/networking software.
If you find any bugs or, even better, make an improvement, feel free to share it as an issue or a merge request!

# gRaIL in a Nutshell

In a nutshell, gRaIL executes a protocol binary by intercepting all system calls that the protocol process issues.
The gRaIL architecture is able to maintain perfect repeatability, that is, executing a simulation with identical parameters normally yields identical results.
Also, gRaIL fully runs in *discrete* time.
Thus gRaIL simulations can, run faster than system time if only few events are spawned by the simulated protocols, or slower than system time for large scale simulations without negatively affecting results (different from many real time approaches).

You may find in-depth information on the gRaIL architecture in our associated research article (TODO cite once published).

# Try gRaIL with Docker

The repository contains a docker file that helps you get gRaIL working as fast as possible.
Simply check out the repository and build/run the docker file.
Note that the `--privileged` option is strictly required to allow intercepting system calls via `ptrace`:

```sh
git clone https://gitlab.informatik.hu-berlin.de/grail/grail-module grail
cd grail
docker build -t grail .
docker run --privileged -it grail
```

The docker container will move you to an ns-3 installation with gRaIL locked and loaded!

# Examples

## OLSR example

The OLSR example simulates a wireless network with a regular grid topology or a random disc topology.
Inside the wireless network, OLSR is used to establish routes.
The example can run either ns-3's OLSR or the real-world OLSRd implementation.

One server and one client node are attached to the wireless network via wired CSMA (Ethernet) links.
The client continuously sends packets to the server and the simulation reports the packet delivery ratio.
The packet delivery ratio is indicative for the quality of the routes that OLSR(d) determine.

You can see the available options with by running (inside the Docker container):
```sh
./waf --run 'grail-olsr-example --help'
```

To, e.g., compare OLSRd with link quality (LQ) extensions enabled (the OLSRd default) to the version without LQ (i.e., simple hop count) for five seeds/topologies each, run:

```sh
for i in `seq 1 5`; do ./waf --run "grail-olsr-example --disc=true --olsrLq=true --n=12 --rngRun=$i"; done
# results on our docker system:  98%, 100%, 100%, 97%, 68%
for i in `seq 1 5`; do ./waf --run "grail-olsr-example --disc=true --olsrLq=false --n=12 --rngRun=$i"; done
# results on our docker system: 100%,  98%,  52%, 04%, 06%
```

You may repeat these example runs to observe that the results are fully repeatable between consequtive runs (not necessarily between different systems, though. Should results not be repeatable, please do report this as a bug).

## Iperf3 example

You may also run Iperf as an example with the following instruction:
```
./waf --run 'grail-iperf-example'
```

Again, the `--help` option shows available switches.

# Manual installation

To install this ns-3 gRaIL implementation, you must check out the repository into a compatible ns-3 tree.
We have tested gRaIL for compatilibity with *ns-3.28* and *ns-3.29*.
The location of the grail-module directory must be the *src* directory, the repository-directory should be named *grail*.
To download ns-3.29 *and* install gRaIL, you may follow these instructions:

```sh
  git clone --branch ns-3.29 https://github.com/nsnam/ns-3-dev-git ns-3.29
  cd ns-3.29/src
  git clone https://gitlab.informatik.hu-berlin.de/grail/grail-module grail
  cd ..
  ./waf configure
  # check in output that gRaIL is enabled, then build project:
  ./waf
```

# Supported protocol implementations

As of now, we have tested the following networking software explicitly for compatibility:

 * OLSRd
 * Iperf3

You may, however, try other software.
General socket APIs, netlink protocols, IO, and randomness related functionality is supported.

# Module attributes

The gRaIL module supports a number of attributes that may be set individually for each protocol instance.
For an full list, consult `module/grail.cc`. The examples in the `examples` directory show how to set attributes.
At the time of writing, the gRaIL attributes are:

 - `PrintStdout` (`bool`, default `false`): Print the protocol process's stdout and stderr messages to stdout. Mainly useful for debugging.
 - `MayQuit` (`bool`, default: `false`): If `false`, report an error if the protocol's process terminates. Should be set `false` on server side protocol processes which are not supposed to terminate and to `true` on clients that may terminate.
 - `PollLoopDetection` (`bool`, default: `true`): A feature that massively increases performance via a heuristic if the protocol contains poll loop. Not yet documented or evaluated in any paper, so you may want to disable it for publications.
 - `EnableRouting` (`bool`, default: `true`): The protocol process may modify the simulated node's routing tables via, e.g., netlink kernel subsystems. If you want to disallow this, set the attribute to `false`.
 - `SyscallProcessingTime` (`ns3::Time`, default: `0s`): The system call processing time. If you want to be in sync with the paper, set it to `100ns`. Setting it to `0s` can avoid possible perfect-repeatability limitations arising from protocol-process-introduced differences in the file system between repeated simulation runs. If you disable the `PollLoopDetection`, consider setting `SyscallProcessingTime` to `100ns` if you encounter hangs due to poll loop behavior in emulated protocols.
 - `EnablePreloading` (`bool`, default: `true`): Enables the `libnovdso.so` feature, may be disabled if the vDSO is disabled on the simulation system. See the section on the vDSO below for details and background information.

# Suggested: vDSO system configuration

gRaIL uses the system call barrier for protocol emulation.
On many Linux/amd64 operating systems, a dynamic object called the vDSO is loaded into each process and allows reading some I/O values without the system call barrier.
This feature is supposed to improve performance if a process makes frequent calls of, e.g., gettimeofday, but it leaks information into a process and thus invalidates gRaIL results if not taken care of.
We advice to disable the kernel feature system wide, but our architecture has a countermeasure implemented that will very likely work on your system if you cannot disable vDSO (see further below).

We suggest to disable the vDSO feature globally on your simulation system, as we could not observe any significant differences in simulation performance.
To disable the vDOS globally, simply pass `vdso=0` as a flag to the Linux kernel upon boot.
On Ubuntu/Debian operating systems, this is easiest accomplished by modifying `/etc/default/grub` so that the file contains the following line:
```
GRUB_CMDLINE_LINUX="vdso=0"
```
After the modification, run `update-grub` once as root and reboot the simulation server.

Alternatively, e.g., if you do not have root access on the simulation server, you may make use of our `libnovdso.so` library feature.
This feature is enabled by default for gRaIL as it does not conflict with a system-wide disabled vDSO.

The `libnovdso.so` library is pre-loaded at each protocol process start via the `LD_PRELOADING` environment variable.
The library is built automatically along with the gRaIL module and replaces the four vDSO-affected system calls' library-wrappers to date: `gettimeofday`, `clock_gettime`, `time`, and `getcpu`.
We could not observe any significant performance difference between disabling the vDSO globally and using the wrapper library, but it is possible that a future Linux kernel version extends the usage of the vDSO (althrough this has not happened since the 2.6 release of Linux/amd64).
In this unlikely case, an update to the `libnovdso.so` library is required or simulation results may be invalid, thus our advice to disable the vDSO system wide.
If you opt to rely on the `libnovdso.so` library, you may consult the simulation system's `vdso(7)` man page to see if any additional calls were implemented (please report an issue in this case).

# Extending gRaIL

Since gRaIL operates exclusively on system calls, the obvious way to start extending gRaIL is to implement a missing system call.
The proven workflow for this is as follows:

## (1) Run an unsupported protocol binary

The protocol may just work.
In this case, please report this so we can extend the list.

At some point, you may encounter an error "unsupported system call: \<number\>".
The number reported is the decimal identifier of the Linux/amd64 system call.
As a first step, look up which system call has this number, e.g., via https://filippo.io/linux-syscall-table/.
Next, extend the mapping from numeric to symbolic system call identifiers in `syscname.cc`.

Re-run the unsupported protocol, the error should now report the symbolic name of this unsupported system call.

## (2) Analyze the system call

Look up the man page for the system call (man page section 2) and analyze the functionality of the call.
Consult the paper as a reference to assign one or more system call categories to subsets of the features.
Often, it is not necessary to implement all facets of the system call, as only a small subset of features is used by protocols.
Start with those.

## (3) Provide a handler for the system call

System call handling is initiated by a large case statement that matches on the symbolic system call identifier.
First, extend this list in the method `HandleSyscallBefore` in `grail.cc` with the new system call's identifier.
If the call belongs to category I, you are done at this point and may retry running the unsupported protocol (step 1).

Otherwise, implement and call a handler method for the system call, e.g, `HandleNanoSleep` for syscall `SYS_nanosleep`.
Reading the other system call implementations will help to understand the necessary implementation work.
Once you have implemented the system call, repeat step (1) to test its functionality and find further missing system calls.

## Kernel subsystems

Some larger kernel subsystems are exposed indirectly via system calls.
E.g., socket system calls expose the netlink kernel protocol via netlink sockets, other systems are exposed via the file system.
If the subsystem is large, consider introducing a separate class that provides an interface for the relevant system calls.
The files `netlink.h` and `netlink.cc`, e.g., introduce the `NetlinkSocket` class that implements relevant socket-related system calls specifically for netlink sockets.

## Refactoring

Although individual system-calls-handler implementations are mostly small and code bloat minimized by implementing them as a method in `grail.cc`, the cumulative size of the handlers renders `grail.cc` quite large.
The file accounts for approximately 50% of the total non comment lines of code at the time of writing, so a refactoring is a reasonable act.
Feel free to submit a merge request if you believe you have found an improved file organization or code architecture.
