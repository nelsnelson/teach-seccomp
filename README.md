
<!doctype html>
<html>
<head>
    <title>Using simple seccomp filters</title>
    <link href="style.css" rel="stylesheet" type="text/css" />
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
</head>
<body>
<h1>Using simple seccomp filters</h1>

<h2>Introduction</h2>
<div>
The Linux kernel (starting in version 3.5) supports
"<a href="https://github.com/redpig/linux/tree/seccomp">seccomp filter</a>"
(or "mode 2 seccomp"). Ubuntu 12.04 LTS had it backported to its 3.2 kernel,
and Chrome OS has been using it (in various forms) for a while.
This document is designed as a quick-start guide
for software authors that want to take advantage of this security feature.
In the simplest terms, it allows a program to declare ahead of time
which system calls it expects to use, so that if an attacker gains
arbitrary code execution, they cannot poke at any unexpected system calls.
</div>

<div>
The full seccomp filter documentation
can be found in the Linux kernel source, <a
href="http://kernel.ubuntu.com/git?p=ubuntu/ubuntu-precise.git;a=blob;f=Documentation/prctl/seccomp_filter.txt;hb=HEAD">here</a>.
The seccomp filter system uses the Berkley Packet Filter system. Combined
with argument checking and the many possible filter return values (kill, trap, trace, errno), this is
allows for extensive logic. This document seeks to show only the minimal
case of defining a syscall whitelist. Everything not added to this filter
causes the program to be killed.
</div>

<div>
To determine which seccomp features are available at runtime, please
see the <a href="autodetect.html">seccomp autodetection</a> examples.
</div>

<div>
Since it is not always obvious to see which syscalls are being called by
the various libraries a program might use, this document also includes
example code that provides a helper to assist in discovering unwhitelisted
syscalls during filter development.
</div>

<h2>Example Program</h2>

<div>
<a href="step-1/">First</a>, we start with an example program that reads stdin, writes to stdout, sleeps,
and exits. We want to make sure it never calls "fork", so we've added that to the end
so we can verify that seccomp filter is working, once it gets added.

<pre>
/*
 * seccomp example with syscall reporting
 *
 * Copyright (c) 2012 The Chromium OS Authors &lt;chromium-os-dev@chromium.org&gt;
 * Authors:
 *  Kees Cook &lt;keescook@chromium.org&gt;
 *  Will Drewry &lt;wad@chromium.org&gt;
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#define _GNU_SOURCE 1
#include &lt;stdio.h&gt;
#include &lt;stddef.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;unistd.h&gt;

#include "config.h"

int main(int argc, char *argv[])
{
    char buf[1024];

	printf("Type stuff here: ");
	fflush(NULL);
	buf[0] = '\0';
	fgets(buf, sizeof(buf), stdin);
	printf("You typed: %s", buf);

	printf("And now we fork, which should do quite the opposite ...\n");
	fflush(NULL);
	sleep(1);

	fork();
	printf("You should not see this because I'm dead.\n");

	return 0;
}
</pre>
</div>

<div>
When we build and run this now, we get:

<pre>
$ <b>autoconf</b>
$ <b>./configure</b>
checking for gcc... gcc
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
checking for suffix of executables... 
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes
checking for gcc option to accept ISO C89... none needed
configure: creating ./config.status
config.status: creating config.h
$ <b>make</b>
gcc -Wall   -c -o example.o example.c
gcc   example.o   -o example
$ <b>./example</b>
Type stuff here: <b>asdf</b>
You typed: asdf
And now we fork, which should do quite the opposite ...
You should not see this because I'm dead.
You should not see this because I'm dead.
</pre>
</div>

Everything is working, even the "fork" we want to eliminate.

<h2>Adding basic seccomp filtering</h2>
<div>
<a href="step-2/">Next</a>, we include the fancy "<a href="step-2/seccomp-bpf.h">seccomp-bpf.h</a>" header.
Additionally, this also updates
an example "<a href="step-2/configure.ac">configure.ac</a>" to check for the new
"linux/seccomp.h" include, since "seccomp-bpf.h" would like to use it. Then we build
our initial list of basic system calls we expect (signal handling, read, write, exit).
The flow of a simple seccomp BPF starts with verifying the architecture (since syscall
numbers are tied to architecture), and then loads the syscall number and compares
it against the whitelist. If no good match is found, it kills the process:

<pre>
--- step-1/example.c	2012-03-22 21:43:10.845732543 -0700
+++ step-2/example.c	2012-03-22 21:50:56.373304922 -0700
@@ -16,11 +16,54 @@
 #include &lt;unistd.h&gt;
 
 #include "config.h"
+#include "seccomp-bpf.h"
+
+static int install_syscall_filter(void)
+{
+	struct sock_filter filter[] = {
+		/* Validate architecture. */
+		VALIDATE_ARCHITECTURE,
+		/* Grab the system call number. */
+		EXAMINE_SYSCALL,
+		/* List allowed syscalls. */
+		ALLOW_SYSCALL(rt_sigreturn),
+#ifdef __NR_sigreturn
+		ALLOW_SYSCALL(sigreturn),
+#endif
+		ALLOW_SYSCALL(exit_group),
+		ALLOW_SYSCALL(exit),
+		ALLOW_SYSCALL(read),
+		ALLOW_SYSCALL(write),
+		KILL_PROCESS,
+	};
+	struct sock_fprog prog = {
+		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
+		.filter = filter,
+	};
+
+	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
+		perror("prctl(NO_NEW_PRIVS)");
+		goto failed;
+	}
+	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &amp;prog)) {
+		perror("prctl(SECCOMP)");
+		goto failed;
+	}
+	return 0;
+
+failed:
+	if (errno == EINVAL)
+		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
+	return 1;
+}
 
 int main(int argc, char *argv[])
 {
 	char buf[1024];
 
+	if (install_syscall_filter())
+		return 1;
+
 	printf("Type stuff here: ");
 	fflush(NULL);
 	buf[0] = '\0';
--- step-1/configure.ac	2012-03-22 21:40:51.651435417 -0700
+++ step-2/configure.ac	2012-03-22 21:44:19.438868163 -0700
@@ -2,4 +2,5 @@
 AC_PREREQ([2.59])
 AC_CONFIG_HEADERS([config.h])
 AC_PROG_CC
+AC_CHECK_HEADERS([linux/seccomp.h])
 AC_OUTPUT
</pre>
</div>

<div>
While this gets us to a nice starting place, it's not obvious what's still needed when
we run the program, since it just blows up instead:

<pre>
$ <b>./configure</b>
<i>...</i>
checking for linux/seccomp.h... yes
configure: creating ./config.status
config.status: creating config.h
$ <b>make</b>
gcc -Wall   -c -o example.o example.c
gcc   example.o   -o example
$ <b>./example</b>
Bad system call
$ <b>echo $?</b>
159
</pre>
</div>

<h2>Adding syscall reporting</h2>
<div>
<a href="step-3/">Now</a> we can utilize one of the extra features of seccomp filter, and temporarily catch
the failed syscall and report it, instead of immediately exiting. The intention is to
remove this at the end, since once we've finished our syscall list, we won't need to
change it (unless the program or its libraries change, in which case, we can do this
again).
</div>

<div>
Here, we add the "<a href="step-3/syscall-reporter.mk">syscall-reporter.mk</a>" Makefile
include and the "<a href="step-3/syscall-reporter.c">syscall-reporter.c</a>" object to
the Makefile, and then add "<a href="step-3/syscall-reporter.h">syscall-reporter.h</a>"
and a call to "install_syscall_reporter" to the program.

<pre>
--- step-2/example.c	2012-03-22 21:50:56.373304922 -0700
+++ step-3/example.c	2012-03-22 21:51:04.377433872 -0700
@@ -17,6 +17,7 @@
 
 #include "config.h"
 #include "seccomp-bpf.h"
+#include "syscall-reporter.h"
 
 static int install_syscall_filter(void)
 {
@@ -34,6 +35,7 @@
 		ALLOW_SYSCALL(exit),
 		ALLOW_SYSCALL(read),
 		ALLOW_SYSCALL(write),
+		/* Add more syscalls here. */
 		KILL_PROCESS,
 	};
 	struct sock_fprog prog = {
@@ -61,6 +63,8 @@
 {
 	char buf[1024];
 
+	if (install_syscall_reporter())
+		return 1;
 	if (install_syscall_filter())
 		return 1;
 
--- step-2/Makefile	2012-03-22 19:41:02.510347542 -0700
+++ step-3/Makefile	2012-03-22 19:41:33.706847395 -0700
@@ -3,7 +3,9 @@
 
 all: example
 
-example: example.o
+include syscall-reporter.mk
+
+example: example.o syscall-reporter.o
 
 .PHONY: clean
 clean:
</pre>
</div>

<div>
Now, when we run it, we can see the missing syscalls, and progressively add them
until we're up to the fork (which is implemented via the "clone" syscall):

<pre>
$ <b>make</b>
gcc -Wall   -c -o example.o example.c
In file included from example.c:20:0:
syscall-reporter.h:21:2: warning: #warning "You've included the syscall reporter. Do not use in production!" [-Wcpp]
echo "static const char *syscall_names[] = {" &gt; syscall-names.h ;\
        echo "#include &lt;syscall.h&gt;" | cpp -dM | grep '^#define __NR_' | \
                LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([0-9]+)(.*)/ [\2] = "\1",/p' &gt;&gt; syscall-names.h;\
        echo "};" &gt;&gt; syscall-names.h
gcc -Wall   -c -o syscall-reporter.o syscall-reporter.c
In file included from syscall-reporter.c:12:0:
syscall-reporter.h:21:2: warning: #warning "You've included the syscall reporter. Do not use in production!" [-Wcpp]
gcc   example.o syscall-reporter.o   -o example
$ <b>./example</b>
Looks like you need syscall fstat(5) too!
$ <b>vi example.c</b>
...
$ <b>make</b>
gcc -Wall   -c -o example.o example.c
gcc   example.o syscall-reporter.o   -o example
$ <b>./example</b>
Looks like you need syscall mmap(9) too!
$ <b>vi example.c</b>
...
$ <b>make</b>
gcc -Wall   -c -o example.o example.c
gcc   example.o syscall-reporter.o   -o example
$ <b>./example</b>
Type stuff here: <b>asdf</b>
You typed: asdf
And now we fork, which should do quite the opposite ...
Looks like you need syscall rt_sigprocmask(14) too!
$ ...
</pre>
</div>

<h2>Testing is done</h2>
<div>
<a href="step-4/">This</a> continues until we hit the report of the "clone" use, and we know we're done:

<pre>
--- step-3/example.c	2012-03-22 21:51:04.377433872 -0700
+++ step-4/example.c	2012-03-22 21:51:13.577583466 -0700
@@ -36,6 +36,11 @@
 		ALLOW_SYSCALL(read),
 		ALLOW_SYSCALL(write),
 		/* Add more syscalls here. */
+		ALLOW_SYSCALL(fstat),
+		ALLOW_SYSCALL(mmap),
+		ALLOW_SYSCALL(rt_sigprocmask),
+		ALLOW_SYSCALL(rt_sigaction),
+		ALLOW_SYSCALL(nanosleep),
 		KILL_PROCESS,
 	};
 	struct sock_fprog prog = {
</pre>

<pre>
$ <b>./example</b>
Type stuff here: <b>asdf</b>
You typed: asdf
And now we fork, which should do quite the opposite ...
Looks like you need syscall clone(56) too!
</pre>
</div>

<h2>Ready for prime-time</h2>

<div>
<a href="step-5/">Now</a> that we're done, we can remove the syscall reporter again, and see that the
program correctly dies when it hits the fork. (To be really done, the fork should
be removed too!)

<pre>
--- step-4/example.c	2012-03-22 21:51:13.577583466 -0700
+++ step-5/example.c	2012-03-22 21:51:21.785717260 -0700
@@ -17,7 +17,6 @@
 
 #include "config.h"
 #include "seccomp-bpf.h"
-#include "syscall-reporter.h"
 
 static int install_syscall_filter(void)
 {
@@ -35,7 +34,6 @@
 		ALLOW_SYSCALL(exit),
 		ALLOW_SYSCALL(read),
 		ALLOW_SYSCALL(write),
-		/* Add more syscalls here. */
 		ALLOW_SYSCALL(fstat),
 		ALLOW_SYSCALL(mmap),
 		ALLOW_SYSCALL(rt_sigprocmask),
@@ -68,8 +66,6 @@
 {
 	char buf[1024];
 
-	if (install_syscall_reporter())
-		return 1;
 	if (install_syscall_filter())
 		return 1;
 
--- step-4/Makefile	2012-03-22 19:55:27.056164102 -0700
+++ step-5/Makefile	2012-03-22 19:55:33.680270186 -0700
@@ -3,9 +3,7 @@
 
 all: example
 
-include syscall-reporter.mk
-
-example: example.o syscall-reporter.o
+example: example.o
 
 .PHONY: clean
 clean:
</pre>

<pre>
$ <b>./example</b>
Type stuff here: <b>asdf</b>
You typed: asdf
And now we fork, which should do quite the opposite ...
Bad system call
$ <b>echo $?</b>
159
</pre>
</div>

<h2>Conclusion</h2>
<div>
Ta-da! That's it -- you've now got a seccomp filter built into your program. To make this
even more portable, you can ignore the "prctl" failures if seccomp is not available, or
warn the user but not die, or put the entire thing behind a "#ifdef HAVE_LINUX_SECCOMP_H"
test.
</div>

<div>
For more complex, or dynamic, BPF constructions, you'll probably want to take a look
at <a href="http://sourceforge.net/projects/libseccomp/">libseccomp</a>.
</div>

<div>
For a stand-alone filtering tool, check out
<a href="https://gerrit.chromium.org/gerrit/gitweb?p=chromiumos/platform/minijail.git;a=summary">minijail</a>.
</div>

<div>
Thanks for reading! --<a href="mailto:keescook@chromium.org">Kees Cook</a>, Mar-Nov 2012.
</div>

<div>
For reference, this is all under a <a href="LICENSE">BSD license</a>.
</div>

</body>
</html>
