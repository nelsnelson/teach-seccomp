#include <stdio.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main()
{
	FILE *f1;
	int fd;
	int ret;

	f1 = fopen("/tmp/test1", "w");

	ret = seccomp_init(SCMP_ACT_ERRNO(5));
	if (ret < 0)
		printf("Error from seccomp_init\n");
	ret = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (!ret)
		ret = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
	if (!ret)
		ret = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (!ret)
		ret = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	if (!ret)
		ret = seccomp_load();
	if (ret)
		printf("error setting seccomp\n");

	fprintf(f1, "hi there\n");
	fd = open("/tmp/test2", O_RDWR);
	if (fd >= 0)
		printf("error, was able to open f2\n");
	else
		fprintf(f1, "open returned %d errno %d\n", fd, errno);
	fclose(f1);
	exit(0);
}

