#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

/* An agent-like host with a version-number comm, not a real model process. */
int main(int argc, char **argv) {
    if (prctl(PR_SET_NAME,"2.1.999",0,0,0)) return 2;
    int command=1;
    while (command<argc && strcmp(argv[command],"--")) ++command;
    if (++command>=argc) return 2;
    pid_t pid=fork();
    if (pid<0) return 2;
    if (!pid) { execvp(argv[command],argv+command); perror("execvp"); _exit(2); }
    int status;
    if (waitpid(pid,&status,0)<0) return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
