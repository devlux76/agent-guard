#define _GNU_SOURCE
#include "scope.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ssize_t proc_read(long pid, const char *name, char *buf, size_t size) {
    char path[96];
    snprintf(path,sizeof(path),"/proc/%ld/%s",pid,name);
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t n=read(fd,buf,size-1);
    close(fd);
    if (n>=0) buf[n]='\0';
    return n;
}

static bool one_of(const char *name, const char *const *names) {
    for (; *names; ++names) if (!strcmp(name,*names)) return true;
    return false;
}

/* Shell command strings are transparent; a script-file invocation is not. */
static bool script_arguments(char **argv, unsigned count) {
    const char *name=strrchr(argv[0],'/');
    name=name ? name+1 : argv[0];
    if (*name=='-') ++name;
    static const char *const shells[]={"sh","bash","dash","zsh","ksh","fish",NULL};
    static const char *const runners[]={"make","gmake","ninja","cmake","ctest","meson",
        "pytest","pytest-3","npm","npx","pnpm","yarn","cargo","just","rake",NULL};
    if (one_of(name,runners)) return true;
    bool shell=one_of(name,shells);
    bool interpreter=shell || !strncmp(name,"python",6) || !strncmp(name,"pypy",4) ||
        !strcmp(name,"bun") || !strcmp(name,"node") || !strcmp(name,"nodejs") ||
        !strcmp(name,"deno") || !strcmp(name,"ruby") || !strcmp(name,"perl") ||
        !strcmp(name,"php") || !strncmp(name,"lua",3);
    if (!interpreter) return false;
    for (unsigned i=1;i<count;++i) {
        const char *a=argv[i];
        if (!strcmp(a,"-")) return false; // inline stdin / here-document, not a file
        if (!strcmp(a,"--")) return i+1<count;
        if (!strcmp(a,"--command") || !strcmp(a,"--eval") || !strcmp(a,"--print") ||
            !strncmp(a,"--eval=",7) || !strncmp(a,"--print=",8)) return false;
        if (a[0]=='-' && a[1] && a[1]!='-') {
            if (shell && (strchr(a+1,'c') || strchr(a+1,'s'))) return false;
            if (!shell && (!strcmp(a,"-c") || !strncmp(a,"-e",2) || !strcmp(a,"-p"))) return false;
            if (!shell && !strcmp(a,"-m")) return true;
        }
        static const char *const takes_value[]={"-o","-O","--rcfile","--init-file",
            "--init-command","-W","-X","-r","--require","--loader","--import",
            "--cwd","--preload","--config",NULL};
        if (one_of(a,takes_value)) { ++i; continue; }
        if (a[0]!='-') return true;
    }
    return false;
}

bool inside_script(void) {
    long pid=getppid();
    for (unsigned hops=0;pid>1 && hops<32;++hops) {
        char comm[96],buf[32768];
        if (proc_read(pid,"comm",comm,sizeof(comm))<=0) return false;
        comm[strcspn(comm,"\n")]='\0';
        if (!strcmp(comm,"codex") || !strncmp(comm,"codex-code-mode",15) ||
            !strcmp(comm,"claude") || !strcmp(comm,"opencode") || !strcmp(comm,"qoder"))
            return false; // do not inspect the agent host's own implementation
        ssize_t length=proc_read(pid,"cmdline",buf,sizeof(buf));
        if (length>0 && length<(ssize_t)sizeof(buf)-1) {
            char *argv[128]; unsigned count=0;
            for (ssize_t i=0;i<length && count<128;) {
                char *end=memchr(buf+i,'\0',(size_t)(length-i));
                if (!end) break;
                argv[count++]=buf+i;
                i=(end-buf)+1;
            }
            if (count && script_arguments(argv,count)) return true;
        }
        if (proc_read(pid,"stat",buf,sizeof(buf))<=0) return false;
        char *end=strrchr(buf,')'),state;
        long parent;
        if (!end || sscanf(end+1," %c %ld",&state,&parent)!=2 || parent==pid)
            return false;
        pid=parent;
    }
    return false; // unknown or vanished ancestry stays gated
}
