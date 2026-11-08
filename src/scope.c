#define _GNU_SOURCE
#include "scope.h"
#include <fcntl.h>
#include <limits.h>
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

static const char *basename_of(const char *path) {
    const char *name=strrchr(path,'/');
    name=name ? name+1 : path;
    return *name=='-' ? name+1 : name;
}

static bool agent_frame(long pid, const char *comm, const char *argv0) {
    static const char *const names[]={"claude","codex","opencode","qoder",NULL};
    if (one_of(comm,names) || !strncmp(comm,"codex-code-mode",15) ||
        (argv0 && one_of(basename_of(argv0),names))) return true;
    const char *home=getenv("HOME");
    char canonical_home[PATH_MAX],path[96],exe[PATH_MAX],prefix[PATH_MAX];
    if (!home || !realpath(home,canonical_home)) return false;
    snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
    ssize_t n=readlink(path,exe,sizeof(exe)-1);
    if (n<0) return false;
    exe[n]='\0';
    int length=snprintf(prefix,sizeof(prefix),"%s/.local/share/claude/versions/",canonical_home);
    return length>0 && (size_t)length<sizeof(prefix) && !strncmp(exe,prefix,(size_t)length);
}

static long parent_of(long pid) {
    char buf[32768],state; long parent;
    if (proc_read(pid,"stat",buf,sizeof(buf))<=0) return 0;
    char *end=strrchr(buf,')');
    if (!end || sscanf(end+1," %c %ld",&state,&parent)!=2 || parent==pid) return 0;
    return parent;
}

bool agent_ancestor(void) {
    long pid=getppid();
    for (unsigned hops=0;pid>1 && hops<32;++hops) {
        char comm[96],args[32768];
        if (proc_read(pid,"comm",comm,sizeof(comm))<=0) return false;
        comm[strcspn(comm,"\n")]='\0';
        ssize_t n=proc_read(pid,"cmdline",args,sizeof(args));
        if (agent_frame(pid,comm,n>0 ? args : NULL)) return true;
        pid=parent_of(pid);
    }
    return false;
}

static bool inline_fd(const char *path) {
    return !strncmp(path,"/dev/fd/",8) || !strncmp(path,"/proc/self/fd/",14);
}

/* Shell command strings are transparent; a script-file invocation is not. */
static bool script_arguments(char **argv, unsigned count) {
    const char *name=basename_of(argv[0]);
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
    bool python=!strncmp(name,"python",6) || !strncmp(name,"pypy",4);
    bool perl=!strcmp(name,"perl");
    const char *eval=python ? "c" : perl ? "eE" : !strcmp(name,"php") ? "r" : "ep";
    const char *value=python ? "WX" : perl ? "IiF" : "r";
    for (unsigned i=1;i<count;++i) {
        const char *a=argv[i];
        if (!strcmp(a,"-")) return false; // inline stdin / here-document, not a file
        if (!strcmp(a,"--")) return i+1<count && !inline_fd(argv[i+1]);
        if (!strcmp(a,"--command") || !strcmp(a,"--eval") || !strcmp(a,"--print") ||
            !strncmp(a,"--eval=",7) || !strncmp(a,"--print=",8)) return false;
        if (a[0]=='-' && a[1] && a[1]!='-') {
            if (shell && (strchr(a+1,'c') || strchr(a+1,'s'))) return false;
            if (!shell) for (const char *p=a+1; *p; ++p) {
                if (strchr(eval,*p)) return false;
                if (python && *p=='m') return true;
                if (strchr(value,*p)) break; // following bytes are an option value
            }
        }
        static const char *const takes_value[]={"-o","-O","--rcfile","--init-file",
            "--init-command","-W","-X","-r","--require","--loader","--import",
            "--cwd","--preload","--config",NULL};
        if (one_of(a,takes_value)) { ++i; continue; }
        if (a[0]!='-') return !inline_fd(a);
    }
    return false;
}

bool inside_script(void) {
    long pid=getppid();
    for (unsigned hops=0;pid>1 && hops<32;++hops) {
        char comm[96],buf[32768];
        if (proc_read(pid,"comm",comm,sizeof(comm))<=0) return false;
        comm[strcspn(comm,"\n")]='\0';
        ssize_t length=proc_read(pid,"cmdline",buf,sizeof(buf));
        if (agent_frame(pid,comm,length>0 ? buf : NULL)) return false;
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
        pid=parent_of(pid);
    }
    return false; // unknown or vanished ancestry stays gated
}
