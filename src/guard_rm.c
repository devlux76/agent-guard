#define _GNU_SOURCE
#include "scope.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { FORCE=1, RECURSE=2, EMPTY_DIR=4, VERBOSE=8, INTERACTIVE=16,
       ONCE=32, ONE_FS=64, PRESERVE_ALL=128 };
static unsigned options;
static char *home, *cwd;
static bool agent(void);

static void die(const char *why) {
    fprintf(stderr, "agent-guard: %s. Nothing was deleted.\n", why);
    exit(2);
}

/* Keep filenames with control characters from forging the preview. */
static void quoted(const char *s) {
    fputc('"',stderr);
    for (const unsigned char *p=(const unsigned char *)s; *p; ++p) {
        if (*p=='"' || *p=='\\') fprintf(stderr,"\\%c", *p);
        else if (*p=='\n') fputs("\\n", stderr);
        else if (*p=='\r') fputs("\\r", stderr);
        else if (*p=='\t') fputs("\\t", stderr);
        else if (*p<32 || *p>=127) fprintf(stderr,"\\u%04x", *p);
        else fputc(*p,stderr);
    }
    fputc('"',stderr);
}

static bool inside(const char *p, const char *root) {
    size_t n=strlen(root);
    return !strncmp(p, root, n) && (p[n]=='/' || p[n]=='\0');
}

/* Resolve parent links, but never follow the final symlink rm would unlink. */
static char *canonical(const char *arg) {
    if (!*arg) die("empty deletion target");
    char *p=strdup(arg);
    if (!p) die("out of memory");
    size_t n=strlen(p);
    while (n>1 && p[n-1]=='/') p[--n]='\0';
    char *slash=strrchr(p, '/');
    const char *base=slash ? slash+1 : p;
    if (!strcmp(base, ".") || !strcmp(base, "..") || !strcmp(p, "/")) {
        char *r=realpath(p, NULL);
        free(p);
        if (!r) die("cannot resolve target");
        return r;
    }
    char *name=strdup(base);
    if (slash) *slash='\0';
    char *parent=realpath(slash ? (*p ? p : "/") : ".", NULL);
    if (!parent || !name) die("cannot resolve target parent");
    char *r=NULL;
    if (asprintf(&r, "%s%s%s", parent, !strcmp(parent,"/") ? "" : "/", name)<0)
        die("out of memory");
    free(name); free(parent); free(p);
    return r;
}

static const char *protected(const char *p, const struct stat *st) {
    if (!(options & RECURSE) || S_ISLNK(st->st_mode)) return NULL;
    if (!strcmp(p,"/")) return "filesystem root";
    if (inside(cwd,p)) return "working directory or its ancestor";
    if (inside(p,home)) {
        const char *rel=p+strlen(home);
        unsigned depth=0;
        for (; *rel; ++rel) if (*rel=='/') ++depth;
        if (depth<=2) return "HOME or within two levels of HOME";
    } else if (!inside(p,"/tmp") && !inside(p,"/var/tmp") &&
               !inside(p,"/dev/shm") && !inside(p,"/run/user")) {
        return "outside HOME and temporary storage";
    } else if (!strcmp(p,"/tmp") || !strcmp(p,"/var/tmp") ||
               !strcmp(p,"/dev/shm") || !strcmp(p,"/run/user")) {
        return "temporary storage root";
    }
    char *git=NULL;
    if (asprintf(&git,"%s/.git",p)<0) die("out of memory");
    struct stat gs;
    bool repository=lstat(git,&gs)==0;
    free(git);
    if (repository && (inside(p,home) || !inside(p,"/tmp")) && !strstr(p,"/.claude/worktrees/"))
        return "git repository root";
    return NULL;
}

static void field(EVP_MD_CTX *ctx, const char *value) {
    uint64_t length=strlen(value);
    if (EVP_DigestUpdate(ctx,&length,sizeof(length))!=1 ||
        EVP_DigestUpdate(ctx,value,length)!=1) die("hash update failed");
}

static int order(const FTSENT **a, const FTSENT **b) {
    return strcmp((*a)->fts_name, (*b)->fts_name);
}

struct Plan { char hash[65]; uint64_t entries, bytes; };

static struct Plan snapshot(char **paths) {
    struct Plan plan={0};
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)!=1) die("hash init failed");
    field(ctx,"agent-guard-rm-v2"); field(ctx,home); field(ctx,cwd);
    char meta[512];
    snprintf(meta,sizeof(meta),"uid=%ju options=%u",(uintmax_t)getuid(),options);
    field(ctx,meta);
    for (char **p=paths; *p; ++p) field(ctx,*p);
    int flags=FTS_PHYSICAL|FTS_NOCHDIR;
    if (options & ONE_FS) flags|=FTS_XDEV;
    FTS *tree=fts_open(paths,flags,order);
    if (!tree) die("cannot inspect deletion targets");
    FTSENT *entry;
    errno=0;
    while ((entry=fts_read(tree))) {
        if (entry->fts_info==FTS_DP) continue;
        if (entry->fts_info==FTS_ERR || entry->fts_info==FTS_DNR || entry->fts_info==FTS_NS)
            die("cannot inspect complete deletion tree");
        const struct stat *s=entry->fts_statp;
        field(ctx,entry->fts_path);
        snprintf(meta,sizeof(meta),"%ju:%ju:%jo:%ju:%ju:%jd:%jd.%09ld:%jd.%09ld",
                 (uintmax_t)s->st_dev,(uintmax_t)s->st_ino,(uintmax_t)s->st_mode,
                 (uintmax_t)s->st_uid,(uintmax_t)s->st_gid,(intmax_t)s->st_size,
                 (intmax_t)s->st_mtim.tv_sec,s->st_mtim.tv_nsec,
                 (intmax_t)s->st_ctim.tv_sec,s->st_ctim.tv_nsec);
        field(ctx,meta);
        ++plan.entries;
        if (S_ISREG(s->st_mode)) plan.bytes+=(uint64_t)s->st_size;
        if (!(options & RECURSE) && entry->fts_info==FTS_D) fts_set(tree,entry,FTS_SKIP);
        errno=0;
    }
    if (errno) die("tree changed or became unreadable during inspection");
    if (fts_close(tree)) die("tree close failed");
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length=0;
    if (EVP_DigestFinal_ex(ctx,digest,&length)!=1 || length!=32) die("hash final failed");
    EVP_MD_CTX_free(ctx);
    for (unsigned i=0;i<32;++i) snprintf(plan.hash+2*i,3,"%02x",digest[i]);
    return plan;
}

static void prune_plans(void) {
    char *path=NULL;
    if (asprintf(&path,"%s/.local/state/agent-guard/plans",home)<0) die("out of memory");
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    free(path);
    if (fd<0) { if (errno==ENOENT) return; die("cannot inspect saved plans"); }
    struct stat st;
    if (fstat(fd,&st) || st.st_uid!=getuid() || (st.st_mode&077))
        die("plan directory must be owned by you and mode 0700");
    DIR *dir=fdopendir(fd);
    if (!dir) { close(fd); die("cannot enumerate saved plans"); }
    time_t now=time(NULL);
    for (;;) {
        errno=0;
        struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) die("cannot enumerate saved plans"); break; }
        const char *name=entry->d_name;
        if (strlen(name)!=64 || strspn(name,"0123456789abcdef")!=64) continue;
        if (fstatat(fd,name,&st,AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
            st.st_uid!=getuid() || (st.st_mode&077)) continue;
        if (now-st.st_mtim.tv_sec>3600 && unlinkat(fd,name,0) && errno!=ENOENT)
            die("cannot prune expired saved plan");
    }
    closedir(dir);
}

static char *planfile(const char *hash) {
    char *dir=NULL;
    if (asprintf(&dir,"%s/.local/state/agent-guard/plans",home)<0) die("out of memory");
    for (char *p=dir+1; ; ++p) {
        if (*p!='/' && *p!='\0') continue;
        char saved=*p; *p='\0';
        if (mkdir(dir,0700) && errno!=EEXIST) die("cannot create private plan directory");
        *p=saved;
        if (!saved) break;
    }
    struct stat st;
    if (lstat(dir,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=getuid() || (st.st_mode&077))
        die("plan directory must be owned by you and mode 0700");
    char *file=NULL;
    if (asprintf(&file,"%s/%s",dir,hash)<0) die("out of memory");
    free(dir);
    return file;
}

static void show_plan(char **paths, struct Plan plan, bool confirmed) {
    fputs(confirmed ? "CONFIRMED — deleting:\n" :
          "DRY RUN — no files deleted. Resolved targets:\n",stderr);
    for (char **p=paths; *p; ++p) { fputs("  ",stderr); quoted(*p); fputc('\n',stderr); }
    fprintf(stderr,"Inventory: %"PRIu64" entries; %"PRIu64" regular-file bytes\nPlan hash: %s\n",
           plan.entries,plan.bytes,plan.hash);
    if (!confirmed) {
        fputs("Execution needs --confirm HASH with these same arguments",stderr);
        fputs(agent() ? ".\n" : ", then human terminal confirmation.\n",stderr);
    }
}

static bool agent(void) {
    const char *keys[]={"AGENT_GUARD_ACTIVE","CODEX_THREAD_ID","CLAUDECODE","OPENCODE",NULL};
    for (const char **k=keys; *k; ++k) if (getenv(*k) && *getenv(*k)) return true;
    return false;
}

int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--internal-agent-chain")) return agent_ancestor() ? 0 : 1;
    if (getenv("AGENT_GUARD_SCOPED") && inside_script()) {
        execv("/usr/bin/rm",argv);
        die("cannot execute system rm for script cleanup");
    }
    static const struct option longs[]={
        {"confirm",required_argument,NULL,1000},{"dry-run",no_argument,NULL,1001},
        {"force",no_argument,NULL,'f'},{"recursive",no_argument,NULL,'r'},
        {"dir",no_argument,NULL,'d'},{"verbose",no_argument,NULL,'v'},
        {"interactive",optional_argument,NULL,1002},
        {"one-file-system",no_argument,NULL,1003},
        {"preserve-root",optional_argument,NULL,1004},
        {"no-preserve-root",no_argument,NULL,1005},{"help",no_argument,NULL,1006},
        {NULL,0,NULL,0}};
    char *confirm=NULL; bool dry=false; int c;
    while ((c=getopt_long(argc,argv,"fiIrRdv",longs,NULL))!=-1) {
        switch(c) {
        case 'f': options=(options&~(INTERACTIVE|ONCE))|FORCE; break;
        case 'i': options=(options&~(FORCE|ONCE))|INTERACTIVE; break;
        case 'I': options=(options&~(FORCE|INTERACTIVE))|ONCE; break;
        case 'r': case 'R': options|=RECURSE; break;
        case 'd': options|=EMPTY_DIR; break;
        case 'v': options|=VERBOSE; break;
        case 1000: if (confirm) die("duplicate --confirm"); confirm=optarg; break;
        case 1001: dry=true; break;
        case 1002:
            options&=~(INTERACTIVE|ONCE);
            if (!optarg || !strcmp(optarg,"always")) { options|=INTERACTIVE; options&=~FORCE; }
            else if (!strcmp(optarg,"once")) { options|=ONCE; options&=~FORCE; }
            else if (strcmp(optarg,"never")) die("invalid --interactive value");
            break;
        case 1003: options|=ONE_FS; break;
        case 1004:
            if (optarg && strcmp(optarg,"all")) die("invalid --preserve-root value");
            if (optarg) options|=PRESERVE_ALL;
            break;
        case 1006: puts("agent-guard rm [GNU rm flags] [--dry-run | --confirm HASH] -- PATH...\n"
                        "Default is preview only (exit 3). Confirmation needs a matching saved plan. Humans also confirm in a terminal."); return 0;
        default: die("unsupported or unsafe rm option");
        }
    }
    if (confirm && dry) die("--confirm and --dry-run cannot be combined");
    if (confirm && (strlen(confirm)!=64 || strspn(confirm,"0123456789abcdef")!=64))
        die("confirmation hash must be the full 64-character plan hash");
    const char *h=getenv("HOME");
    if (!h || !*h || !(home=realpath(h,NULL)) || !strcmp(home,"/")) die("valid HOME required");
    cwd=getcwd(NULL,0); if (!cwd) die("cannot resolve current directory");
    prune_plans();
    char **paths=calloc((size_t)argc+1,sizeof(char *));
    if (!paths) die("out of memory");
    unsigned count=0;
    for (int i=optind;i<argc;++i) {
        char *p=canonical(argv[i]); struct stat st;
        if (lstat(p,&st)) {
            if (errno==ENOENT && (options&FORCE)) { free(p); continue; }
            die("cannot stat deletion target");
        }
        const char *why=protected(p,&st);
        if (why) { fputs("Protected target: ",stderr); quoted(p); fputc('\n',stderr); die(why); }
        if (S_ISDIR(st.st_mode) && !(options&(RECURSE|EMPTY_DIR))) die("directory needs -r or -d");
        paths[count++]=p;
    }
    if (!count) { if (confirm) die("confirmed targets disappeared"); if (options&FORCE) return 0; die("no deletion targets"); }
    struct Plan plan=snapshot(paths);
    if (confirm && strcmp(confirm,plan.hash)) die("deletion plan changed; preview again");
    char *file=planfile(plan.hash);
    if (!confirm) {
        show_plan(paths,plan,false);
        int fd=open(file,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if (fd<0 && errno!=EEXIST) die("cannot save preview plan");
        if (fd>=0) { if (write(fd,plan.hash,64)!=64 || close(fd)) die("cannot save preview plan"); }
        return 3;
    }
    int fd=open(file,O_RDONLY|O_NOFOLLOW);
    struct stat st; char saved[65]={0};
    if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=getuid() ||
        (st.st_mode&077) || read(fd,saved,65)!=64 || strcmp(saved,confirm))
        die("missing or invalid saved preview plan");
    close(fd);
    bool is_agent=agent();
    if (!is_agent) {
        if (!isatty(STDIN_FILENO)) die("human terminal required; piped or unattended approval refused");
        FILE *tty=fopen("/dev/tty","r+");
        if (!tty) die("no controlling human terminal");
        fprintf(tty,"Type DELETE to execute this exact plan, or anything else to cancel: "); fflush(tty);
        char *answer=NULL; size_t size=0;
        ssize_t length=getline(&answer,&size,tty);
        bool yes=length==7 && !memcmp(answer,"DELETE\n",7);
        free(answer); fclose(tty);
        if (!yes) { fputs("agent-guard: cancelled; nothing deleted.\n",stderr); return 3; }
    }
    struct Plan fresh=snapshot(paths);
    if (strcmp(fresh.hash,confirm)) die("deletion plan changed while awaiting confirmation");
    if (unlink(file)) die("cannot consume saved plan");
    char **args=calloc(count+16,sizeof(char *)); unsigned a=0;
    if (!args) die("out of memory");
    args[a++]="/usr/bin/rm";
    if (options&FORCE) args[a++]="-f";
    if (options&RECURSE) args[a++]="-r";
    if (options&EMPTY_DIR) args[a++]="-d";
    if (options&VERBOSE) args[a++]="-v";
    if (!is_agent && (options&INTERACTIVE)) args[a++]="-i";
    if (!is_agent && (options&ONCE)) args[a++]="-I";
    if (options&ONE_FS) args[a++]="--one-file-system";
    if (options&PRESERVE_ALL) args[a++]="--preserve-root=all";
    args[a++]="--";
    for (unsigned i=0;i<count;++i) args[a++]=paths[i];
    show_plan(paths,plan,true);
    fflush(NULL);
    pid_t child=fork();
    if (child<0) die("cannot start system rm");
    if (!child) {
        execv(args[0],args);
        die("cannot execute system rm");
    }
    int status;
    while (waitpid(child,&status,0)<0) {
        if (errno==EINTR) continue;
        fputs("agent-guard: cannot wait for system rm; deletion outcome unknown.\n",stderr);
        return 2;
    }
    if (!WIFEXITED(status)) return WIFSIGNALED(status) ? 128+WTERMSIG(status) : 2;
    if (WEXITSTATUS(status)) return WEXITSTATUS(status);
    bool remaining=false;
    for (unsigned i=0;i<count;++i) {
        if (!lstat(paths[i],&st) || (errno!=ENOENT && errno!=ENOTDIR)) remaining=true;
    }
    if (remaining) fputs("Deletion completed; some requested targets remain or could not be checked.\n",stderr);
    else fprintf(stderr,"Deleted %"PRIu64" entries\n",plan.entries);
    return 0;
}
