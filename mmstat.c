#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "mmstat.h"
#include "ssp_list_pub.h"

static void * (*real_malloc)(size_t);
static void   (*real_free)(void *ptr);
static void * (*real_calloc)(size_t nmemb, size_t size);
static void * (*real_realloc)(void *ptr, size_t size);

volatile long g_mem_malloc_cnt;
volatile long g_mem_malloc_size;

static pthread_mutex_t initialization_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t spin_lock_internal;

SSP_LIST_HEAD(g_pstMalloc_list);	/* list for list all mem alloc */

/* Default memory Limit of 2GiB. Override with env MY_RAM_LIMIT. */
static size_t memory_limit = 1024L * 1024L * 1024L * 2L;
static bool is_initializing;

log_level_e curent_log_level = LOG_ERROR;
FILE *g_memdbg_fp;

static void init(void) {
    char *ram_limit;

    if (real_malloc) {
        return;
    }
    pthread_mutex_lock(&initialization_mutex);
    /* I think this double check is an anti-pattern.
     * Let's do it here. Nobody is watching. And it will save time.
     */
    if (real_malloc) {
        pthread_mutex_unlock(&initialization_mutex);
        return;
    }

    is_initializing = true;

    LOG(LOG_INFO, "** Initializing **");

    LOG(LOG_INFO, "USING uthash version " STR(UTHASH_VERSION));

    ram_limit = getenv ("MY_RAM_LIMIT");

    if (ram_limit) {
        memory_limit = atoll(ram_limit); /* TODO: Use strtoll and validate. */
        LOG(LOG_INFO, "MY_RAM_LIMIT set. Using: %zu", memory_limit);
    } else {
        LOG(LOG_INFO, "MY_RAM_LIMIT ***NOT*** set. Using default of: %zu. "
                "Override with env MY_RAM_LIMIT.", memory_limit);
    }


    /* Initialize the spinlock first. */
    if(pthread_spin_init(&spin_lock_internal, PTHREAD_PROCESS_SHARED)) {
        DIE("Error in `pthread_spin_init`");
    }

    if (!((real_malloc = dlsym(RTLD_NEXT, "malloc")) &&
                (real_free = dlsym(RTLD_NEXT, "free")) &&
                (real_calloc = dlsym(RTLD_NEXT, "calloc")) &&
                (real_realloc = dlsym(RTLD_NEXT, "realloc"))
         )) {
        DIE("Error in `dlsym`: %s", dlerror());
    }

    is_initializing = false;
    pthread_mutex_unlock(&initialization_mutex);
}

void *malloc(size_t size) {
    MALLOC_HEADER *p;
    size_t malloc_len = size + PROTECT_LEN;
    if (is_initializing) {
        extern void *__libc__malloc(size_t);
        return __libc__malloc(size);
    }

    init();
    p = real_malloc(malloc_len);
    if (p) {
        malloc_record(p, size);
        __sync_add_and_fetch(&g_mem_malloc_cnt, 1);
        __sync_add_and_fetch(&g_mem_malloc_size, size);
    } else {
        return NULL;
    }
    return p->data;
}

void *calloc(size_t nmemb, size_t size) {
    MALLOC_HEADER *p;
    size_t malloc_len = size * nmemb + PROTECT_LEN;
    if (is_initializing) {
        extern void *__libc_calloc(size_t, size_t);
        return __libc_calloc(nmemb, size);
    }
    init();

    p = real_calloc(1, malloc_len);
    if (p) {
        malloc_record(p, size);
        __sync_add_and_fetch(&g_mem_malloc_cnt, 1);
        __sync_add_and_fetch(&g_mem_malloc_size, size * nmemb);
        return p->data;
    } else {
        return NULL;
    }
}

static const char __HEX[] = "0123456789abcdef";
static char *__safe_utoa(int _base, uint64_t val, char *buf)
{
    uint32_t base = (uint32_t) _base;
    *buf-- = 0;
    do {
        *buf-- = __HEX[val % base];
    } while ((val /= base) != 0);
    return buf + 1;
}

static char *__safe_itoa(int base, int64_t val, char *buf)
{
    char *orig_buf = buf;
    const int32_t is_neg = (val < 0);
    *buf-- = 0;

    if (is_neg) {
        val = -val;
    }
    if (is_neg && base == 16) {
        int ix;
        val -= 1;
        for (ix = 0; ix < 16; ++ix)
            buf[-ix] = '0';
    }

    do {
        *buf-- = __HEX[val % base];
    } while ((val /= base) != 0);

    if (is_neg && base == 10) {
        *buf-- = '-';
    }

    if (is_neg && base == 16) {
        int ix;
        buf = orig_buf - 1;
        for (ix = 0; ix < 16; ++ix, --buf) {
            /* *INDENT-OFF* */
            switch (*buf) {
            case '0': *buf = 'f'; break;
            case '1': *buf = 'e'; break;
            case '2': *buf = 'd'; break;
            case '3': *buf = 'c'; break;
            case '4': *buf = 'b'; break;
            case '5': *buf = 'a'; break;
            case '6': *buf = '9'; break;
            case '7': *buf = '8'; break;
            case '8': *buf = '7'; break;
            case '9': *buf = '6'; break;
            case 'a': *buf = '5'; break;
            case 'b': *buf = '4'; break;
            case 'c': *buf = '3'; break;
            case 'd': *buf = '2'; break;
            case 'e': *buf = '1'; break;
            case 'f': *buf = '0'; break;
            }
            /* *INDENT-ON* */
        }
    }
    return buf + 1;
}

static const char *__safe_check_longlong(const char *fmt, int32_t * have_longlong)
{
    *have_longlong = false;
    if (*fmt == 'l') {
        fmt++;
        if (*fmt != 'l') {
            *have_longlong = (sizeof(long) == sizeof(int64_t));
        } else {
            fmt++;
            *have_longlong = true;
        }
    }
    return fmt;
}

static int __safe_vsnprintf(char *to, size_t size, const char *format, va_list ap)
{
    char *start = to;
    char *end = start + size - 1;
    for (; *format; ++format) {
        int32_t have_longlong = false;
        unsigned char zero;
        uint32_t width = 0;
        int32_t left_align = 0;
        if (*format != '%') {
            if (to == end) {    /* end of buffer */
                break;
            }
            *to++ = *format;    /* copy ordinary char */
            continue;
        }
        ++format;               /* skip '%' */

        if(*format == '-') {
            format++;
            left_align = 1;
        }

        /* judge 0 with number like prefix*/
        zero = (unsigned char) (((*format == '0') && (left_align == 0))? '0' : ' ');
        while (*format >= '0' && *format <= '9') {
            width = width * 10 + *format++ - '0';
        }

        format = __safe_check_longlong(format, &have_longlong);

        switch (*format) {
        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'p':
            {
                int64_t ival = 0;
                uint64_t uval = 0;
                if (*format == 'p')
                    have_longlong = (sizeof(void *) == sizeof(uint64_t));
                if (have_longlong) {
                    if (*format == 'u') {
                        uval = va_arg(ap, uint64_t);
                    } else {
                        ival = va_arg(ap, int64_t);
                    }
                } else {
                    if (*format == 'u') {
                        uval = va_arg(ap, uint32_t);
                    } else {
                        ival = va_arg(ap, int32_t);
                    }
                }

                {
                    char buff[22];
                    uint32_t len;
                    const int base = (*format == 'x' || *format == 'p') ? 16 : 10;

		            /* *INDENT-OFF* */
                    char *val_as_str = (*format == 'u') ?
                        __safe_utoa(base, uval, &buff[sizeof(buff) - 1]) :
                        __safe_itoa(base, ival, &buff[sizeof(buff) - 1]);
		            /* *INDENT-ON* */

                    /* Strip off "ffffffff" if we have 'x' format without 'll' */
                    if (*format == 'x' && !have_longlong && ival < 0) {
                        val_as_str += 8;
                    }

                    /* gen 0 prefix */
                    len = &buff[sizeof(buff) - 1] - val_as_str;

                    if(left_align == 0) {
                        while (len++ < width && to < end) {
                            *to++ = zero;
                        }
                    }
                    while (*val_as_str && to < end) {
                        *to++ = *val_as_str++;
                    }

                    if(left_align) {
                        while (len++ < width && to < end) {
                            *to++ = zero;
                        }
                    }
                    continue;
                }
            }
        case 'c':
            {
                int32_t ival = va_arg(ap, int32_t);
                *to++ = (unsigned char) (ival & 0xff);
                continue;
            }
        case 's':
            {
                const char *val = va_arg(ap, char *);
                if (!val) {
                    val = "(null)";
                }
                while (*val && to < end) {
                    *to++ = *val++;
                }
                continue;
            }
        }
    }
    *to = 0;
    return (int)(to - start);
}

static int __safe_snprintf(char *to, size_t n, const char *fmt, ...)
{
    int result;
    va_list args;
    va_start(args, fmt);
    result = __safe_vsnprintf(to, n, fmt, args);
    va_end(args);
    return result;
}

static void mem_dumpstack_to_fp(void *fp, pfprint_t pfprint)
{
#define SYSCALL_ADDRESS  0xfffffff010UL
#define BUFFER_SIZE  8192
    void *array[64] = {0};
    size_t size;
    size_t i = 0;
    int pipe_fd[2];
    char *stackbuffer;
    ssize_t readlen;
    char* printline;
    int jumpline = 0;
    
    size = backtrace (array, 64);
    if(size == 0) {
        return;
    }
    for (i = 0; i < size; i++) {
        if((unsigned long)array[i] == SYSCALL_ADDRESS) {
            i += 1;
            jumpline = i;
            break;
        }
    }
    if(i == size) {
        i = 0;
    }
    
    pipe(pipe_fd);
    stackbuffer = (char*)alloca(BUFFER_SIZE);
    backtrace_symbols_fd (&array, size, pipe_fd[1]);
    readlen = read(pipe_fd[0], stackbuffer, BUFFER_SIZE);
    if(readlen < 0) {
        pfprint (fp, "backtrace_symbols_fd error, errno:%d, reason:%s\n", errno, strerror(errno));
        return;
    }
    if(readlen == 0) {
        pfprint (fp, "backtrace_symbols_fd read length return 0. fd0: %d, fd1: %d\n", 
            errno, strerror(errno), pipe_fd[0], pipe_fd[1]);
        return;
    }
    
    pfprint (fp, "\ndumped thread call funtion stack frames:\n"
        "--------------------------------------------------------------------------------\n");
    
    printline = stackbuffer;
    /* jump first n signal call */
    while(jumpline > 0){
        char* enter_pos = strchr(printline, '\n');
        printline = enter_pos + 1;
        jumpline--;
    }
    
    for (; i < size; i++) {
        char* left_brace;
        char* newline = strchr(printline, '\n');

        if(newline) {
            *newline = '\0';
        }
        left_brace = strchr(printline, '(');
        if((left_brace == NULL && strchr(printline, '['))
            || (left_brace && *(left_brace+1) == ')')) 
        {
            /* try to parse static symbol */
            char *left_brace2 = strchr(printline, '[');
            if(left_brace2) {
                unsigned long addr;
                int n = sscanf(left_brace2, "[0x%lx]", &addr);
                if(n == 1) {
                    char buffer[256];
                    buffer[0] = '\0';
                    __safe_snprintf(buffer, left_brace2 - printline + 1, "%s", printline);
                    pfprint (fp, "%s", buffer);
                    mem_parse_symbol((void*)addr, buffer, 256);
                    pfprint (fp, "(%s)", buffer);
                    pfprint (fp, " %s\n", left_brace2);
                }
            } else {
                pfprint (fp, "%s\n", printline);
            }
        } else {
            pfprint (fp, "%s\n", printline);
        }
        printline = newline + 1;
    }
}

static int mem_log(const char *fmt, ...)
{
    int result;
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    result = __safe_vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
        
    if(g_memdbg_fp == NULL) {
        int fd = open(filename, O_RDWR|O_CREAT|O_NONBLOCK, 0644);
        g_memdbg_fp = fdopen(fd, "a+");
        if(g_memdbg_fp == NULL) {
            return result;
        }
    }
    fprintf(g_memdbg_fp, "%s\n", buffer);
    return result;
}

void mem_log_destroyer(MALLOC_HEADER* pheader)
{
    char buffer[1024];
    mem_parse_symbol(pheader->alloc_by[0], buffer, sizeof(buffer));
    mem_log("Malloc func: 0x%p(%s), pointer: 0x%p, length: %d\n", 
            pheader->alloc_by[0], buffer, pheader->data, pheader->memlen);
    mem_dumpstack_to_fp(g_memdbg_fp, fprintf);
}

#define HEAD_SEARCH_RANGE  (2 << 20)
#define TAIL_SEARCH_RANGE  (1 << 20)
int pointer_check(void* ptr)
{
    MALLOC_HEADER *pheader = (MALLOC_HEADER*)((unsigned long)ptr - sizeof(MALLOC_HEADER));
    MALLOC_TAIL *ptail = (MALLOC_TAIL *)((unsigned long)pheader + sizeof(MALLOC_HEADER) + pheader->memlen);
    if(pheader->magic_head == MALLOC_MAGIC_HEAD) {
        if(ptail->magic_tail == MALLOC_MAGIC_TAIL) {
            /* header and tail all match, ok */
            return 1;
        } else {
            /* header match, tail not match, overlap memory after this region */
            mem_log("Detect memory overlapped(0x%p). this memory overlaped memory after this region.\n", ptr);
            mem_log_destroyer(pheader);
            return 0;
        }
    } else {
        /* this block is overlapped by region before */
        if(ptail->magic_tail == MALLOC_MAGIC_TAIL) {
            mem_log("Detect memory overlapped(0x%p). this memory is overlaped by memory before this region.\n", ptr);
            uint32_t limit = HEAD_SEARCH_RANGE;
            uint32_t idx = 0;
            void* search_pointer = ((unsigned long)pheader - limit) & ((unsigned long)(-8));
            for(idx = 0; idx < limit; idx += sizeof(void*)) {
                MALLOC_HEADER *pheader = (MALLOC_HEADER*)(search_pointer + idx);
                if (pheader->magic_head == MALLOC_MAGIC_HEAD) {
                    mem_log("Find memory destroyer.\n");
                    mem_log_destroyer(pheader);
                    return 0;
                } else {
                    continue;
                }
            }
            mem_log("Cann't find memory destroyer before 1M size.\n");
        } else {
            /* header and tail all not match, may be totally destroyed or free a not valid pointer */
            mem_log("Memory header and tailer all not match.maybe free a not valid pointer(0x%p).\n", );
        }
    }
}

void free(void *ptr) {
    MALLOC_HEADER *p = (MALLOC_HEADER*)((unsigned long)ptr - sizeof(MALLOC_HEADER));
    if (is_initializing) {
        extern void __libc_free(void *);
        __libc_free(ptr);
        return;
    }
    if (ptr == NULL)
        return;

    init();
    if(p->magic_head != MALLOC_MAGIC_HEAD) {
        //LOG(LOG_ERROR, "Tried to free unknown pointer %p.", ptr);
        real_free(ptr);
        return;
    }
    __sync_sub_and_fetch(&g_mem_malloc_cnt, 1);
    __sync_sub_and_fetch(&g_mem_malloc_size, p->memlen);
    free_record(p);  
    real_free(p);
    return;
}

void *realloc(void *old_ptr, size_t new_size) {
    size_t memsize = new_size + PROTECT_LEN;
    MALLOC_HEADER *real_ptr = (MALLOC_HEADER*)((unsigned long)old_ptr - sizeof(MALLOC_HEADER));
    MALLOC_HEADER *ret_p;
    int orig_malloc_mem = 0;
    long old_size = 0;
    if (is_initializing) {
        extern void *__libc_realloc(void *, size_t);
        return __libc_realloc(old_ptr, new_size);
    }

    if (old_ptr == NULL)
        return malloc(new_size);

    if (new_size == 0) {
        free(old_ptr);
        return NULL;
    }

    if(real_ptr->magic_head != MALLOC_MAGIC_HEAD) {
        orig_malloc_mem = 1;
        ret_p = (MALLOC_HEADER*)real_realloc(old_ptr, new_size);
    } else {
        old_size = real_ptr->memlen;
        free_record(real_ptr);
        ret_p = (MALLOC_HEADER*)real_realloc(real_ptr, memsize);
    }
    if(ret_p == NULL) {
        if(orig_malloc_mem == 0)
            malloc_record(real_ptr, real_ptr->memlen);
        return NULL;
    }

    __sync_add_and_fetch(&g_mem_malloc_size, new_size - old_size);
    malloc_record(ret_p, new_size);
    return ret_p->data;
}

static int mem_parse_symbol(void *addr, char* buffer, int buflen)
{
    typedef int (*parse_symbol_func)(void *addr, char* buffer, int buflen);
    static void *handle;
    static parse_symbol_func parse_func;
    int ret;

    if(parse_func == NULL || handle == NULL) {
        const char *libpath = NULL;
        libpath = getenv("LIBSYMBOL_PATH");
        if (libpath == NULL) {
            size_t i;
            char *default_path[] = {
                "./libsymbol.so",
                "/lib64/libsymbol.so",
                "/lib/libsymbol.so",
                "/usr/lib64/libsymbol.so", 
                "/usr/lib/libsymbol.so",
            };
            for(i = 0; i < (sizeof(default_path) / sizeof(default_path[0])); i++) {
                handle = dlopen(default_path[i], RTLD_LAZY);
                if(handle != NULL)
                    break;
            }

        } else {
            handle = dlopen(libpath, RTLD_LAZY);
        }
        if(handle == NULL) {
            fprintf(stderr, "%s\n", dlerror());
            buffer[0] = '\0';
            return 0;
        }
        parse_func =(parse_symbol_func) dlsym(handle, "parse_symbol_by_addr");
        if(parse_func == NULL) {
            fprintf(stderr, "%s\n", dlerror());
            buffer[0] = '\0';
            return 0;
        }
    }
    ret = parse_func(addr, buffer, buflen);
    if(ret == 0) {
        snprintf(buffer, buflen, "%p #library #", addr);
        buffer[buflen - 1] = '\0';
    }
    return 1;
}

int print_mem_stat_list()
{
    MALLOC_HEADER *pMh;
    char buffer[256];
    spin_lock();
    SSP_LIST_FOR_EACH_ENTRY(pMh, &g_pstMalloc_list, stList, MALLOC_HEADER) {
        mem_parse_symbol(pMh->alloc_by[0], buffer, 256);
        printf("Malloc func: %s <0x%p>, size:%ld\n", buffer, pMh->alloc_by[0], pMh->memlen);
    }
    spin_unlock();
    return 0;
}

void MemStatNodeAdd(MALLOC_HEADER *pMh, LIST_HEAD_S *head, MemInfoNode* pstMemInfoNode)
{
    MemInfoNode *node_in_list;
    pstMemInfoNode->total_mem = pMh->total_len;
    pstMemInfoNode->counter = pMh->count;
    pstMemInfoNode->alloc_func = pMh->alloc_by[0];

    SSP_LIST_FOR_EACH_ENTRY(node_in_list, head, stList, MemInfoNode) {
        if(pstMemInfoNode->total_mem >= node_in_list->total_mem) {
            break;
        }
    }
    /* empty or last one */
    if(&node_in_list->stList == head) {
        SSP_ListAddTail(&pstMemInfoNode->stList, head);
    } else {
        SSP_ListAddTail(&pstMemInfoNode->stList, &node_in_list->stList);
    }
}

void MemStatPrint(LIST_HEAD_S *head, void* para,  print_func_t pf_print)
{
    MemInfoNode *node;
    char func_name[128];
    pf_print(para, "%56s  %12s  %12s  %12s    %s\n",
            "AllocFunc", "Total(MB)", "Total(KB)", "Total(B)", "AllocCount");
    pf_print(para, "========================================================="
            "=========================================================\n");
    SSP_LIST_FOR_EACH_ENTRY(node, head, stList, MemInfoNode) {
        func_name[0] = '\0';
        mem_parse_symbol(node->alloc_func, func_name, sizeof(func_name));
        pf_print(para, "%56s  %12d  %12d  %12d    %d\n",
                func_name,
                node->total_mem >> 20,
                node->total_mem >> 10,
                node->total_mem,
                node->counter);
    }
}

static inline int MemAddrHash64(void* addr)
{
    struct uptr_addr{
        unsigned long val1:16;
        unsigned long val2:16;
        unsigned long val3:16;
        unsigned long val4:16;
    } *uladdr = (struct uptr_addr*)&addr;
    return (uladdr->val1 ^ uladdr->val2 ^ uladdr->val3 ^ uladdr->val4) & (HASH_BUCKET_SIZE - 1);
}

static inline int MemAddrHash32(void* addr)
{
    struct uptr_addr{
        unsigned long val1:16;
        unsigned long val2:16;
    } *uladdr = (struct uptr_addr*)&addr;
    return (uladdr->val1 ^ uladdr->val2) & (HASH_BUCKET_SIZE - 1);
}

int print_mem_stat(void *para, print_func_t pf_print)
{
    MALLOC_HEADER *pMh;
    HLIST_HEAD_S *memstat_hashtable;
    int i, j = 0;
    unsigned long mem_info_node_no = 0;
    LIST_HEAD_S MemStatInfoList = SSP_LIST_HEAD_INIT(MemStatInfoList);
    MemInfoNode *pstMemInfoNode;
    unsigned long total_malloc_count = 0;
    unsigned long total_malloc_memory = 0;
    unsigned long walk_node_num = 0;
    memstat_hashtable = (HLIST_HEAD_S*)real_malloc(sizeof(HLIST_HEAD_S) * HASH_BUCKET_SIZE);
    if(memstat_hashtable == NULL) {
        return 0;
    }
    for(i = 0; i < HASH_BUCKET_SIZE; i++) {
        SSP_INIT_HLIST_HEAD(&memstat_hashtable[i]);
    }

    spin_lock();
    SSP_LIST_FOR_EACH_ENTRY(pMh, &g_pstMalloc_list, stList, MALLOC_HEADER) {
        int hash_val;
        HLIST_HEAD_S *hlist_head;
        HLIST_NODE_S *hlist_node;
        MALLOC_HEADER *pMhHlist = NULL;
        int found = 0;
        walk_node_num++;

        /* this memory is freeing */
        if(pMh->magic_head == FREE_MAGIC_HEAD) {
            continue;
        }

        if(sizeof(void*) == 8) {
            hash_val = MemAddrHash64(pMh->alloc_by[0]);
        } else {
            hash_val = MemAddrHash32(pMh->alloc_by[0]);
        }
        hlist_head = &memstat_hashtable[hash_val];

        SSP_HLIST_FOR_EACH_ENTRY(pMhHlist, hlist_node, hlist_head, stHNode, MALLOC_HEADER) {
            if(pMhHlist->alloc_by[0] == pMh->alloc_by[0]) {
                pMhHlist->total_len += pMh->memlen;
                pMhHlist->count++;
                found = 1;
                break;
            }
        }
        if(found == 0) {
            pMh->total_len = pMh->memlen;
            pMh->count = 1;
            mem_info_node_no++;
            SSP_HlistAddHead(&pMh->stHNode, hlist_head);
        }
    }

    pstMemInfoNode = (MemInfoNode*)real_malloc(sizeof(MemInfoNode) * mem_info_node_no);
    if(pstMemInfoNode == NULL) {
        real_free(memstat_hashtable);
        return 0;
    }

    for(i = 0; i < HASH_BUCKET_SIZE; i++) {
        HLIST_HEAD_S *hlist_head = &memstat_hashtable[i];
        HLIST_NODE_S *hlist_node;
        MALLOC_HEADER *pMhHlist = NULL;
        SSP_HLIST_FOR_EACH_ENTRY(pMhHlist, hlist_node, hlist_head, stHNode, MALLOC_HEADER) {
            MemStatNodeAdd(pMhHlist, &MemStatInfoList, &pstMemInfoNode[j]);
            j++;
            total_malloc_count += pMhHlist->count;
            total_malloc_memory+= pMhHlist->total_len;
        }
    }
    spin_unlock();
    
    pf_print(para, "========================================================="
            "=========================================================\n");
    pf_print(para, " %32s : %ld\n", "Total Malloc Function Point", mem_info_node_no);
    pf_print(para, " %32s : %ld\n", "Total Malloc Count", total_malloc_count);
    pf_print(para, " %32s : %ld\n", "Total Malloc Memory", total_malloc_memory);
    pf_print(para, "---------------------------------------------------------"
            "---------------------------------------------------------\n");
    MemStatPrint(&MemStatInfoList, para, pf_print);

    real_free(pstMemInfoNode);
    real_free(memstat_hashtable);
    return 0;
}

void dump_meminfo_to_file(void* filename)
{
    //FILE *fp = NULL;
    time_t now;
    char asctime_str[256];
    char* pos;
    
    if(g_memdbg_fp == NULL) {
        int fd = open(filename, O_RDWR|O_CREAT|O_NONBLOCK, 0644);
        g_memdbg_fp = fdopen(fd, "a+");
        if(g_memdbg_fp == NULL) {
            return;
        }
    }
    now = time(NULL);
    ctime_r(&now, asctime_str);
    pos = strchr(asctime_str, '\n');
    if(pos) {
        *pos = '\0';
    }
    fprintf(g_memdbg_fp, "=====================================================\n");
    fprintf(g_memdbg_fp, "Memory Dump time: %s\n", asctime_str);
    fprintf(g_memdbg_fp, "=====================================================\n");
    print_mem_stat(g_memdbg_fp, (print_func_t)fprintf);
    //fclose(fp);
    return;
}
