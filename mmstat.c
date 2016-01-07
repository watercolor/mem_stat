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
                "/lib/libsymbol.so",
                "/usr/lib/libsymbol.so",
                "/lib64/libsymbol.so",
                "/usr/lib64/libsymbol.so", 
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
    mem_parse_symbol(pMh->alloc_by[0], pstMemInfoNode->func_name, sizeof(pstMemInfoNode->func_name));

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
    pf_print(para, "%56s  %12s  %12s  %12s    %s\n",
            "AllocFunc", "Total(MB)", "Total(KB)", "Total(B)", "AllocCount");
    pf_print(para, "========================================================="
            "=========================================================\n");
    SSP_LIST_FOR_EACH_ENTRY(node, head, stList, MemInfoNode) {
        pf_print(para, "%56s  %12d  %12d  %12d    %d\n",
                node->func_name,
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
    memstat_hashtable = (HLIST_HEAD_S*)malloc(sizeof(HLIST_HEAD_S) * HASH_BUCKET_SIZE);
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
    spin_unlock();

    pstMemInfoNode = (MemInfoNode*)malloc(sizeof(MemInfoNode) * mem_info_node_no);
    if(pstMemInfoNode == NULL) {
        free(memstat_hashtable);
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
    pf_print(para, "========================================================="
            "=========================================================\n");
    pf_print(para, " %32s : %ld\n", "Total Malloc Function Point", mem_info_node_no);
    pf_print(para, " %32s : %ld\n", "Total Malloc Count", total_malloc_count);
    pf_print(para, " %32s : %ld\n", "Total Malloc Memory", total_malloc_memory);
    pf_print(para, "---------------------------------------------------------"
            "---------------------------------------------------------\n");
    MemStatPrint(&MemStatInfoList, para, pf_print);

    free(pstMemInfoNode);
    free(memstat_hashtable);
    return 0;
}

void dump_meminfo_to_file(void* filename)
{
    FILE *fp = NULL;
    time_t now;
    char asctime_str[256];
    char* pos;
    int fd;
    
    fd = open(filename, O_RDWR|O_CREAT|O_NONBLOCK, 0644);
    fp = fdopen(fd, "a+");
    if(fp == NULL) {
        return;
    }
    
    now = time(NULL);
    ctime_r(&now, asctime_str);
    pos = strchr(asctime_str, '\n');
    if(pos) {
        *pos = '\0';
    }
    fprintf(fp, "=====================================================\n");
    fprintf(fp, "Memory Dump time: %s\n", asctime_str);
    fprintf(fp, "=====================================================\n");
    print_mem_stat(fp, (print_func_t)fprintf);
    fclose(fp);
    return;
}
