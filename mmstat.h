#ifndef __MEM_STAT_H_
#define __MEM_STAT_H_
#include <stdio.h>
#include <pthread.h>
#include "ssp_list_pub.h"

typedef enum {
    LOG_FATAL,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_TRACE,
}log_level_e;
extern log_level_e curent_log_level;

#define STR_TMP(x) #x
#define STR(x) STR_TMP(x)
#define LOG(level, format, ...) do {                                  \
    if (level <= curent_log_level) {                                  \
        fprintf(stderr, __FILE__ ":" STR(__LINE__) ": "               \
                format "\n", ##__VA_ARGS__);                          \
    }                                                                 \
} while(0)

#define DIE(format, ...) do {                                         \
    fprintf(stderr, __FILE__ ":" STR(__LINE__) ":"                    \
            format "\n", ##__VA_ARGS__);                              \
    exit(0);                                                          \
} while(0)

#define RET_ADDR_LEVEL(x) __builtin_return_address(x)
#define RET_ADDR     RET_ADDR_LEVEL(0)
#define RET_ADDR1    RET_ADDR_LEVEL(1)
#define RET_ADDR2    RET_ADDR_LEVEL(2)
#define RET_ADDR3    RET_ADDR_LEVEL(3)

extern pthread_spinlock_t spin_lock_internal;
#define spin_lock() while (pthread_spin_lock(&spin_lock_internal))
#define spin_unlock() while (pthread_spin_unlock(&spin_lock_internal))

typedef struct Malloc_Header_t
{
    unsigned int magic_head;
    unsigned int count;
    unsigned long memlen;
    unsigned long total_len;
    void   *alloc_by[2];
    LIST_HEAD_S stList;
    HLIST_NODE_S stHNode;
    char* data[0];
}MALLOC_HEADER;

typedef struct Malloc_Tail_t
{
    unsigned int magic_tail;
}MALLOC_TAIL;

#define MALLOC_MAGIC_HEAD       (0xa5a5a5a5)
#define MALLOC_MAGIC_TAIL       (0x3c3c3c3c)
#define FREE_MAGIC_HEAD         (0x1e1e1e1e)
#define FREE_MAGIC_TAIL         (0x78787878)

#define PROTECT_LEN  (sizeof(MALLOC_HEADER) + sizeof(MALLOC_TAIL))
#define malloc_record(pMh, size) do {\
    MALLOC_TAIL *pMt = (MALLOC_TAIL *)((unsigned long)pMh + sizeof(MALLOC_HEADER) + size); \
    pMh->magic_head = MALLOC_MAGIC_HEAD; \
    pMh->memlen     = size; \
    pMh->total_len  = 0; \
    pMh->count = 0; \
    pMh->alloc_by[0] = RET_ADDR; \
    pMt->magic_tail = MALLOC_MAGIC_TAIL; \
    spin_lock(); \
    SSP_ListAdd(&(pMh->stList), &g_pstMalloc_list); \
    spin_unlock(); \
}while(0)

#define free_record(pMh) do {\
    MALLOC_TAIL *pMt = (MALLOC_TAIL *)((unsigned long)pMh + sizeof(MALLOC_HEADER) + pMh->memlen); \
    pMh->magic_head = FREE_MAGIC_HEAD; \
    pMh->memlen = 0; \
    pMh->total_len  = 0; \
    pMh->count = 0; \
    pMh->alloc_by[0] = RET_ADDR; \
    pMt->magic_tail = FREE_MAGIC_TAIL; \
    spin_lock(); \
    SSP_ListDel(&(pMh->stList)); \
    spin_unlock(); \
}while(0)

typedef int (*print_func_t)(void*, const char *format, ...);

#define HASH_BUCKET_SIZE 1024
typedef struct {
    LIST_HEAD_S stList;
    char func_name[128];
    void* alloc_func;
    int total_mem;
    int counter;
} MemInfoNode;

#endif
