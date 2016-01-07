#ifndef _SSP_LIST_PUB_H_
#define _SSP_LIST_PUB_H_

#define INLINE inline
#define BOOL   int

/**
 * SSP_CONTAINER_OF - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_CONTAINER_OF(ptr, type, member)  (type*)((char*)ptr - (size_t)(&(((type*)0)->member)))
/* 获取数组元素个数*/
#define SSP_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SSP_ALIGN(x,a) (((x)+((unsigned long )a)-1)&~(((unsigned long )a)-1))
#define SSP_SWAP(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define PREFETCH(x)		__builtin_prefetch(x)

/*双向链表节点定义*/
typedef struct ListHead_S
{
	 struct ListHead_S *pstNext, *pstPrev;
}LIST_HEAD_S;

/**接口形式
接口用途	声明和初始化
参数说明	
返回值说明	
使用举例
#define SSP_LIST_HEAD_INIT(name)   LIST_HEAD_INIT(name)	
*/
#define SSP_LIST_HEAD_INIT(name)   { &(name), &(name) }

#define SSP_LIST_HEAD(name) \
	LIST_HEAD_S name = SSP_LIST_HEAD_INIT(name)

/** 3.7.1.2	判断链表是否为空
接口形式	INLINE ULONG SSP_IsListEmpty(LIST_HEAD_S *pstHead);
接口用途	判断链表是否为空:它的pstNext, pstPrev指针是否指向自己.
参数说明	LIST_HEAD_S *pstHead:链表头
返回值说明	空:VSP_YES, 失败:VSP_NO
使用举例	
#define SSP_IsListEmpty(pstHead)     list_empty(pstHead)
*/
static INLINE BOOL SSP_IsListEmpty(const LIST_HEAD_S *pstHead)
{
    return pstHead->pstNext == pstHead;
}

/** 3.7.1.3	链表的初始化
接口形式	#define SSP_ListHeadInit(ptr) do { \
(ptr)->pstNext = (ptr); (ptr)->pstPrev = (ptr);\
}While(0)
接口用途	初始化
参数说明	ptr:链表头
返回值说明	
使用举例	
#define SSP_ListHeadInit(ptr)     INIT_LIST_HEAD(ptr)
*/
static INLINE void SSP_ListHeadInit(LIST_HEAD_S *pstHead)
{
    pstHead->pstNext = pstHead;
    pstHead->pstPrev = pstHead;
}

/** 3.7.1.3	最基本的list添加函数
接口形式	static INLINE void SSP_BaseListADD(LIST_HEAD_S *pstNewHead,
			      LIST_HEAD_S *pstPrev,
			      LIST_HEAD_S *pstNext)
接口用途	将pstNewHead插入到pstPrev和pstNext的中间
参数说明	ptr:链表头
返回值说明	
使用举例	
#define SSP_BaseListAdd( pstNew,pstHead)    __list_add(pstNew, pstHead)
*/
static INLINE void SSP_BaseListADD(LIST_HEAD_S *pstNewHead,
			      LIST_HEAD_S *pstPrev,
			      LIST_HEAD_S *pstNext)
{
    pstNext->pstPrev = pstNewHead;
    pstNewHead->pstNext = pstNext;
    pstNewHead->pstPrev = pstPrev;
    pstPrev->pstNext = pstNewHead;
}

/** 3.7.1.4	表头插入
接口形式	INLINE void SSP_ListAdd(LIST_HEAD_S *pstNew, 
LIST_HEAD_S *pstHead);
接口用途	表头插入
参数说明	LIST_HEAD_S *pstNew:新链表节点
LIST_HEAD_S *pstHead:链表头
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListAdd( pstNew,pstHead)    list_add(pstNew, pstHead)
*/
static INLINE void SSP_ListAdd(LIST_HEAD_S *pstNew, LIST_HEAD_S *pstHead)
{
    SSP_BaseListADD(pstNew, pstHead, pstHead->pstNext);
}

/** 3.7.1.5	表尾插入
接口形式	INLINE void SSP_ListAddTail(LIST_HEAD_S *pstNew,
               LIST_HEAD_S *pstHead);
接口用途	表尾插入
参数说明	LIST_HEAD_S *:新链表节点
LIST_HEAD_S *:链表头
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListAddTail( pstNew,pstHead)    list_add_tail(pstNew, pstHead)
*/
static INLINE void  SSP_ListAddTail(LIST_HEAD_S *pstNew, LIST_HEAD_S *pstHead)
{
    SSP_BaseListADD(pstNew, pstHead->pstPrev, pstHead);
}

/** 3.7.1.6	基本的链表节点删除
接口形式	INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry);
INLINE void SSP_ListDelInit(LIST_HEAD_S *pstEntry);
接口用途	SSP_ListDel:删除链表头部的节点
SSP_ListDelTail: 删除链表尾部的节点
参数说明	LIST_HEAD_S *pstEntry:链表头
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_BaseListDel( pstEntry)  __list_del(pstEntry)
*/
static INLINE void SSP_BaseListDel(LIST_HEAD_S * pstPrev, LIST_HEAD_S * pstNext)
{
    pstNext->pstPrev = pstPrev;
    pstPrev->pstNext = pstNext;
}


/** 3.7.1.6	链表节点删除
接口形式	INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry);
INLINE void SSP_ListDelInit(LIST_HEAD_S *pstEntry);
接口用途	SSP_ListDel:删除链表头部的节点
SSP_ListDelTail: 删除链表尾部的节点
参数说明	LIST_HEAD_S *pstEntry:链表头
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListDel( pstEntry)  list_del(pstEntry)
*/
static INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry)
{
    SSP_BaseListDel(pstEntry->pstPrev, pstEntry->pstNext);
    pstEntry->pstNext = pstEntry;
    pstEntry->pstPrev = pstEntry;
}


/** 3.7.1.7	搬移
接口形式	移到链头部
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
接口用途	SPP_ListMove: 移到链头部
SPP_ ListMoveTail: 移到链尾部
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void	SSP_ListMove(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_BaseListDel(pstList->pstPrev, pstList->pstNext);
    SSP_ListAdd(pstList, pstHead);
}


/*移到链尾部
Inline void SSP_ListMoveTail(LIST_HEAD_S *pstList, 
LIST_HEAD_S *pstHead);
接口用途	SPP_ ListMoveTail: 移到链尾部
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void	SSP_ListMoveTail(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_BaseListDel(pstList->pstPrev, pstList->pstNext);
    SSP_ListAddTail(pstList, pstHead);
}

/*将链表加入到链表中
Inline void SSP_ListAddList( LIST_HEAD_S *pstHead, LIST_HEAD_S *pstFirstMoveNode, LIST_HEAD_S *pstLastMoveNode);
接口用途	SPP_ ListMoveTail: 移到链尾部
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void SSP_ListAddList( LIST_HEAD_S *pstHead, LIST_HEAD_S *pstFirstMoveNode, LIST_HEAD_S *pstLastMoveNode)
{
    /* 将需要搬移的链表加入到目的链表中  */
        pstFirstMoveNode->pstPrev = pstHead;
        pstLastMoveNode->pstNext = pstHead->pstNext;
        pstHead->pstNext->pstPrev = pstLastMoveNode;
        pstHead->pstNext = pstFirstMoveNode;
}

/** 3.7.1.7	搬移一定数量的节点
接口形式	移到链头部
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
接口用途	SPP_ListMove: 移到链头部
SPP_ ListMoveTail: 移到链尾部
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
  static INLINE int SSP_ListNMove(LIST_HEAD_S *pstSrcHead, LIST_HEAD_S *pstDstHead, int ulCounter )
{
    int ulLoop = 0;
    LIST_HEAD_S *pstFirstMoveNode = NULL;
    LIST_HEAD_S *pstLastMoveNode = NULL;
    pstFirstMoveNode = pstSrcHead->pstNext;
    pstLastMoveNode = pstFirstMoveNode;

    /* 只剩链表头 */
    if( pstFirstMoveNode == pstSrcHead )
    {
        return 0;
    }
    /* ulCounter == 0 */
    if( ulCounter == 0 )
    {
        return 0;
    }
    ulLoop++;
    
    /* 找到要搬移的最后一个节点 */
    while( pstLastMoveNode->pstNext != pstSrcHead && ulLoop < ulCounter )
    {
        pstLastMoveNode = pstLastMoveNode->pstNext;
        ulLoop++;
    }  
    /* 将需要搬移的链表从原先链表中搬移出来  */
    pstFirstMoveNode->pstPrev->pstNext = pstLastMoveNode->pstNext;
    pstLastMoveNode->pstNext->pstPrev = pstFirstMoveNode->pstPrev;

    SSP_ListAddList( pstDstHead,  pstFirstMoveNode,  pstLastMoveNode); 
    
    return ulLoop; 
 }  

/** 3.7.1.7	搬移一定数量的节点
接口形式	移到链尾部
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
接口用途	SPP_ListMove: 移到链尾部
SPP_ ListMoveTail: 移到链尾部
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
  static INLINE int SSP_ListNMoveTail(LIST_HEAD_S *pstSrcHead, LIST_HEAD_S *pstDstHead, int ulCounter )
{
    return SSP_ListNMove( pstSrcHead, pstDstHead->pstPrev,ulCounter );
}

/** 3.7.1.8	最基本的合并函数
接口形式	INLINE void SSP_BaseListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
接口用途	将list链表中的节点合并到head链表中去.
SSP_ListSplice_init还会将list初始化一下
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_BaseListSplice( pstList, pstHead)   __list_splice( pstList, pstHead)
*/
static INLINE void SSP_BaseListSplice(LIST_HEAD_S *pstList,
				 LIST_HEAD_S *pstHead)
{
    LIST_HEAD_S *pstFirst = pstList->pstNext;
    LIST_HEAD_S *pstLast = pstList->pstPrev;
    LIST_HEAD_S *pstTmp = pstHead->pstNext;

    pstFirst->pstPrev = pstHead;
    pstHead->pstNext = pstFirst;

    pstLast->pstNext = pstTmp;
    pstTmp->pstPrev = pstLast;
}
/** 3.7.1.8	合并
接口形式	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
接口用途	将list链表中的节点合并到head链表中去.
SSP_ListSplice_init还会将list初始化一下
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSplice(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    if (!SSP_IsListEmpty(pstList))
    {   
        SSP_BaseListSplice(pstList, pstHead);
    }
}

/** 3.7.1.8	合并且初始化
接口形式	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
接口用途	将list链表中的节点合并到head链表中去.
SSP_ListSplice_init还会将list初始化一下
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSpliceInit(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    if (!SSP_IsListEmpty(pstList))
    {   
        SSP_BaseListSplice(pstList, pstHead);
        SSP_ListHeadInit(pstList);
    }
}

/** 3.7.1.8	合并到尾部
接口形式	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
接口用途	将list链表中的节点合并到head链表中去.
SSP_ListSplice_init还会将list初始化一下
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSpliceToTail(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_ListSplice( pstList, pstHead->pstPrev );
}

/** 3.7.1.8	合并到尾部且初始化
接口形式	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
接口用途	将list链表中的节点合并到head链表中去.
SSP_ListSplice_init还会将list初始化一下
参数说明	LIST_HEAD_S *pstList:源链表
LIST_HEAD_S *pstHead:目的链表
返回值说明	成功:SSP_OK, 失败:SSP_ERR
使用举例	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSpliceInitToTail(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_ListSpliceInit( pstList, pstHead->pstPrev);
}

/**
 * SSP_CONTAINER_OF - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_ListEntry(ptr, type, member)   SSP_CONTAINER_OF(ptr, type, member)

/** 3.7.1.9	向前遍历链表节点,该遍历不遍历链表头
接口形式	#define SSP_LIST_FOR_EACH(pos, head) _list_for_each(pos, head)
接口用途	向前遍历链表节点
参数说明	Pos:链表节点指针
Head:链表头
返回值说明	
使用举例	
#define SSP_LIST_FOR_EACH(pos, head) list_for_each(pos, head)
*/
#define SSP_LIST_FOR_EACH(pos, head) \
	for (pos = (head)->pstNext; PREFETCH(pos->pstNext), pos != (head); \
        	pos = pos->pstNext)

#if 1 //add in VSP_TENANT
/**从pos位置开始遍历**/
#define SSP_LIST_FOR_EACH_CONTINUE(pos, head) \
	for (pos = (pos)->pstNext; PREFETCH(pos->pstNext), pos != (head); \
        	pos = pos->pstNext)
        	
#endif
/** 3.7.1.10	向后遍历链表节点,该遍历不遍历链表头
接口形式	#define SSP_LIST_FOR_EACH _PREW(pos, head)    \
 list_for_each_pstPrev(pos, head)
接口用途	
参数说明	Pos:链表节点指针
Head:链表头
返回值说明	向后遍历链表节点
使用举例	
#define SSP_LIST_FOR_EACH_PREW(pos, head)    list_for_each_pstPrev(pos, head)
*/
#define SSP_LIST_FOR_EACH_PREW(pos, head) \
	for (pos = (head)->pstPrev; PREFETCH(pos->pstPrev), pos != (head); \
        	pos = pos->pstPrev)
        	
/** 3.7.1.11	向前遍历数据项变量,该遍历不遍历链表头
接口形式	#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member) \
	list_for_each_entry(pos, head, member)
接口用途	向后遍历数据项变量
参数说明	Pos: 数据项变量指针
Head:链表头
Member:链表节点在数据项结构中的域名
返回值说明	
使用举例	
#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member) list_for_each_entry(pos, head, member)
*/
#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member, type)				\
	for (pos = SSP_ListEntry((head)->pstNext, type, member);	\
	     PREFETCH(pos->member.pstNext), &pos->member != (head); 	\
	     pos = SSP_ListEntry(pos->member.pstNext, type, member))

/** 3.7.1.12	向后遍历数据项变量
接口形式	#define SSP_LIST_FOR_EACH_ENTRY_REVERSE(pos, head, member)	\
list_for_each_entry_reverse
接口用途	向后遍历数据项变量
参数说明	Pos: 数据项变量指针
Head:链表头
Member:链表节点在数据项结构中的域名
返回值说明	
使用举例
#define SSP_LIST_FOR_EACH_ENTRY_REVERSE(pos, head, member)   list_for_each_entry_reverse
*/
#define SSP_LIST_FOR_EACH_ENTRY_REVERSE(pos, head, member, type)			\
	for (pos = SSP_ListEntry((head)->pstPrev, type, member);	\
	     PREFETCH(pos->member.pstPrev), &pos->member != (head); 	\
	     pos = SSP_ListEntry(pos->member.pstPrev, type, member))


/**
 * list_for_each_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop counter.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
 
#define SSP_LIST_FOR_EACH_SAFE(pos, n, head) \
	for (pos = (head)->pstNext, n = pos->pstNext; pos != (head); \
		pos = n, n = pos->pstNext)
		
/**
 * list_prepare_entry - prepare a pos entry for use as a start point in
 *			list_for_each_entry_continue
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_struct within the struct.
 */
 
#define SSP_LIST_PREPARE_ENTRY(pos, head, member, type)			\
	((pos) ? : SSP_ListEntry(head, type, member))

/**
 * list_for_each_entry_continue -	iterate over list of given type
 *			continuing after existing point
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_LIST_FOR_EACH_ENTRY_CONTINUE(pos, head, member, typeofpost)			\
	for (pos = SSP_ListEntry(pos->member.pstNext, typeofpost, member);	\
	     PREFETCH(pos->member.pstNext), &pos->member != (head);	\
	     pos = SSP_ListEntry(pos->member.pstNext, typeofpost, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member,typeofpos,typeofn)			\
	for (pos = SSP_ListEntry((head)->pstNext,typeofpos, member),	\
		n = SSP_ListEntry(pos->member.pstNext, typeofpos, member);	\
	     &pos->member != (head); 					\
	     pos = n, n = SSP_ListEntry(n->member.pstNext, typeofn, member))

/**
 * list_for_each_entry_safe_continue -	iterate over list of given type
 *			continuing after existing point safe against removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_LIST_FOR_EACH_ENTRY_SAFE_CONTINUE(pos, n, head, member,typeofpos,typeofn)			\
	for (pos = SSP_ListEntry(pos->member.pstNext, typeofpos, member), 		\
		n = SSP_ListEntry(pos->member.pstNext, typeofpos, member);		\
	     &pos->member != (head);						\
	     pos = n, n = SSP_ListEntry(n->member.pstNext, typeofn, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list of given type safe against
 *				      removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_LIST_FOR_EACH_ENTRY_SAFE_REVERSE(pos, n, head, member, typeofpost)			\
	for (pos = SSP_ListEntry((head)->pstPrev,typeofpost, member),	\
		n = SSP_ListEntry(pos->member.pstPrev, typeofpost, member);	\
	     &pos->member != (head); 					\
	     pos = n, n = SSP_ListEntry(n->member.pstPrev,typeofpost, member))


#define SSP_LIST_FOR_EACH_ENTRY_RCU(pos, head, member, type)			\
	for (pos = SSP_ListEntry((head)->pstNext, type, member);	\
	     PREFETCH(SSP_RcuDereference(pos)->member.pstNext), &pos->member != (head); 	\
	     pos = SSP_ListEntry(pos->member.pstNext, type, member))


/** 3.7.2	hlist的封装*/

/*哈希链表节点定义*/
typedef struct HlistHead_S
{
	 struct HlistNode_S *pstFirst;
}HLIST_HEAD_S;

/*哈希冲突链表节点定义*/
typedef struct HlistNode_S
{
	 struct HlistNode_S *pstNext, **ppstPrev;
}HLIST_NODE_S;

/** 3.7.2.1	声明和初始化
接口形式	Typedefine HLIST_HEAD_S  HLIST_HEAD_S
Typedefine HLIST_NODE_S  HLIST_NODE_S
#define SSP_HLIST_HEAD_INIT { .pstFirst = NULL }
#define SSP_HLIST_HEAD(name) HLIST_HEAD_S name = {  .pstFirst = NULL }
#define SSP_INIT_HLIST_HEAD(ptr) ((ptr)->pstFirst = NULL)
接口用途	hlist声明和初始化
参数说明	
返回值说明	
使用举例
#define SSP_HLIST_HEAD_INIT            HLIST_HEAD_INIT
#define SSP_HLIST_HEAD(name)            HLIST_HEAD(name)
#define SSP_INIT_HLIST_HEAD(ptr)      INIT_HLIST_HEAD(ptr)
*/
#define SSP_HLIST_HEAD_INIT { .pstFirst = NULL }
#define SSP_HLIST_HEAD(name) HLIST_HEAD_S name = {  .pstFirst = NULL }
#define SSP_INIT_HLIST_HEAD(ptr) ((ptr)->pstFirst = NULL)
/* 初始化哈希冲突链表节点 */
static INLINE void SSP_INIT_HLIST_NODE(HLIST_NODE_S *pHnode)
{
	pHnode->pstNext = NULL;
	pHnode->ppstPrev= NULL;
}

/** 3.7.2.2	节点是否有冲突节点
接口形式	INLINE ULONG SSP_HLIST_UNHASHED(CONST HLIST_NODE_S *pHnode)
接口用途	节点是否有冲突节点
参数说明	CONST HLIST_NODE_S *pHnode:hlist节点
返回值说明	是:VSP_YES, 否:VSP_NO
使用举例	
#define SSP_HLIST_UNHASHED(CONST HLIST_NODE_S *pHnode) hlist_unhashed(const HLIST_NODE_S * h)
*/
 static INLINE int SSP_HlistUnhashed(const HLIST_NODE_S *pHnode)
{
	return !pHnode->ppstPrev;
}

/** 3.7.2.3	hlist是否为空
接口形式	INLINE LONG SSP_HLIST_EMPTY(CONST HLIST_HEAD_S *pHlist)
接口用途	hlist是否为空
参数说明	CONST HLIST_HEAD_S *pHlist: hlist头部
返回值说明	是:VSP_YES, 否:VSP_NO
使用举例	
#define SSP_HLIST_EMPTY(pHlist) hlist_empty(const HLIST_NODE_S * h)
*/
 static INLINE int SSP_HlistEmpty(const HLIST_HEAD_S *pHlistHead)
{
	return !pHlistHead->pstFirst;
}

	
/* 初始化哈希冲突链表头*/
static INLINE void SSP_HlistHeadInit( HLIST_HEAD_S *pHlistHead)
{
	pHlistHead->pstFirst = NULL;
}

/** 3.7.2.4	最基本的删除一个hlist节点
接口形式	INLINE void SSP_HLIST_DEL(HLIST_NODE_S *pHnode)
接口用途	删除一个hlist节点
参数说明	HLIST_NODE_S *pHnode: hlist节点
返回值说明	无
使用举例	
#define   SSP_BaseHlistDel( pHnode) __hlist_del( pHnode)
*/
static INLINE void SSP_BaseHlistDel(HLIST_NODE_S *pHnode)
{
    HLIST_NODE_S *pstNext = pHnode->pstNext;
    HLIST_NODE_S **ppstPrev = pHnode->ppstPrev;
    *ppstPrev = pstNext;
    if (pstNext)
    {   
        pstNext->ppstPrev = ppstPrev;
    }
}

/** 3.7.2.4	删除一个hlist节点
接口形式	INLINE void SSP_HLIST_DEL(HLIST_NODE_S *pHnode)
接口用途	删除一个hlist节点
参数说明	HLIST_NODE_S *pHnode: hlist节点
返回值说明	无
使用举例	
#define   SSP_HLIST_DEL( pHnode) hlist_del( pHnode)
*/
static INLINE void SSP_HlistDel(HLIST_NODE_S *pHnode)
{
	SSP_BaseHlistDel(pHnode);
}

static INLINE void SSP_HlistDelInit(HLIST_NODE_S *pHnode)
{
	if (pHnode->ppstPrev)  {
		SSP_BaseHlistDel(pHnode);
		SSP_INIT_HLIST_NODE(pHnode);
	}
}

#define SSP_HLIST_FOR_EACH_SAFE(pos, n, head) \
	for (pos = (head)->pstFirst; pos && ({ n = pos->pstNext; 1; }); \
	     pos = n)
/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop counter.
 * @pos:	the &struct hlist_node to use as a loop counter.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define SSP_HLIST_FOR_EACH_ENTRY_SAFE(tpos, pos, n, head, member, typeoftpos) 		 \
	for (pos = (head)->pstFirst;					 \
	     pos && ({ n = pos->pstNext; 1; }) && 				 \
		({ tpos = SSP_HlistEntry(pos, typeoftpos, member); 1;}); \
	     pos = n)
	     	     

/** 3.7.2.5	在hlist链头增加一个节点
接口形式	INLINE void SSP_HLIST_ADD_HEAD(HLIST_NODE_S *pHnode,
HLIST_HEAD_S *pHlist)
接口用途	将pHnode加到pHlist的头部.
参数说明	HLIST_NODE_S *pHnode: hlist节点
HLIST_HEAD_S *pHlist: hlist头部
返回值说明	无
使用举例
#define SSP_HLIST_ADD_HEAD( pHnode,pHlist)  hlist_add_head(HLIST_NODE_S * n, HLIST_HEAD_S * h)	
*/
static INLINE void SSP_HlistAddHead(HLIST_NODE_S *pHnode, HLIST_HEAD_S *pHlist)
{
    HLIST_NODE_S *pstFirst = pHlist->pstFirst;
    pHnode->pstNext = pstFirst;
    if (pstFirst)
    {   
        pstFirst->ppstPrev = &pHnode->pstNext;
    }
    pHlist->pstFirst = pHnode;
    pHnode->ppstPrev = &pHlist->pstFirst;
}

/** 3.7.2.6	在某节点前插入一个新节点
接口形式	INLINE void SSP_HLIST_ADD_BEFORE(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
接口用途	将pNextHnode插入到pHnode前
参数说明	HLIST_NODE_S *pHnode: hlist节点
HLIST_NODE_S *pNextHnode: 新的hlist节点
返回值说明	无
使用举例
#define SSP_HLIST_ADD_BEFORE(pHnode,pNextHnode) hlist_add_before(HLIST_NODE_S * n, HLIST_NODE_S * pstNext)	
*/
static INLINE void SSP_HlistAddBefore(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
{
	pHnode->ppstPrev = pNextHnode->ppstPrev;
	pHnode->pstNext = pNextHnode;
	pNextHnode->ppstPrev = &pHnode->pstNext;
	*(pHnode->ppstPrev) = pHnode;
}

/**
 * SSP_CONTAINER_OF - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define SSP_HlistEntry(ptr, type, member)   SSP_CONTAINER_OF(ptr, type, member)

/** 3.7.2.7	在某节点后插入一个新节点
接口形式	INLINE void SSP_HLIST_ADD_AFTER(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
接口用途	将pNextHnode插入到pHnode后
参数说明	HLIST_NODE_S *pHnode: hlist节点
HLIST_NODE_S *pNextHnode: 新的hlist节点
返回值说明	无
使用举例
#define SSP_HLIST_ADD_AFTER(pHnode,pNextHnode) hlist_add_after(HLIST_NODE_S * n, HLIST_NODE_S * pstNext)	
*/
static INLINE void SSP_HlistAddAfter(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
{
    pNextHnode->pstNext = pHnode->pstNext;
    pHnode->pstNext = pNextHnode;
    pNextHnode->ppstPrev = &pHnode->pstNext;

    if(pNextHnode->pstNext)
    {   
        pNextHnode->pstNext->ppstPrev  = &pNextHnode->pstNext;
    }
}

/** 3.7.2.8	遍历hlist链表
接口形式	#define SSP_HLIST_FOR_EACH(pos, head)  hlist_for_each(pos, head) 
接口用途	遍历hlist链表宏
参数说明	pos:链表节点指针
head:hlist链表头
返回值说明	
使用举例	
#define SSP_HLIST_FOR_EACH(pos, head)  hlist_for_each(pos, head)  
*/
#define SSP_HLIST_FOR_EACH(pos, head)  \
	for (pos = (head)->pstFirst; pos && ({ PREFETCH(pos->pstNext); 1; }); \
	     pos = pos->pstNext)


/** 3.7.2.9	遍历hlist链表中的数据项变量
接口形式	#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) \
  hlist_for_each_entry(tpos, pos, head, member)	
接口用途	遍历hlist链表中的数据项变量
参数说明	tpos: hlist链表节点在数据项结构中的域
pos: hlist链表节点指针
head:hlist链表头
member: 链表节点在数据项结构中的域名
返回值说明	
使用举例	
#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) hlist_for_each_entry(tpos, pos, head, member)	
*/
#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member,type) 			 \
	for (pos = (head)->pstFirst;\
	     pos && (PREFETCH(pos->pstNext), 1) &&\
		(tpos = SSP_HlistEntry(pos, type, member), 1);\
	     pos = pos->pstNext)

/** 3.7.2.10	从某节点的下一个节点开始遍历hlist链表中的数据项变量
接口形式	#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member)\
 hlist_for_each_entry_continue(tpos, pos, member)	
接口用途	从某节点的下一个节点开始遍历hlist链表中的数据项变量
参数说明	tpos: hlist链表节点在数据项结构中的域
pos: hlist链表节点指针
member: 链表节点在数据项结构中的域名
返回值说明	
使用举例	
#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member)    hlist_for_each_entry_continue(tpos, pos, member)	 
*/
#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member,type) 	 \
	for (pos = (pos)->pstNext;						 \
	     pos && (PREFETCH(pos->pstNext), 1) &&			 \
		(tpos = SSP_HlistEntry(pos, type, member), 1); \
	     pos = pos->pstNext)

/** 3.7.2.11	从某节点开始遍历hlist链表中的数据项变量
接口形式	#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member) \
hlist_for_each_entry_from(tpos, pos, member)	
接口用途	从某节点开始遍历hlist链表中的数据项变量
参数说明	tpos: hlist链表节点在数据项结构中的域
pos: hlist链表节点指针
member: 链表节点在数据项结构中的域名
返回值说明	
使用举例	
#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member)    hlist_for_each_entry_from(tpos, pos, member)	
*/
#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member,type)		 \
	for (; pos && ({ PREFETCH(pos->pstNext); 1;}) &&			 \
		({ tpos = SSP_HlistEntry(pos, type, member); 1;}); \
	     pos = pos->pstNext)

#endif

