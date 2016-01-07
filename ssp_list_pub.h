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
/* ��ȡ����Ԫ�ظ���*/
#define SSP_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SSP_ALIGN(x,a) (((x)+((unsigned long )a)-1)&~(((unsigned long )a)-1))
#define SSP_SWAP(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define PREFETCH(x)		__builtin_prefetch(x)

/*˫������ڵ㶨��*/
typedef struct ListHead_S
{
	 struct ListHead_S *pstNext, *pstPrev;
}LIST_HEAD_S;

/**�ӿ���ʽ
�ӿ���;	�����ͳ�ʼ��
����˵��	
����ֵ˵��	
ʹ�þ���
#define SSP_LIST_HEAD_INIT(name)   LIST_HEAD_INIT(name)	
*/
#define SSP_LIST_HEAD_INIT(name)   { &(name), &(name) }

#define SSP_LIST_HEAD(name) \
	LIST_HEAD_S name = SSP_LIST_HEAD_INIT(name)

/** 3.7.1.2	�ж������Ƿ�Ϊ��
�ӿ���ʽ	INLINE ULONG SSP_IsListEmpty(LIST_HEAD_S *pstHead);
�ӿ���;	�ж������Ƿ�Ϊ��:����pstNext, pstPrevָ���Ƿ�ָ���Լ�.
����˵��	LIST_HEAD_S *pstHead:����ͷ
����ֵ˵��	��:VSP_YES, ʧ��:VSP_NO
ʹ�þ���	
#define SSP_IsListEmpty(pstHead)     list_empty(pstHead)
*/
static INLINE BOOL SSP_IsListEmpty(const LIST_HEAD_S *pstHead)
{
    return pstHead->pstNext == pstHead;
}

/** 3.7.1.3	����ĳ�ʼ��
�ӿ���ʽ	#define SSP_ListHeadInit(ptr) do { \
(ptr)->pstNext = (ptr); (ptr)->pstPrev = (ptr);\
}While(0)
�ӿ���;	��ʼ��
����˵��	ptr:����ͷ
����ֵ˵��	
ʹ�þ���	
#define SSP_ListHeadInit(ptr)     INIT_LIST_HEAD(ptr)
*/
static INLINE void SSP_ListHeadInit(LIST_HEAD_S *pstHead)
{
    pstHead->pstNext = pstHead;
    pstHead->pstPrev = pstHead;
}

/** 3.7.1.3	�������list��Ӻ���
�ӿ���ʽ	static INLINE void SSP_BaseListADD(LIST_HEAD_S *pstNewHead,
			      LIST_HEAD_S *pstPrev,
			      LIST_HEAD_S *pstNext)
�ӿ���;	��pstNewHead���뵽pstPrev��pstNext���м�
����˵��	ptr:����ͷ
����ֵ˵��	
ʹ�þ���	
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

/** 3.7.1.4	��ͷ����
�ӿ���ʽ	INLINE void SSP_ListAdd(LIST_HEAD_S *pstNew, 
LIST_HEAD_S *pstHead);
�ӿ���;	��ͷ����
����˵��	LIST_HEAD_S *pstNew:������ڵ�
LIST_HEAD_S *pstHead:����ͷ
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListAdd( pstNew,pstHead)    list_add(pstNew, pstHead)
*/
static INLINE void SSP_ListAdd(LIST_HEAD_S *pstNew, LIST_HEAD_S *pstHead)
{
    SSP_BaseListADD(pstNew, pstHead, pstHead->pstNext);
}

/** 3.7.1.5	��β����
�ӿ���ʽ	INLINE void SSP_ListAddTail(LIST_HEAD_S *pstNew,
               LIST_HEAD_S *pstHead);
�ӿ���;	��β����
����˵��	LIST_HEAD_S *:������ڵ�
LIST_HEAD_S *:����ͷ
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListAddTail( pstNew,pstHead)    list_add_tail(pstNew, pstHead)
*/
static INLINE void  SSP_ListAddTail(LIST_HEAD_S *pstNew, LIST_HEAD_S *pstHead)
{
    SSP_BaseListADD(pstNew, pstHead->pstPrev, pstHead);
}

/** 3.7.1.6	����������ڵ�ɾ��
�ӿ���ʽ	INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry);
INLINE void SSP_ListDelInit(LIST_HEAD_S *pstEntry);
�ӿ���;	SSP_ListDel:ɾ������ͷ���Ľڵ�
SSP_ListDelTail: ɾ������β���Ľڵ�
����˵��	LIST_HEAD_S *pstEntry:����ͷ
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_BaseListDel( pstEntry)  __list_del(pstEntry)
*/
static INLINE void SSP_BaseListDel(LIST_HEAD_S * pstPrev, LIST_HEAD_S * pstNext)
{
    pstNext->pstPrev = pstPrev;
    pstPrev->pstNext = pstNext;
}


/** 3.7.1.6	����ڵ�ɾ��
�ӿ���ʽ	INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry);
INLINE void SSP_ListDelInit(LIST_HEAD_S *pstEntry);
�ӿ���;	SSP_ListDel:ɾ������ͷ���Ľڵ�
SSP_ListDelTail: ɾ������β���Ľڵ�
����˵��	LIST_HEAD_S *pstEntry:����ͷ
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListDel( pstEntry)  list_del(pstEntry)
*/
static INLINE void SSP_ListDel(LIST_HEAD_S *pstEntry)
{
    SSP_BaseListDel(pstEntry->pstPrev, pstEntry->pstNext);
    pstEntry->pstNext = pstEntry;
    pstEntry->pstPrev = pstEntry;
}


/** 3.7.1.7	����
�ӿ���ʽ	�Ƶ���ͷ��
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
�ӿ���;	SPP_ListMove: �Ƶ���ͷ��
SPP_ ListMoveTail: �Ƶ���β��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void	SSP_ListMove(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_BaseListDel(pstList->pstPrev, pstList->pstNext);
    SSP_ListAdd(pstList, pstHead);
}


/*�Ƶ���β��
Inline void SSP_ListMoveTail(LIST_HEAD_S *pstList, 
LIST_HEAD_S *pstHead);
�ӿ���;	SPP_ ListMoveTail: �Ƶ���β��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void	SSP_ListMoveTail(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_BaseListDel(pstList->pstPrev, pstList->pstNext);
    SSP_ListAddTail(pstList, pstHead);
}

/*��������뵽������
Inline void SSP_ListAddList( LIST_HEAD_S *pstHead, LIST_HEAD_S *pstFirstMoveNode, LIST_HEAD_S *pstLastMoveNode);
�ӿ���;	SPP_ ListMoveTail: �Ƶ���β��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
static INLINE void SSP_ListAddList( LIST_HEAD_S *pstHead, LIST_HEAD_S *pstFirstMoveNode, LIST_HEAD_S *pstLastMoveNode)
{
    /* ����Ҫ���Ƶ�������뵽Ŀ��������  */
        pstFirstMoveNode->pstPrev = pstHead;
        pstLastMoveNode->pstNext = pstHead->pstNext;
        pstHead->pstNext->pstPrev = pstLastMoveNode;
        pstHead->pstNext = pstFirstMoveNode;
}

/** 3.7.1.7	����һ�������Ľڵ�
�ӿ���ʽ	�Ƶ���ͷ��
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
�ӿ���;	SPP_ListMove: �Ƶ���ͷ��
SPP_ ListMoveTail: �Ƶ���β��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
  static INLINE int SSP_ListNMove(LIST_HEAD_S *pstSrcHead, LIST_HEAD_S *pstDstHead, int ulCounter )
{
    int ulLoop = 0;
    LIST_HEAD_S *pstFirstMoveNode = NULL;
    LIST_HEAD_S *pstLastMoveNode = NULL;
    pstFirstMoveNode = pstSrcHead->pstNext;
    pstLastMoveNode = pstFirstMoveNode;

    /* ֻʣ����ͷ */
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
    
    /* �ҵ�Ҫ���Ƶ����һ���ڵ� */
    while( pstLastMoveNode->pstNext != pstSrcHead && ulLoop < ulCounter )
    {
        pstLastMoveNode = pstLastMoveNode->pstNext;
        ulLoop++;
    }  
    /* ����Ҫ���Ƶ������ԭ�������а��Ƴ���  */
    pstFirstMoveNode->pstPrev->pstNext = pstLastMoveNode->pstNext;
    pstLastMoveNode->pstNext->pstPrev = pstFirstMoveNode->pstPrev;

    SSP_ListAddList( pstDstHead,  pstFirstMoveNode,  pstLastMoveNode); 
    
    return ulLoop; 
 }  

/** 3.7.1.7	����һ�������Ľڵ�
�ӿ���ʽ	�Ƶ���β��
INLINE void SSP_ListMove(LIST_HEAD_S *pstList,
        LIST_HEAD_S *pstHead);
�ӿ���;	SPP_ListMove: �Ƶ���β��
SPP_ ListMoveTail: �Ƶ���β��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListMove( pstList, pstHead)     list_move(pstList,pstHead)
*/
  static INLINE int SSP_ListNMoveTail(LIST_HEAD_S *pstSrcHead, LIST_HEAD_S *pstDstHead, int ulCounter )
{
    return SSP_ListNMove( pstSrcHead, pstDstHead->pstPrev,ulCounter );
}

/** 3.7.1.8	������ĺϲ�����
�ӿ���ʽ	INLINE void SSP_BaseListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
�ӿ���;	��list�����еĽڵ�ϲ���head������ȥ.
SSP_ListSplice_init���Ὣlist��ʼ��һ��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
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
/** 3.7.1.8	�ϲ�
�ӿ���ʽ	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
�ӿ���;	��list�����еĽڵ�ϲ���head������ȥ.
SSP_ListSplice_init���Ὣlist��ʼ��һ��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSplice(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    if (!SSP_IsListEmpty(pstList))
    {   
        SSP_BaseListSplice(pstList, pstHead);
    }
}

/** 3.7.1.8	�ϲ��ҳ�ʼ��
�ӿ���ʽ	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
�ӿ���;	��list�����еĽڵ�ϲ���head������ȥ.
SSP_ListSplice_init���Ὣlist��ʼ��һ��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
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

/** 3.7.1.8	�ϲ���β��
�ӿ���ʽ	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
�ӿ���;	��list�����еĽڵ�ϲ���head������ȥ.
SSP_ListSplice_init���Ὣlist��ʼ��һ��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
#define SSP_ListSplice( pstList, pstHead)   list_splice( pstList, pstHead)
*/
static INLINE void SSP_ListSpliceToTail(LIST_HEAD_S *pstList, LIST_HEAD_S *pstHead)
{
    SSP_ListSplice( pstList, pstHead->pstPrev );
}

/** 3.7.1.8	�ϲ���β���ҳ�ʼ��
�ӿ���ʽ	INLINE void SSP_ListSplice(LIST_HEAD *pstList, 
LIST_HEAD *pstHead);
INLINE void SSP_ListSplice Init(LIST_HEAD *pstList, 
LIST_HEAD *pstHead)
�ӿ���;	��list�����еĽڵ�ϲ���head������ȥ.
SSP_ListSplice_init���Ὣlist��ʼ��һ��
����˵��	LIST_HEAD_S *pstList:Դ����
LIST_HEAD_S *pstHead:Ŀ������
����ֵ˵��	�ɹ�:SSP_OK, ʧ��:SSP_ERR
ʹ�þ���	
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

/** 3.7.1.9	��ǰ��������ڵ�,�ñ�������������ͷ
�ӿ���ʽ	#define SSP_LIST_FOR_EACH(pos, head) _list_for_each(pos, head)
�ӿ���;	��ǰ��������ڵ�
����˵��	Pos:����ڵ�ָ��
Head:����ͷ
����ֵ˵��	
ʹ�þ���	
#define SSP_LIST_FOR_EACH(pos, head) list_for_each(pos, head)
*/
#define SSP_LIST_FOR_EACH(pos, head) \
	for (pos = (head)->pstNext; PREFETCH(pos->pstNext), pos != (head); \
        	pos = pos->pstNext)

#if 1 //add in VSP_TENANT
/**��posλ�ÿ�ʼ����**/
#define SSP_LIST_FOR_EACH_CONTINUE(pos, head) \
	for (pos = (pos)->pstNext; PREFETCH(pos->pstNext), pos != (head); \
        	pos = pos->pstNext)
        	
#endif
/** 3.7.1.10	����������ڵ�,�ñ�������������ͷ
�ӿ���ʽ	#define SSP_LIST_FOR_EACH _PREW(pos, head)    \
 list_for_each_pstPrev(pos, head)
�ӿ���;	
����˵��	Pos:����ڵ�ָ��
Head:����ͷ
����ֵ˵��	����������ڵ�
ʹ�þ���	
#define SSP_LIST_FOR_EACH_PREW(pos, head)    list_for_each_pstPrev(pos, head)
*/
#define SSP_LIST_FOR_EACH_PREW(pos, head) \
	for (pos = (head)->pstPrev; PREFETCH(pos->pstPrev), pos != (head); \
        	pos = pos->pstPrev)
        	
/** 3.7.1.11	��ǰ�������������,�ñ�������������ͷ
�ӿ���ʽ	#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member) \
	list_for_each_entry(pos, head, member)
�ӿ���;	���������������
����˵��	Pos: ���������ָ��
Head:����ͷ
Member:����ڵ���������ṹ�е�����
����ֵ˵��	
ʹ�þ���	
#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member) list_for_each_entry(pos, head, member)
*/
#define SSP_LIST_FOR_EACH_ENTRY(pos, head, member, type)				\
	for (pos = SSP_ListEntry((head)->pstNext, type, member);	\
	     PREFETCH(pos->member.pstNext), &pos->member != (head); 	\
	     pos = SSP_ListEntry(pos->member.pstNext, type, member))

/** 3.7.1.12	���������������
�ӿ���ʽ	#define SSP_LIST_FOR_EACH_ENTRY_REVERSE(pos, head, member)	\
list_for_each_entry_reverse
�ӿ���;	���������������
����˵��	Pos: ���������ָ��
Head:����ͷ
Member:����ڵ���������ṹ�е�����
����ֵ˵��	
ʹ�þ���
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


/** 3.7.2	hlist�ķ�װ*/

/*��ϣ����ڵ㶨��*/
typedef struct HlistHead_S
{
	 struct HlistNode_S *pstFirst;
}HLIST_HEAD_S;

/*��ϣ��ͻ����ڵ㶨��*/
typedef struct HlistNode_S
{
	 struct HlistNode_S *pstNext, **ppstPrev;
}HLIST_NODE_S;

/** 3.7.2.1	�����ͳ�ʼ��
�ӿ���ʽ	Typedefine HLIST_HEAD_S  HLIST_HEAD_S
Typedefine HLIST_NODE_S  HLIST_NODE_S
#define SSP_HLIST_HEAD_INIT { .pstFirst = NULL }
#define SSP_HLIST_HEAD(name) HLIST_HEAD_S name = {  .pstFirst = NULL }
#define SSP_INIT_HLIST_HEAD(ptr) ((ptr)->pstFirst = NULL)
�ӿ���;	hlist�����ͳ�ʼ��
����˵��	
����ֵ˵��	
ʹ�þ���
#define SSP_HLIST_HEAD_INIT            HLIST_HEAD_INIT
#define SSP_HLIST_HEAD(name)            HLIST_HEAD(name)
#define SSP_INIT_HLIST_HEAD(ptr)      INIT_HLIST_HEAD(ptr)
*/
#define SSP_HLIST_HEAD_INIT { .pstFirst = NULL }
#define SSP_HLIST_HEAD(name) HLIST_HEAD_S name = {  .pstFirst = NULL }
#define SSP_INIT_HLIST_HEAD(ptr) ((ptr)->pstFirst = NULL)
/* ��ʼ����ϣ��ͻ����ڵ� */
static INLINE void SSP_INIT_HLIST_NODE(HLIST_NODE_S *pHnode)
{
	pHnode->pstNext = NULL;
	pHnode->ppstPrev= NULL;
}

/** 3.7.2.2	�ڵ��Ƿ��г�ͻ�ڵ�
�ӿ���ʽ	INLINE ULONG SSP_HLIST_UNHASHED(CONST HLIST_NODE_S *pHnode)
�ӿ���;	�ڵ��Ƿ��г�ͻ�ڵ�
����˵��	CONST HLIST_NODE_S *pHnode:hlist�ڵ�
����ֵ˵��	��:VSP_YES, ��:VSP_NO
ʹ�þ���	
#define SSP_HLIST_UNHASHED(CONST HLIST_NODE_S *pHnode) hlist_unhashed(const HLIST_NODE_S * h)
*/
 static INLINE int SSP_HlistUnhashed(const HLIST_NODE_S *pHnode)
{
	return !pHnode->ppstPrev;
}

/** 3.7.2.3	hlist�Ƿ�Ϊ��
�ӿ���ʽ	INLINE LONG SSP_HLIST_EMPTY(CONST HLIST_HEAD_S *pHlist)
�ӿ���;	hlist�Ƿ�Ϊ��
����˵��	CONST HLIST_HEAD_S *pHlist: hlistͷ��
����ֵ˵��	��:VSP_YES, ��:VSP_NO
ʹ�þ���	
#define SSP_HLIST_EMPTY(pHlist) hlist_empty(const HLIST_NODE_S * h)
*/
 static INLINE int SSP_HlistEmpty(const HLIST_HEAD_S *pHlistHead)
{
	return !pHlistHead->pstFirst;
}

	
/* ��ʼ����ϣ��ͻ����ͷ*/
static INLINE void SSP_HlistHeadInit( HLIST_HEAD_S *pHlistHead)
{
	pHlistHead->pstFirst = NULL;
}

/** 3.7.2.4	�������ɾ��һ��hlist�ڵ�
�ӿ���ʽ	INLINE void SSP_HLIST_DEL(HLIST_NODE_S *pHnode)
�ӿ���;	ɾ��һ��hlist�ڵ�
����˵��	HLIST_NODE_S *pHnode: hlist�ڵ�
����ֵ˵��	��
ʹ�þ���	
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

/** 3.7.2.4	ɾ��һ��hlist�ڵ�
�ӿ���ʽ	INLINE void SSP_HLIST_DEL(HLIST_NODE_S *pHnode)
�ӿ���;	ɾ��һ��hlist�ڵ�
����˵��	HLIST_NODE_S *pHnode: hlist�ڵ�
����ֵ˵��	��
ʹ�þ���	
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
	     	     

/** 3.7.2.5	��hlist��ͷ����һ���ڵ�
�ӿ���ʽ	INLINE void SSP_HLIST_ADD_HEAD(HLIST_NODE_S *pHnode,
HLIST_HEAD_S *pHlist)
�ӿ���;	��pHnode�ӵ�pHlist��ͷ��.
����˵��	HLIST_NODE_S *pHnode: hlist�ڵ�
HLIST_HEAD_S *pHlist: hlistͷ��
����ֵ˵��	��
ʹ�þ���
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

/** 3.7.2.6	��ĳ�ڵ�ǰ����һ���½ڵ�
�ӿ���ʽ	INLINE void SSP_HLIST_ADD_BEFORE(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
�ӿ���;	��pNextHnode���뵽pHnodeǰ
����˵��	HLIST_NODE_S *pHnode: hlist�ڵ�
HLIST_NODE_S *pNextHnode: �µ�hlist�ڵ�
����ֵ˵��	��
ʹ�þ���
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

/** 3.7.2.7	��ĳ�ڵ�����һ���½ڵ�
�ӿ���ʽ	INLINE void SSP_HLIST_ADD_AFTER(HLIST_NODE_S *pHnode,
					HLIST_NODE_S *pNextHnode)
�ӿ���;	��pNextHnode���뵽pHnode��
����˵��	HLIST_NODE_S *pHnode: hlist�ڵ�
HLIST_NODE_S *pNextHnode: �µ�hlist�ڵ�
����ֵ˵��	��
ʹ�þ���
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

/** 3.7.2.8	����hlist����
�ӿ���ʽ	#define SSP_HLIST_FOR_EACH(pos, head)  hlist_for_each(pos, head) 
�ӿ���;	����hlist�����
����˵��	pos:����ڵ�ָ��
head:hlist����ͷ
����ֵ˵��	
ʹ�þ���	
#define SSP_HLIST_FOR_EACH(pos, head)  hlist_for_each(pos, head)  
*/
#define SSP_HLIST_FOR_EACH(pos, head)  \
	for (pos = (head)->pstFirst; pos && ({ PREFETCH(pos->pstNext); 1; }); \
	     pos = pos->pstNext)


/** 3.7.2.9	����hlist�����е����������
�ӿ���ʽ	#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) \
  hlist_for_each_entry(tpos, pos, head, member)	
�ӿ���;	����hlist�����е����������
����˵��	tpos: hlist����ڵ���������ṹ�е���
pos: hlist����ڵ�ָ��
head:hlist����ͷ
member: ����ڵ���������ṹ�е�����
����ֵ˵��	
ʹ�þ���	
#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) hlist_for_each_entry(tpos, pos, head, member)	
*/
#define SSP_HLIST_FOR_EACH_ENTRY(tpos, pos, head, member,type) 			 \
	for (pos = (head)->pstFirst;\
	     pos && (PREFETCH(pos->pstNext), 1) &&\
		(tpos = SSP_HlistEntry(pos, type, member), 1);\
	     pos = pos->pstNext)

/** 3.7.2.10	��ĳ�ڵ����һ���ڵ㿪ʼ����hlist�����е����������
�ӿ���ʽ	#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member)\
 hlist_for_each_entry_continue(tpos, pos, member)	
�ӿ���;	��ĳ�ڵ����һ���ڵ㿪ʼ����hlist�����е����������
����˵��	tpos: hlist����ڵ���������ṹ�е���
pos: hlist����ڵ�ָ��
member: ����ڵ���������ṹ�е�����
����ֵ˵��	
ʹ�þ���	
#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member)    hlist_for_each_entry_continue(tpos, pos, member)	 
*/
#define SSP_HLIST_FOR_EACH_ENTRY_CONTINUE(tpos, pos, member,type) 	 \
	for (pos = (pos)->pstNext;						 \
	     pos && (PREFETCH(pos->pstNext), 1) &&			 \
		(tpos = SSP_HlistEntry(pos, type, member), 1); \
	     pos = pos->pstNext)

/** 3.7.2.11	��ĳ�ڵ㿪ʼ����hlist�����е����������
�ӿ���ʽ	#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member) \
hlist_for_each_entry_from(tpos, pos, member)	
�ӿ���;	��ĳ�ڵ㿪ʼ����hlist�����е����������
����˵��	tpos: hlist����ڵ���������ṹ�е���
pos: hlist����ڵ�ָ��
member: ����ڵ���������ṹ�е�����
����ֵ˵��	
ʹ�þ���	
#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member)    hlist_for_each_entry_from(tpos, pos, member)	
*/
#define SSP_HLIST_FOR_EACH_ENTRY_FROM(tpos, pos, member,type)		 \
	for (; pos && ({ PREFETCH(pos->pstNext); 1;}) &&			 \
		({ tpos = SSP_HlistEntry(pos, type, member); 1;}); \
	     pos = pos->pstNext)

#endif

