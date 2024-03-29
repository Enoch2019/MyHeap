// heap management system

#ifndef _MYHEAP_H
#define _MYHEAP_H

/** Initialise the Heap. */
int initHeap (int size);

/** Release resources associated with the heap. */
void freeHeap (void);

/** Allocate a chunk of memory large enough to store `size' bytes. */
void *myMalloc (int size);

/** Deallocate a chunk of memory. */
void myFree (void *obj);

/** Convert a pointer to an offset in the heap. */
int heapOffset (void *obj);

/** Dump the contents of the heap (for testing/debugging). */
void dumpHeap (void);

#endif // !defined(_MYHEAP_H)
