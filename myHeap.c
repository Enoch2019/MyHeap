// heap management system
// Edit by: Enoch2019

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myHeap.h"

/** minimum total space for heap */
#define MIN_HEAP 4096
/** minimum amount of space for a free Chunk (excludes Header) */
#define MIN_CHUNK 32

#define ALLOC 0x55555555
#define FREE  0xAAAAAAAA

/// Types:

typedef unsigned int  uint;
typedef unsigned char byte;

typedef uintptr_t     addr; // an address as a numeric type

/** The header for a chunk. */
typedef struct header {
	uint status;    /**< the chunk's status -- ALLOC or FREE */
	uint size;      /**< number of bytes, including header */
	byte data[];    /**< the chunk's data -- not interesting to us */
} header;

/** The heap's state */
struct heap {
	void  *heapMem;     /**< space allocated for Heap */
	uint   heapSize;    /**< number of bytes in heapMem */
	void **freeList;    /**< array of pointers to free chunks */
	uint   freeElems;   /**< number of elements in freeList[] */
	uint   nFree;       /**< number of free chunks */
};


/// Variables:

/** The heap proper. */
static struct heap Heap;


/// Functions:

static addr heapMaxAddr (void);
static void removeAllocChunks (int);
static void updateFreeList (void);

/** Initialise the Heap. */
int initHeap (int size)
{
	Heap.nFree = 0;
	Heap.freeElems = 0;
    
    // Checking size > MIN_CHUNK and adjusting to multiple of 4
	if (size < MIN_HEAP) {
	    Heap.heapSize = MIN_HEAP;
	} else if (size % 4) {
	    Heap.heapSize = size + 4 - (size % 4);
	} else {
	    Heap.heapSize = size;
	}
	
	Heap.heapMem = (void *) malloc(Heap.heapSize);
	
	Heap.freeList = 
	    (void **) malloc ((Heap.heapSize/MIN_CHUNK) * sizeof(void *));
	
	// check for NULL
	if (Heap.heapMem == NULL) return -1;
	if (Heap.freeList == NULL) return -1;
	
	// zero out heap
	memset(Heap.heapMem, 0, Heap.heapSize);
	
	header * initHeader = Heap.heapMem;
	
	// Set whole chunk as one free chunk
	initHeader->status = FREE;
	initHeader->size = Heap.heapSize;
	Heap.freeElems = Heap.heapSize/MIN_CHUNK;
	Heap.nFree++;
	
	Heap.freeList[0] = (void *) Heap.heapMem;

	return 0; // this just keeps the compiler quiet
}

/** Release resources associated with the heap. */
void freeHeap (void)
{
	free (Heap.heapMem);
	free (Heap.freeList);
}

/** Allocate a chunk of memory large enough to store `size' bytes. */
void *myMalloc (int size)
{
    // Checking size and adjust to multiple of 4
    if (size < 1) {
        return NULL;
    } else if (size % 4) {
        size += 4 - size % 4;
    }
    
    header * curr = NULL; // current free chunk
    header * small = NULL; // smallest avaible free chunk
    int j = 0; // index number for small in freeList
    
    // Find smallest suitable sized free chunk
    for (int i = 0; i < Heap.nFree; i++) {
        
        curr = (header *) Heap.freeList[i];
        if (size + sizeof(header) <= curr->size) {
            if (small == NULL) {
                small = curr;
                j = i;
            } else if (small->size > curr->size) {
                small = curr;
                j = i;
           }
        }
    }
    
    // No suitable chunks found
    if (small == NULL) return NULL;
    
    // Check if free chunk is sizable enough to split into smaller
    if (small->size < size + sizeof(header) + MIN_CHUNK) {
        small->status = ALLOC;
        removeAllocChunks(j);
        return small->data;
    } else {
        small->status = ALLOC;
        Heap.freeList[j] = (void *) 
            ((addr) Heap.freeList[j] + sizeof(header) + size);
        curr = Heap.freeList[j];
        curr->size = small->size - sizeof(header) - size;
        curr->status = FREE;
        small->size = size + sizeof(header);
        return small->data;
    }
}

/** Deallocate a chunk of memory. */
void myFree (void *obj)
{
    if (obj == NULL) return;
    
	header * freeObj = (header *)((addr) obj - sizeof (header));
	
	// Checking if chunk is ALLOC
	// Also takes care of the case if address is outside heap.
	if (freeObj->status == FREE) {
	    fprintf(stderr, "Attempt to free unallocated chunk\n");
	    exit(1);
	} else if (freeObj->status != ALLOC) {
	    fprintf(stderr, "Attempt to free corrupted chunk\n");
	    exit(1);
	} else if ((addr) freeObj > heapMaxAddr()) {
	    fprintf(stderr, "Attempt to free chunk outside of heap\n");
	    exit(1);
	}
	
    // Adds chunk in ascending order to free list
    for (int i = 0; i < Heap.nFree - 1; i++) {
        header * prev = Heap.freeList[i];
        header * next = Heap.freeList[i+1];
    
        // Check if between adjacent adresses
        if ((addr) prev < (addr) freeObj && 
            (addr) freeObj < (addr) next) {
            
            for (int j = Heap.nFree; j > i + 1; j--) {
                Heap.freeList[j] = Heap.freeList[j-1];
            }
            Heap.freeList[i+1] = freeObj;
            Heap.nFree++;
            break;
        }
    }
    
    //Lowest address in freeList
    if ((addr) freeObj < (addr) Heap.freeList[0]) {
        for (int i = Heap.nFree; i > 0; i--) {
            Heap.freeList[i] = Heap.freeList[i-1];
        }
        Heap.freeList[0] = freeObj;
        freeObj->status = FREE;
        Heap.nFree++;
    }
    
    //Highest address in freeList
    if ((addr) freeObj > (addr) Heap.freeList[(Heap.nFree-1)]) {
        Heap.freeList[Heap.nFree] = freeObj;
        freeObj->status = FREE;
        Heap.nFree++;
    }
    //}
    updateFreeList();
	return;
}

/** Return the first address beyond the range of the heap. */
static addr heapMaxAddr (void)
{
	return (addr) Heap.heapMem + Heap.heapSize;
}

/** Convert a pointer to an offset in the heap. */
int heapOffset (void *obj)
{
	addr objAddr = (addr) obj;
	addr heapMin = (addr) Heap.heapMem;
	addr heapMax =        heapMaxAddr ();
	if (obj == NULL || !(heapMin <= objAddr && objAddr < heapMax))
		return -1;
	else
		return (int) (objAddr - heapMin);
}

/** Dump the contents of the heap (for testing/debugging). */
void dumpHeap (void)
{
	int onRow = 0;

	// We iterate over the heap, chunk by chunk; we assume that the
	// first chunk is at the first location in the heap, and move along
	// by the size the chunk claims to be.
	addr curr = (addr) Heap.heapMem;
	while (curr < heapMaxAddr ()) {
		header *chunk = (header *) curr;

		char stat;
		switch (chunk->status) {
		case FREE:  stat = 'F'; break;
		case ALLOC: stat = 'A'; break;
		default:
			fprintf (
				stderr,
				"myHeap: corrupted heap: chunk status %08x\n",
				chunk->status
			);
			exit (1);
		}
		
		printf (
			"+%05d (%c,%5d)%c",
			heapOffset ((void *) curr),
			stat, chunk->size,
			(++onRow % 5 == 0) ? '\n' : ' '
		);

		curr += chunk->size;
	}

	if (onRow % 5 > 0)
		printf ("\n");
}
/** Removes allocated chucks from free list at index i */
static void removeAllocChunks (int i) 
{
    for (i = i; i < Heap.nFree; i++) {
        Heap.freeList[i] = Heap.freeList[i+1];
    }
    Heap.nFree--;
}


/** Merges adjacent free chunks */
static void updateFreeList (void)
{
    for (int i = 0; i < Heap.nFree; i++) {
        header * curr = Heap.freeList[i];
        header * next = Heap.freeList[i+1];
        
        // Check for adjacent adresses
        if ((addr)((addr) curr + curr->size) == (addr)next) {
            next->status = ALLOC;
            curr->size = curr->size + next->size;
            removeAllocChunks(i+1);
            // Rechecks
            i--;
        }
    }
    return;
}


