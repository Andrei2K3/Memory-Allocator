// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define KB4 (4 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

static struct block_meta *head;
static int e_4KB_or_128KB;

// Prealocam cei 128kb
static void *heap_preallocation(void)
{
size_t dim_alocata = 128 * 1024;
struct block_meta *aux = sbrk(dim_alocata);
if (aux == (void *)-1) {
	e_4KB_or_128KB = 0;
return NULL;
}

aux->status = STATUS_ALLOC;
aux->size = dim_alocata - ALIGN(sizeof(struct block_meta));
aux->prev = NULL;
aux->next = NULL;

return (void *)aux;
}

void *os_malloc(size_t size)
{
  //
size_t LIMITA = MMAP_THRESHOLD;
if (e_4KB_or_128KB == 1)
	LIMITA = KB4;
e_4KB_or_128KB = 0;
//
if (size == 0) {
	e_4KB_or_128KB = 0;
return NULL;
}
if (head == NULL) {
// Daca initial facem cu brk, prealocam heap ul
	if (size + ALIGN(sizeof(struct block_meta)) < LIMITA) {
		head = heap_preallocation();
if (head == NULL) {
	e_4KB_or_128KB = 0;
return NULL;
}
return (char *)head + ALIGN(sizeof(struct block_meta));
} else {
// Altfel nu mai prealocam
	size = ALIGN(size);
void *block_start = mmap(NULL, size + ALIGN(sizeof(struct block_meta)),
PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (block_start == MAP_FAILED) {
	return NULL;
e_4KB_or_128KB = 0;
}

struct block_meta *new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_MAPPED;
new_block->prev = NULL;
new_block->next = NULL;
head = new_block;

return (char *)new_block + ALIGN(sizeof(struct block_meta));
}
}

size = ALIGN(size); // payload+padding

// De aici comentam
struct block_meta *current = head;
// Unificare blocuri goale
while (current) {
	if (current->status == STATUS_FREE) {
// Unificare blocuri
		struct block_meta *next = current->next;
while (next != NULL && next->status == STATUS_FREE) {
	current->size += ALIGN(sizeof(struct block_meta)) + next->size;
current->next = next->next;

if (next->next != NULL) {
	e_4KB_or_128KB = 0;
	next->next->prev = current;
}

next = current->next;
}
}
current = current->next;
}

// Splituim blocurile si vedem daca putem introduce un bloc nou de dimensiune
// size
current = head;
while (current != NULL) {
	if (current->status == STATUS_FREE && current->size > ALIGN(sizeof(struct block_meta)) + size) {
// Splituim blocurile
		struct block_meta *next_node = (struct block_meta *)((char *)current + ALIGN(sizeof(struct block_meta)) + size);

// Actualizam blocul nou creat
next_node->size = current->size - size - ALIGN(sizeof(struct block_meta));
next_node->status = STATUS_FREE;
// Actualizam blocul curent
current->size = size;
if (current->size + ALIGN(sizeof(struct block_meta)) < LIMITA)
	current->status = STATUS_ALLOC;
else
	current->status = STATUS_MAPPED;
// Inseram next_node intre 2 blocuri!!
next_node->next = current->next;
next_node->prev = current;
if (current->next != NULL)
	current->next->prev = next_node;
current->next = next_node;

return (char *)current + ALIGN(sizeof(struct block_meta)); // returnam payloadul
} else if (current->status == STATUS_FREE && current->size >= size) {
	if (current->size + ALIGN(sizeof(struct block_meta)) < LIMITA)
		current->status = STATUS_ALLOC;
else
	current->status = STATUS_MAPPED;
return (char *)current + ALIGN(sizeof(struct block_meta));
}
current = current->next;
}

// Expand
current = head;
while (current->next != NULL)
	current = current->next;
if (current->status == STATUS_FREE) {
	size_t expand_space = size - current->size;
if (expand_space < LIMITA) {
	if (sbrk(expand_space) == (void *)-1) // am adaugat in continuare pe heap
		return NULL;
current->size = size;
current->status = STATUS_ALLOC;
return (char *)current + ALIGN(sizeof(struct block_meta));
}
}

// Alocam un bloc nou de memorie, pentru ca n am gasit spatiu util in ce era
// pana acum
current = head;
while (current->next != NULL)
	current = current->next;
size_t block_size = size + ALIGN(sizeof(struct block_meta));
// Folosim sbrk pt alocari mici
if (block_size < LIMITA) {
	void *block_start = sbrk(block_size);
if (block_start == (void *)-1) {
	e_4KB_or_128KB = 0;
return NULL;
}

struct block_meta *new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_ALLOC;
new_block->prev = current;
new_block->next = NULL;
current->next = new_block;

return (char *)new_block + ALIGN(sizeof(struct block_meta));
} else {
// Alocam cu mmap blocurile mari
	void *block_start = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (block_start == MAP_FAILED) {
	e_4KB_or_128KB = 0;
return NULL;
}

struct block_meta *new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_MAPPED;
new_block->prev = current;
new_block->next = NULL;
current->next = new_block;

return (char *)new_block + ALIGN(sizeof(struct block_meta));
}
}

void os_free(void *ptr)
{
if (ptr == NULL) {
	e_4KB_or_128KB = 0;
return;
}

struct block_meta *block = (struct block_meta *)((char *)ptr - ALIGN(sizeof(struct block_meta)));

if (block->status == STATUS_MAPPED) {
	struct block_meta *block_prev = block->prev;
struct block_meta *block_next = block->next;
if (block_prev == NULL && block_next == NULL) {
	head = NULL;
} else if (block_prev && block_next == NULL) {
	block_prev->next = NULL;
} else if (block_prev == NULL && block_next) {
	block_next->prev = NULL;
} else {
	block_prev->next = block_next;
block_next->prev = block_prev;
}
block->next = NULL;
block->prev = NULL;
if (munmap(block, block->size + ALIGN(sizeof(struct block_meta))) == -1) {
	e_4KB_or_128KB = 0;
return;
}
} else {
	block->status = STATUS_FREE;
}
}

void *os_calloc(size_t nmemb, size_t size)
{
// Implementare os_calloc
size_t total_size = nmemb * size;
e_4KB_or_128KB = 1;
void *allocated_memory = os_malloc(total_size);

if (allocated_memory != NULL) {
	e_4KB_or_128KB = 0;
	memset(allocated_memory, 0, total_size);
}

return allocated_memory;
}

void *os_realloc(void *ptr, size_t size)
{
if (ptr == NULL)
	return os_malloc(size);

if (size == 0) {
	os_free(ptr);
return NULL;
}

size = ALIGN(size);

struct block_meta *current = (struct block_meta *)((char *)ptr - ALIGN(sizeof(struct block_meta)));
if (current->status == STATUS_FREE)
	return NULL;


if ((struct block_meta *)head == current &&
current->size + ALIGN(sizeof(struct block_meta)) > MMAP_THRESHOLD) {
	struct block_meta *aux = current;

if (size + ALIGN(sizeof(struct block_meta)) < MMAP_THRESHOLD) {
	head = heap_preallocation();
if (head == NULL) {
	e_4KB_or_128KB = 0;
	return NULL;
}
current = head;
} else {
	size = ALIGN(size);
void *block_start = mmap(NULL, size + ALIGN(sizeof(struct block_meta)),
PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (block_start == MAP_FAILED) {
	e_4KB_or_128KB = 0;
	return NULL;
}

struct block_meta *new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_MAPPED;
new_block->prev = NULL;
new_block->next = NULL;
head = new_block;
current = head;
}
    //
current->next = aux->next;
aux->prev = current;
if (munmap(aux, aux->size + ALIGN(sizeof(struct block_meta))) == -1)
	return NULL;
return (char *)current + ALIGN(sizeof(struct block_meta));
}

  // Eliminare bloc mapat
if (ALIGN(sizeof(struct block_meta)) + current->size > MMAP_THRESHOLD) {
	size_t block_size = size + ALIGN(sizeof(struct block_meta));
struct block_meta *new_block;
// Folosim sbrk pt alocari mici
if (block_size < MMAP_THRESHOLD) {
	void *block_start = sbrk(block_size);
		if (block_start == (void *)-1) {
			e_4KB_or_128KB = 0;
			return NULL;
}

new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_ALLOC;
new_block->prev = current->prev;
new_block->next = current->next;
current->prev->next = new_block;
if (current->next != NULL)
	current->next->prev = new_block;

// return (char *)new_block + ALIGN(sizeof(struct block_meta));
} else {
// Alocam cu mmap blocurile mari
	void *block_start = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (block_start == MAP_FAILED)
	return NULL;

new_block = (struct block_meta *)block_start;
new_block->size = size;
new_block->status = STATUS_MAPPED;
new_block->prev = current->prev;
new_block->next = current->next;
current->prev->next = new_block;
if (current->next != NULL)
	current->next->prev = new_block;
}
if (munmap(current, current->size + ALIGN(sizeof(struct block_meta))) == -1)
	return NULL;
return (char *)new_block + ALIGN(sizeof(struct block_meta));
}

if (current->size >= size) {
	if (current->size > size + ALIGN(sizeof(struct block_meta))) {
  // Splituim blocurile
		struct block_meta *next_node = (struct block_meta *)((char *)current + ALIGN(sizeof(struct block_meta)) + size);

// Actualizam blocul nou creat
next_node->size = current->size - size - ALIGN(sizeof(struct block_meta));
next_node->status = STATUS_FREE;
      // Actualizam blocul curent
current->size = size;
if (current->size + ALIGN(sizeof(struct block_meta)) < MMAP_THRESHOLD)
	current->status = STATUS_ALLOC;
else
	current->status = STATUS_MAPPED;
      // Inseram next_node intre 2 blocuri!!
next_node->next = current->next;
next_node->prev = current;
if (current->next != NULL)
	current->next->prev = next_node;
current->next = next_node;

return (char *)current + ALIGN(sizeof(struct block_meta)); // returnam payloadul
} else {
	return (char *)current + ALIGN(sizeof(struct block_meta));
}
} else {
	if (current->next == NULL) {
		size_t expand_space = size - current->size;
			if (expand_space < MMAP_THRESHOLD) {
				if (sbrk(expand_space) == (void *)-1) // am adaugat in continuare pe heap
					return NULL;
current->size = size;
current->status = STATUS_ALLOC;
return (char *)current + ALIGN(sizeof(struct block_meta));
} else {
	void *varf_heap = (char *)current + ALIGN(sizeof(struct block_meta)) + current->size;
void *block_start = mmap(varf_heap, expand_space, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (block_start == MAP_FAILED) {
	e_4KB_or_128KB = 0;
	return NULL;
}
current->size = size;
return (char *)current + ALIGN(sizeof(struct block_meta));
}
}
size_t dim_actual = current->size;

struct block_meta *next = current->next;
while (next != NULL && next->status == STATUS_FREE) {
	current->size += ALIGN(sizeof(struct block_meta)) + next->size;
current->next = next->next;

if (next->next != NULL) {
	next->next->prev = current;
	e_4KB_or_128KB = 0;
}

next = current->next;
}
if (current->size >= size) {
	if (current->size > size + ALIGN(sizeof(struct block_meta))) {
// Splituim blocurile
		struct block_meta *next_node = (struct block_meta *)((char *)current + ALIGN(sizeof(struct block_meta)) + size);

// Actualizam blocul nou creat
next_node->size = current->size - size - ALIGN(sizeof(struct block_meta));
next_node->status = STATUS_FREE;
// Actualizam blocul curent
current->size = size;
if (current->size + ALIGN(sizeof(struct block_meta)) < MMAP_THRESHOLD)
	current->status = STATUS_ALLOC;
else
	current->status = STATUS_MAPPED;
// Inseram next_node intre 2 blocuri!!
next_node->next = current->next;
next_node->prev = current;
	if (current->next != NULL)
		current->next->prev = next_node;
current->next = next_node;

return (char *)current + ALIGN(sizeof(struct block_meta));
} else {
	return (char *)current + ALIGN(sizeof(struct block_meta));
}
} else {
	void *new_block;
current->status = STATUS_FREE;
new_block = os_malloc(size);
memmove(new_block, (void *)((char *)current + ALIGN(sizeof(struct block_meta))), dim_actual);
return new_block;
}
}
return NULL;
}
