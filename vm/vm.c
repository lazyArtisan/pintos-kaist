/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"
#include "userprog/process.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;
	// printf("\nalloc addr: %p\n", upage);
	// printf("alloc_page va: %p\n", upage);
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

		struct page *new_page = malloc(sizeof(struct page));
		if (new_page == NULL)
		{

			goto err;
		}

		memset(new_page, 0, sizeof(struct page));
		// printf("\n\npage_alloc_ addr22 : %p\n", upage);

		uninit_new(new_page, pg_round_down(upage), init, type, aux, VM_TYPE(type) == VM_FILE ? file_backed_initializer : anon_initializer);

		new_page->writable = writable;

		if (!spt_insert_page(spt, new_page))
		{
			// 재원 추가 일단 프레임 테이블이 없어 냅다 free 잘못되면
			// palloc_free_page(new_page->frame->kva);
			// free(new_page->frame);
			printf("\n\n%pdsad\n", upage);

			free(new_page);
			goto err;
		}
		// printf("\n\npage_alloc_ addr2233: %p\n", upage);

		return true;
	}
	// printf("\n\npage_alloc_ addr2233: %p\n", upage);

err:
{
	printf("안녕 나 뒤졌어 ㅋㅋ");
	return false;
}
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
	struct hash_elem *e;

	// va에 해당하는 hash_elem 찾기
	page->va = pg_round_down(va);
	e = hash_find(&spt->pages, &page->hash_elem);

	// 있으면 e에 해당하는 페이지 반환
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	return hash_insert(&spt->pages, &page->hash_elem) == NULL ? true : false; // 존재하지 않을 경우에만 삽입
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if (frame->kva == NULL) // 나중에 스왑 아웃 처리로 바꿔야 함
		PANIC("TO DO");
	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	uintptr_t rsp = f->rsp;

	if (!user)
		rsp = thread_current()->rsp;

	if (addr == NULL)
		return false;

	if (is_kernel_vaddr(addr))
		return false;

	if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
	{
		if ((USER_STACK - (1 << 20) <= rsp - 8) && addr == rsp - 8 && addr <= USER_STACK)
			vm_stack_growth(addr);
		else if ((USER_STACK - (1 << 20) <= rsp) && addr >= rsp && addr <= USER_STACK)
			vm_stack_growth(addr);

		/* TODO: Validate the fault */
		page = spt_find_page(spt, addr);
		if (page == NULL)
			return false;
		if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
			return false;
		return vm_do_claim_page(page);
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	// spt에서 va에 해당하는 page 찾기
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 가상 주소와 물리 주소를 매핑
	struct thread *current = thread_current();
	pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

	return swap_in(page, frame->kva); // uninit_initialize
}

unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src)
{
	// dst 해시 테이블 초기화 이전에 함.
	// hash_init(&dst->hash_table, page_hash, page_less, NULL);

	// src 해시 테이블 순회
	struct hash_iterator i;
	hash_first(&i, &src->pages);
	while (hash_next(&i))
	{ // hash_next는 모든 요소를 돌면 bukets->buket의 요소 모두 돌면 (이유는 malloc으로 bukets를 list 포인터 배열로 만들었기 때문)
		struct page *original_page = hash_entry(hash_cur(&i), struct page, hash_elem);

		// 새로운 페이지 구조체 할당
		if (VM_TYPE(original_page->operations->type) == VM_UNINIT)
		{
			// printf("im_uninit!!\n");

			struct aux_pak *new_aux = malloc(sizeof(struct aux_pak));
			if (new_aux == NULL)
			{
				// printf("fuck\n");
				return false;
			}
			memcpy(new_aux, original_page->uninit.aux, sizeof(struct aux_pak));

			// 이거 아닌 것 같은데 file 많이 많듦
			// new_aux->file = file_duplicate(new_aux->file);

			vm_alloc_page_with_initializer(original_page->uninit.type, original_page->va, original_page->writable, original_page->uninit.init, new_aux);
		}

		else
		{
			// printf("im_onon!!\n");
			if (!vm_alloc_page_with_initializer(page_get_type(original_page), original_page->va, original_page->writable, NULL, NULL))
			{
				// printf("hellodasdasdsa");
				return false;
			}

			struct page *new_page = spt_find_page(dst, original_page->va);
			if (!vm_do_claim_page(new_page))
			{
				//  printf("\n\ndo claim_copy Failed!!\n\n");
				return false;
			}

			memcpy(new_page->frame->kva, original_page->frame->kva, PGSIZE);
		}

		// printf("hello");
	}
	// printf("\n\nfork done hello");
	return true;
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, hash_page_destroy); // 해시 테이블의 모든 요소를 제거
}
