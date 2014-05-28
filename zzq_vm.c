#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/decompress/mm.h>

MODULE_LICENSE("ZZQ");

#define current get_current()
struct task_struct;

static void mtest_dump_vma_list(void) { struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	printk("The current process id %s\n", current->comm);
	printk("mtest_dump_vma_list\n");
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		printk(" VMA 0x%lx-0x%lx ", vma->vm_start, vma->vm_end);
		if (vma->vm_flags & VM_WRITE)
			printk(" WRITE ");
		if (vma->vm_flags & VM_READ)
			printk(" READ ");
		if (vma->vm_flags & VM_EXEC)
			printk(" EXEC ");
		printk("\n");
	}
	up_read(&mm->mmap_sem);
}

static void mtest_find_vma(unsigned long addr) {
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	
	printk("mtest_find_vma\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (vma && addr >= vma->vm_start) {
		printk("found vma 0x%lx-0x%lx flag %lx for addr 0x%lx\n", 
			vma->vm_start, vma->vm_end, vma->vm_flags, addr);
	} else {
		printk("no vma found for %lx\n", addr);
	}
	up_read(&mm->mmap_sem);
}

static struct page* my_follow_page(struct vm_area_struct *vma, unsigned long addr) {
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pgd_t *pgd = NULL;
	pte_t *pte = NULL;
	spinlock_t *ptl = NULL;
	struct page* page = NULL;
	struct mm_struct *mm = current->mm;
	pgd = pgd_offset(current->mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		goto out;
	}
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		goto out;
	}
	printk("aaaa\n");
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		goto out;
	}
	pte = pte_offset_map_lock(current->mm, pmd, addr, &ptl);
	printk("bbbb\n");
	if (!pte) goto out;
	printk("cccc\n");
	if (!pte_present(*pte)) goto unlock;
	page = pfn_to_page(pte_pfn(*pte));
	if (!page) goto unlock;
	get_page(page);
unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return page;
}

static void mtest_find_page (unsigned long addr) {
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long kernel_addr;
	struct page *page;
	printk("mtest_find_page\n");
	if (!mm) printk("what the fuck!\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (!vma) {
		printk("The address %lx is not valid\n", addr);
		goto out;
	}
	page = my_follow_page(vma, addr);
	if (!page) {
		printk("page not fount for 0x%lx\n", addr);
		goto out;
	}

	printk("eeee\n");
	kernel_addr = (unsigned long) page_address(page);
	kernel_addr += (addr&~PAGE_MASK);
	printk("find 0x%lx to kernel address 0x%lx\n", addr, kernel_addr);

out:
	up_read(&mm->mmap_sem);
}

static void mtest_write_val(unsigned long addr, unsigned long val) {
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct page *page;
	unsigned long kernel_addr;
	printk("mtest_write_val\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (vma && addr >= vma->vm_start && (addr + sizeof(val)) < vma->vm_end) {
		if (!(vma->vm_flags & VM_WRITE)) {
			printk("vma is not writable for 0x%lx\n", addr);
			goto out;
		}
		page = my_follow_page(vma, addr);
		if (!page) {
			printk("page not found for 0x%lx\n", addr);
			goto out;
		}
		kernel_addr = (unsigned long)page_address(page);
		kernel_addr += (addr & ~PAGE_MASK);
		printk("write 0x%lx to address 0x%lx\n", val, kernel_addr);
		*(unsigned long*)kernel_addr = val;
		put_page(page);
	} else {
		printk("no vma found for %lx\n", addr);
	}
out:
	up_read(&mm->mmap_sem);
}

static ssize_t mtest_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
	printk("mtest_write\n");
	char buf[128];
	unsigned long val, val2;
	if (count > sizeof(buf)) return -EINVAL;
	
	if (copy_from_user(buf, buffer, count)) return -EINVAL;
	
	if (memcmp(buf, "listvma", 7) == 0) mtest_dump_vma_list();
	else if (memcmp(buf, "findvma", 7) == 0) {
		if (sscanf(buf + 7, "%lx", &val) == 1) {
			mtest_find_vma(val);
		}
	} else if (memcmp(buf, "findpage", 8) == 0) {
		if (sscanf(buf + 8, "%lx", &val) == 1) {
			mtest_find_page(val);
		}
	} else if (memcmp(buf, "writeval", 8) == 0) {
		if (sscanf(buf + 8, "%lx %lx", &val, &val2) == 2) {
		 	mtest_write_val(val, val2);
		}
	}
	return count;
}

static int mtest_open(struct inode *inode, struct file *file) {
	printk("mtest_open\n");
	return 0;
}

static struct file_operations proc_mtest_operations = {
	.write = mtest_write,
	.open = mtest_open
};

static struct proc_dir_entry *mtest_proc_entry;

static int __init mtest_init(void) {
	mtest_proc_entry = proc_create ("mtest", 0777, NULL, &proc_mtest_operations);
	if (mtest_proc_entry == NULL) {
		printk("Error creating proc entry\n");
		return -1;
	}

	printk("create the filename mtest mtest_nit sucess\n");
	mtest_dump_vma_list();
	return 0;
}

static void __exit mtest_exit(void) {
	printk("exit the module mtest_exit\n");
	proc_remove(mtest_proc_entry);
}

module_init(mtest_init);
module_exit(mtest_exit);

