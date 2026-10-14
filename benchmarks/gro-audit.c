/* Untimed libc mechanism audit only. Never preload into performance runs.
 * Layout: calls[5], successes[5], errors[5], receive entries/datagrams/bytes,
 * send entries/datagrams/bytes, GRO entries. Operations: recvfrom, recvmsg,
 * recvmmsg, sendto, sendmmsg. Shared counters are read after the peer fence. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

static _Atomic uint64_t *stats;
static ssize_t (*next_recvfrom)(int,void*,size_t,int,struct sockaddr*,socklen_t*);
static ssize_t (*next_recvmsg)(int,struct msghdr*,int);
static int (*next_recvmmsg)(int,struct mmsghdr*,unsigned int,int,struct timespec*);
static ssize_t (*next_sendto)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
static int (*next_sendmmsg)(int,struct mmsghdr*,unsigned int,int);

__attribute__((constructor)) static void setup(void) {
    next_recvfrom=dlsym(RTLD_NEXT,"recvfrom");
    next_recvmsg=dlsym(RTLD_NEXT,"recvmsg");
    next_recvmmsg=dlsym(RTLD_NEXT,"recvmmsg");
    next_sendto=dlsym(RTLD_NEXT,"sendto");
    next_sendmmsg=dlsym(RTLD_NEXT,"sendmmsg");
    const char *path=getenv("GRO_AUDIT_COUNTERS");
    if (!path || !next_recvfrom || !next_recvmsg || !next_recvmmsg || !next_sendto || !next_sendmmsg) _exit(91);
    int fd=open(path,O_RDWR|O_CREAT|O_EXCL,0600);
    if(fd<0 || ftruncate(fd,22*sizeof(uint64_t))) _exit(92);
    void *map=mmap(NULL,22*sizeof(uint64_t),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(map==MAP_FAILED) _exit(93);
    close(fd);
    stats=map;
}
static void add(unsigned i,uint64_t n) { atomic_fetch_add_explicit(&stats[i],n,memory_order_relaxed); }
static void status(unsigned op,ssize_t result) { add(op,1); add(op+(result<0?10:5),1); }
static void received(struct msghdr *msg,size_t length) {
    int segment=0;
    if(msg->msg_flags & (MSG_TRUNC|MSG_CTRUNC)) _exit(94);
    for(struct cmsghdr *c=CMSG_FIRSTHDR(msg);c;c=CMSG_NXTHDR(msg,c)) {
        if(c->cmsg_level==IPPROTO_UDP && c->cmsg_type==UDP_GRO) {
            if(c->cmsg_len!=CMSG_LEN(sizeof(int))) _exit(95);
            memcpy(&segment,CMSG_DATA(c),sizeof(segment));
            if(segment<=0 || segment>65535 || !length) _exit(96);
        }
    }
    add(15,1); add(16,segment?(length+segment-1)/segment:1); add(17,length);
    if(segment) add(21,1);
}
ssize_t recvfrom(int fd,void *buf,size_t n,int flags,struct sockaddr *addr,socklen_t *len) {
    ssize_t ret=next_recvfrom(fd,buf,n,flags,addr,len);int saved=errno;
    status(0,ret);
    if(ret>=0) {add(15,1);add(16,1);add(17,ret);}
    errno=saved;return ret;
}
ssize_t recvmsg(int fd,struct msghdr *msg,int flags) {
    ssize_t ret=next_recvmsg(fd,msg,flags);int saved=errno;
    status(1,ret);if(ret>=0)received(msg,ret);
    errno=saved;return ret;
}
int recvmmsg(int fd,struct mmsghdr *msgs,unsigned int count,int flags,struct timespec *timeout) {
    int ret=next_recvmmsg(fd,msgs,count,flags,timeout);int saved=errno;
    status(2,ret);for(int i=0;i<ret;i++)received(&msgs[i].msg_hdr,msgs[i].msg_len);
    errno=saved;return ret;
}
ssize_t sendto(int fd,const void *buf,size_t n,int flags,const struct sockaddr *addr,socklen_t len) {
    ssize_t ret=next_sendto(fd,buf,n,flags,addr,len);int saved=errno;
    status(3,ret);if(ret>=0){add(18,1);add(19,1);add(20,ret);}
    errno=saved;return ret;
}
int sendmmsg(int fd,struct mmsghdr *msgs,unsigned int count,int flags) {
    int ret=next_sendmmsg(fd,msgs,count,flags);int saved=errno;
    status(4,ret);
    for(int i=0;i<ret;i++) {
        uint16_t segment=0;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&msgs[i].msg_hdr);c;c=CMSG_NXTHDR(&msgs[i].msg_hdr,c)) {
            if(c->cmsg_level==IPPROTO_UDP && c->cmsg_type==UDP_SEGMENT) {
                if(c->cmsg_len!=CMSG_LEN(sizeof(segment))) _exit(97);
                memcpy(&segment,CMSG_DATA(c),sizeof(segment));
            }
        }
        unsigned len=msgs[i].msg_len;
        add(18,1);add(19,segment?(len+segment-1)/segment:1);add(20,len);
    }
    errno=saved;return ret;
}
