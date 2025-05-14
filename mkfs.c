#define FUSE_USE_VERSION 30
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/mman.h>

#include "wfs.h"



void usage(){
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "./mkfs -d <dsk_img> -i <inode_num> -b <block_num>\n");
    fprintf(stderr, "-d\t the disk image\n");
    fprintf(stderr, "-i\t the number of inodes\n");
    fprintf(stderr, "-b\t the number of data blocks\n");
    fprintf(stderr, "-h\t help\n");
    exit(-1);
}

super_block_t* init_super_block(char* mem, unsigned long int nblocks, unsigned long int ninodes)
{
    memset((void*)mem, 0, BLOCK_SIZE);
    super_block_t* block = (super_block_t*)mem;

    memset((void*)block, 0, sizeof(super_block_t));

    size_t inode_size = ninodes * BLOCK_SIZE;
    inode_size = (inode_size + BLOCK_SIZE-1) & ~(BLOCK_SIZE-1);
    
    block->num_data_blocks = nblocks;
    block->num_inodes = ninodes;
    block->i_bitmap_ptr = (off_t)(sizeof(super_block_t));
    block->d_bitmap_ptr = (off_t)(block->i_bitmap_ptr + (ninodes >> 3));
    block->i_blocks_ptr = (off_t)(block->d_bitmap_ptr + (nblocks >> 3));
    block->d_blocks_ptr = (off_t)(block->i_blocks_ptr + inode_size);

    inode_t* sp_inode = (inode_t*)(mem + block->i_blocks_ptr);
    memset((void*)sp_inode, 0, sizeof(inode_t));
    sp_inode->mode = __S_IFDIR | 0x1C0;
    sp_inode->num = 0;
    sp_inode->uid = getuid();
    sp_inode->gid = getgid();
    sp_inode->size = 0;
    sp_inode->nlinks = 2;
    sp_inode->atim = sp_inode->mtim = sp_inode->ctim = 0;

    //root directory
    // dentry_t* root_entry = (dentry_t*)(mem + block->d_blocks_ptr);
    // memset((void*)root_entry, 0, sizeof(dentry_t));
    // strcpy(root_entry->name,"/");
    return block;
}

int init_inode_bitmap(char* mem, super_block_t* sb) {
    char* bitmap = mem + sb->i_bitmap_ptr;
    size_t num_set_bytes = sb->num_inodes >> 3; //number of bits to set.
    //clear everything out.
    memset((void*)bitmap, 0, num_set_bytes);

    *bitmap = 0x1; //the first inode is taken => corresponds to root.
    
    return 0;
}

int init_data_bitmap(char* mem, super_block_t* sb){
    char* bitmap =mem + sb->d_bitmap_ptr;
    size_t num_set_bytes = sb->num_data_blocks >> 3;

    memset((void*)bitmap, 0, num_set_bytes);

    return 0;
}


int main(int argc, char** argv){
    if(argc < 4) {
        usage();
    }

    int opt;
    char* disk_img = NULL;
    int inode_num = 0;
    int block_num = 0;

    int fd = -1;
    while((opt = getopt(argc, argv, ":d:i:b:h")) != -1){
        switch (opt)
        {
        case 'd':
            disk_img = optarg;
            break;

        case 'b':
            block_num = atoi(optarg);
            break;

        case 'i':
            inode_num = atoi(optarg);
            break;
        
        default:
            usage();
            break;
        }
    }

    if(block_num == 0 || inode_num == 0 || disk_img == NULL){
        usage();
    }

    // round block num by 32.
    block_num = (block_num + DATA_BLOCK_MASK) & ~DATA_BLOCK_MASK;
    inode_num = (inode_num + DATA_BLOCK_MASK) & ~DATA_BLOCK_MASK;

    if((fd = open(disk_img, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        usage();
    }

    struct stat df_stat;
    if(fstat(fd, &df_stat))
    {
        fprintf(stderr, "%s\n", strerror(errno));
        close(fd);
        usage();
    }

    if((df_stat.st_mode & __S_IFMT) == __S_IFBLK) {
        unsigned long int block_size = 0;
        if(ioctl(fd, BLKGETSIZE64, &block_size))
        {
            fprintf(stderr, "%s\n", strerror(errno));
            close(fd);
            usage();
        }
        df_stat.st_size = block_size;
    }

    unsigned long int required_size = 
        block_num * BLOCK_SIZE // data blocks
         + inode_num*BLOCK_SIZE // inode blocks
          + sizeof(super_block_t) // super blocks
           + (inode_num << 3) // inode bitmap
            + (block_num << 3); // data block bitmap
    if(df_stat.st_size <= required_size)
    {
        fprintf(stderr, "error: not enough space\n");
        close(fd);
        usage();
    }

    void* mem = mmap(NULL, required_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(mem == MAP_FAILED){
        fprintf(stderr, "unable to map disk image to memory\n");
        close(fd);
        exit(-1);
    }

    memset(mem, 0, required_size);

    super_block_t* sb = init_super_block((char*)mem, block_num, inode_num);

    if(sb == NULL)
    {
        perror("init_super_block()");
        close(fd);
        return -1;
    }

    if(init_inode_bitmap((char*)mem, sb) < -1)
    {
        perror("init_inode_bitmap()");
        close(fd);
        return -1;
    }

    if(init_data_bitmap((char*)mem, sb) < -1)
    {
        perror("init_data_bitmap()");
        close(fd);
        return -1;
    }

    return 0;
}