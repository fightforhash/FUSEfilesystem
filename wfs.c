#include "wfs.h"
#include <sys/stat.h>
#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

#define MAX_PATH_LEN    1024

static char* mem = NULL;
static struct wfs_sb* root = NULL;

typedef struct {
    const char* list[MAX_PATH_LEN];
    size_t lens[MAX_PATH_LEN];
    size_t list_len;
} path_list_t;

off_t alloc_dblock();
inode_t* alloc_inode();
int free_dblock(off_t);
int free_inode(inode_t*);
inode_t* lookup_path(path_list_t* , size_t , dentry_t**);
dentry_t* find_directory_entry(inode_t*, const char*);

static inline inode_t* get_inode(off_t offset) {
    return (inode_t*)(mem + root->i_blocks_ptr + offset);
}

static inline char* get_dblock(off_t offset){
    return mem + offset;
}

static inline dentry_t* alloc_direntry(inode_t* inode)
{
    dentry_t* curr_entry = NULL;
    dentry_t* bound = NULL;
    size_t block_index = 0;
    size_t block_end = IND_BLOCK;
    int walking_indirect = 0;
    off_t* blocks = inode->blocks;
    while(block_index < block_end){
        if(blocks[block_index] == 0) {
            blocks[block_index] = alloc_dblock();
            if(blocks[block_index] == 0){
                return NULL;
            }
        }

        curr_entry = (dentry_t*)get_dblock(blocks[block_index]);
        bound = (dentry_t*)((char*)curr_entry + BLOCK_SIZE);

        while(curr_entry < bound) {
            if(curr_entry->num == 0){
                return curr_entry;
            }
            curr_entry++;
        }
        block_index++;

        if(block_index == block_end && !walking_indirect){
            walking_indirect = 1;
            block_index = 0;
            if(inode->blocks[IND_BLOCK] == 0){
                inode->blocks[IND_BLOCK] = alloc_dblock();
                if(inode->blocks[IND_BLOCK] == 0)
                {
                    return NULL;
                }
            }
            blocks = (off_t*)get_dblock(inode->blocks[IND_BLOCK]);
            block_end = BLOCK_SIZE/sizeof(off_t);
        }
    }
    return NULL;
}

int free_dblock(off_t offset){
    char* block = get_dblock(offset);
    memset((void*)block, 0, BLOCK_SIZE);
    size_t block_index = (offset - root->d_blocks_ptr)/BLOCK_SIZE;
    size_t bytes = block_index >> 3;
    char* bitmap = mem + root->d_bitmap_ptr + bytes;

    unsigned char actual_bit = 0x1 << (block_index - (bytes << 3));
    *bitmap &= ~actual_bit;
    return 0;
}

int free_inode(inode_t* inode)
{
    size_t bytes = inode->num >> 3;
    char* bitmap = mem + root->i_bitmap_ptr + bytes;
    unsigned char actual_bit = 0x1 << (inode->num - (bytes << 3));
    *bitmap &= ~actual_bit;
    memset((void*)inode, 0, sizeof(inode_t));
    return 0;
}

dentry_t* find_directory_entry(inode_t* inode, const char* name) {
    size_t block_index = 0;
    size_t block_end = IND_BLOCK;
    off_t* blocks = inode->blocks;
    int walking_indirect = 0;
    if(S_ISDIR(inode->mode)){
        while(block_index < block_end)
        {
            if(blocks[block_index]) {
                dentry_t* curr = (dentry_t*)get_dblock(blocks[block_index]);
                dentry_t* end = (dentry_t*)((char*)curr + BLOCK_SIZE);
                while(curr < end){
                    if(!strcmp(name, curr->name) && strlen(name) == strlen(curr->name)){
                        return curr;
                    }
                    curr++;
                }
            }

            block_index++;
            if(block_index == block_end && !walking_indirect && blocks[IND_BLOCK]){
                walking_indirect = 1;
                block_index = 0;
                block_end = BLOCK_SIZE/sizeof(dentry_t);
                blocks = (off_t*)get_dblock(blocks[IND_BLOCK]);
            }
        }
    }

    return NULL;
}

inode_t* alloc_inode() {
    unsigned char* bitmap = (unsigned char*)(mem + root->i_bitmap_ptr);
    size_t max_bytes = root->num_inodes >> 3;
    inode_t* node = NULL;
    size_t bytes = 0;
    size_t inode_index = -1;
    while(bytes < max_bytes){
        unsigned char cur_byte = bitmap[bytes];
        unsigned char byte = cur_byte & 0xFF;
        if(byte != 0xFF) {
            size_t count = 0;
            unsigned char added = 0x1;
            while(added & byte)
            {
                added <<= 1;
                count++;
            }
            inode_index = (bytes << 3) + count;
            bitmap[bytes] |= added; 
            break;
        }   
        bytes++;
    }

    if(inode_index >= 0 && inode_index < root->num_inodes){
        node = get_inode(inode_index*BLOCK_SIZE);
        node->num = inode_index;
    }

    return node;
}

static int delete_file(inode_t* parent_dir, path_list_t* l)
{
    dentry_t* direntry = NULL;
    inode_t* inode = NULL;

    char name[MAX_NAME];
    memset(name, 0, MAX_NAME);

    strncpy(name, l->list[l->list_len-1], l->lens[l->list_len-1]);

    direntry = find_directory_entry(parent_dir, name);
    if(direntry == NULL)
    {
        return -1;
    }

    inode = get_inode(direntry->num*BLOCK_SIZE);


    size_t block_index = 0;
    size_t block_end = IND_BLOCK;
    int walking_indirect = 0;
    dentry_t* curr_direntry = NULL;
    dentry_t* direntry_end = NULL;

    path_list_t temp_list;
    memcpy(&temp_list, l, sizeof(temp_list));

    off_t* blocks = inode->blocks;

    while(block_index < block_end){
        if(blocks[block_index]) {
            char* dblock = get_dblock(blocks[block_index]);
            if(S_ISDIR(inode->mode)) {
                curr_direntry = (dentry_t*)dblock;
                direntry_end = (dentry_t*)((char*)curr_direntry + BLOCK_SIZE);

                while(curr_direntry < direntry_end) {
                    if(curr_direntry->num != 0){
                        temp_list.list[l->list_len] = curr_direntry->name;
                        temp_list.lens[l->list_len] = strlen(curr_direntry->name);
                        temp_list.list_len = l->list_len+1;
                        delete_file(inode, &temp_list);
                        memset((void*)curr_direntry, 0, sizeof(dentry_t));
                    }
                    curr_direntry++;
                }
            }
            //current data block is now not needed.
            free_dblock(blocks[block_index]);
        }

        block_index++;

        if(!walking_indirect && block_index == block_end && inode->blocks[IND_BLOCK]){
            block_index = 0;
            block_end = BLOCK_SIZE/sizeof(off_t);
            blocks = (off_t*)get_dblock(inode->blocks[IND_BLOCK]);
            walking_indirect = 1;
        }
    }

    //clear all blocks
    memset((void*)inode->blocks, 0, sizeof(inode->blocks));
    //clear the directory entry
    memset((void*)direntry, 0, sizeof(direntry));
    free_inode(inode);

    // clear directory entry.
    memset((void*)direntry, 0, sizeof(dentry_t));
    parent_dir->nlinks--;
    parent_dir->size -= sizeof(dentry_t);
    return 0;
}

off_t alloc_dblock(){
    unsigned char* bitmap = (unsigned char*)(mem + root->d_bitmap_ptr);
    size_t max_bytes = root->num_data_blocks >> 3;
    off_t block = 0;
    size_t bytes = 0;
    size_t dblock_index = -1;
    while(bytes < max_bytes){
        unsigned char cur_byte = bitmap[bytes];
        unsigned char byte = cur_byte & 0xFF;
        if(byte != 0xFF) {
            size_t count = 0;
            unsigned char added = 0x1;
            while(added & byte)
            {
                added <<= 1;
                count++;
            }
            dblock_index = (bytes << 3) + count;
            bitmap[bytes] |= added;
            break;
        } 
        bytes++;  
    }

    if(dblock_index >= 0 && dblock_index < root->num_data_blocks){
        block = root->d_blocks_ptr + dblock_index*BLOCK_SIZE;
    }

    return block;
}

static inline void get_stats(inode_t* inode, struct stat* stats)
{
    memset((void*)stats, 0, sizeof(stats));
    stats->st_atime = inode->atim;
    stats->st_ctime = inode->ctim;
    stats->st_mode = inode->mode;
    stats->st_uid = inode->uid;
    stats->st_gid = inode->gid;
    stats->st_mtime = inode->mtim;
    stats->st_blksize = BLOCK_SIZE;
    stats->st_size = inode->size;
    stats->st_nlink = inode->nlinks;
}

path_list_t get_path_list(const char* path){
    path_list_t l;
    memset((void*)&l, 0, sizeof(l));
    if(*path != '/'){
        return l;
    };
    l.lens[0] = 1;
    l.list[0] = path;
    const char* curr_path = &path[1];
    const char* cursor = curr_path;
    const char* path_end = path + strlen(path);
    size_t list_len = 1;
    while(cursor <= path_end){
        while(curr_path < path_end && *curr_path == '/'){
            curr_path++;
            cursor++;
        }
        if(cursor <= path_end && curr_path < path_end){
            if(*cursor == '/' || cursor == path_end)
            {
                l.list[list_len] = curr_path;
                l.lens[list_len] = cursor - curr_path;
                list_len++;
                curr_path = cursor;
                curr_path++;
            }
        }

        cursor++;
    }

    l.list_len = list_len;

    return l;
}

inode_t* lookup_path(path_list_t* l, size_t lookup_depth, dentry_t** direntry)
{
    if(lookup_depth == 0 || lookup_depth > MAX_PATH_LEN)
    {
        return NULL;
    }
    //get the root node
    inode_t* current_inode = (inode_t*)(mem + root->i_blocks_ptr);
    dentry_t* current_folder = (dentry_t*)(get_dblock(current_inode->blocks[0]));
    char name[MAX_NAME];
    
    size_t list_index = 1;
    while(list_index < lookup_depth) {
        memset(name, 0, MAX_NAME);
        strncpy(name, l->list[list_index], l->lens[list_index]);
        dentry_t* dir_ent = find_directory_entry(current_inode, name);
        if(!dir_ent) {
            return NULL;
        }

        current_inode = get_inode(dir_ent->num*BLOCK_SIZE);
        current_folder = dir_ent;
        list_index++;
    }

    *direntry = current_folder;
    return current_inode;
}

static int wfs_getattr(const char* path, struct stat* res)
{
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* inode = lookup_path(&l, l.list_len, &direntry);
    if(inode == NULL){
        return -ENOENT;
    }
    get_stats(inode, res);
    return 0;
}

static int wfs_mknod(const char* path, mode_t mode, dev_t dev)
{
    path_list_t l = get_path_list(path);
    dentry_t* dirent = NULL;
    inode_t* parent_inode = lookup_path(&l, l.list_len-1, &dirent);
    inode_t* inode = NULL;

    if(parent_inode == NULL){
        return -ENOENT;
    }
    mode |= __S_IFREG;

    inode = lookup_path(&l, l.list_len, &dirent);
    if(inode != NULL)
    {
        return -EEXIST;
    }

    if(!S_ISDIR(parent_inode->mode))
    {
        return -ENOTDIR;
    }

    char name[MAX_NAME];
    memset((void*)name, 0, MAX_NAME);
    strncpy(name, l.list[l.list_len-1], l.lens[l.list_len-1]);

    dirent = alloc_direntry(parent_inode);
    if(dirent == NULL) {
        return -ENOSPC;
    }
    inode = alloc_inode();
    if(inode == NULL){
        return -ENOSPC;
    }
    dirent->num = inode->num;
    memcpy(dirent->name, name, MAX_NAME);

    inode->mode = mode | __S_IFREG;
    inode->uid = getuid();
    inode->gid = getgid();
    inode->size = 0;
    inode->nlinks = 1;
    parent_inode->size += sizeof(dentry_t);
    parent_inode->nlinks++;
    
    return 0;
}

static int wfs_mkdir(const char* path, mode_t mode)
{

    mode |= __S_IFDIR;
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* parent_inode = lookup_path(&l, l.list_len-1, &direntry);
    if(parent_inode == NULL || !S_ISDIR(parent_inode->mode)){
        return -ENOENT;
    }

    direntry = NULL;
    inode_t* inode = lookup_path(&l, l.list_len, &direntry);
    if(inode != NULL){
        printf("inode: %p dentry:%p\n", (void*)inode, (void*)direntry);
        return -EEXIST;
    }

    dentry_t* dir_entry = alloc_direntry(parent_inode);
    if(dir_entry == NULL){
        return -ENOSPC;
    }

    strncpy(dir_entry->name, l.list[l.list_len-1], l.lens[l.list_len-1]);
    inode = alloc_inode();
    if(inode == NULL){
        memset((void*)dir_entry, 0, sizeof(dentry_t));
        return -ENOSPC;
    }

    // off_t dblock = alloc_dblock();
    // if(dblock == 0){
    //     //TODO: free inode and direntry
    // }

    // inode->blocks[0] = dblock;
    dir_entry->num = inode->num;

    inode->size = sizeof(dentry_t);
    inode->uid = getuid();
    inode->gid = getgid();
    inode->nlinks = 2;
    inode->mode = mode;

    parent_inode->size += sizeof(dentry_t);
    parent_inode->nlinks++;
    
    return 0;
}

static int wfs_unlink(const char* path)
{
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* parent_inode = NULL;
    parent_inode = lookup_path(&l, l.list_len-1, &direntry);
    if(parent_inode == NULL){
        return -ENOENT;
    }

    inode_t* inode = NULL;
    inode = lookup_path(&l, l.list_len, &direntry);
    if(inode == NULL)
    {
        return -ENOENT;
    }

    delete_file(parent_inode, &l);
    return 0;
}

static int wfs_rmdir(const char* path)
{
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* parent_inode = NULL;
    parent_inode = lookup_path(&l, l.list_len-1, &direntry);
    if(parent_inode == NULL){
        return -ENOENT;
    }

    direntry = NULL;
    inode_t* inode = NULL;
    inode = lookup_path(&l, l.list_len, &direntry);
    if(inode == NULL){
        return -ENOENT;
    }

    if(!S_ISDIR(inode->mode)){
        return -EINVAL;
    }

    delete_file(parent_inode, &l);

    return 0;
}

static int wfs_read(const char* path, char *buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* inode = lookup_path(&l, l.list_len, &direntry);

    if(inode == NULL){
        return -ENOENT;
    }

    if(!(inode->mode & S_IRUSR)){
        return -EACCES;
    }

    if(offset > inode->size || size == 0){
        return 0;
    }


    off_t start_block = offset/BLOCK_SIZE;
    off_t start_byte = offset - (start_block*BLOCK_SIZE);
    size_t block_index = start_block;

    size_t end_block = ((size + offset + BLOCK_SIZE-1) & ~(BLOCK_SIZE-1))/BLOCK_SIZE;
    size_t blocks_to_read = end_block - start_block;
    size_t block_end = IND_BLOCK;

    off_t* blocks = inode->blocks;
    
    int walking_indirect = 0;
    size_t read_bytes = 0;
    size_t blocks_read = 0;

    while(blocks_read < blocks_to_read) {
        if(block_index < block_end) {
            if(blocks[block_index]) {
                char* mem = get_dblock(blocks[block_index]);
                char* mem_end = mem+BLOCK_SIZE;
                if(start_block == block_index){
                    mem = &mem[start_byte];
                }
                while(read_bytes < size && read_bytes < inode->size) {
                    if(mem == mem_end){
                        //we are done with this block.
                        break;
                    }
                    buf[read_bytes] = *mem;
                    mem++;
                    read_bytes++;
                }
            }else{
                break;
            }

        }else if(!walking_indirect){
            if(blocks[IND_BLOCK]){
                blocks = (off_t*)get_dblock(blocks[IND_BLOCK]);
                block_index = 0;
                block_end = BLOCK_SIZE/sizeof(off_t);
                walking_indirect = 1;
                continue;
            }else{
                break;
            }
        }
        blocks_read++;
        block_index++;
    }
    return read_bytes;
}

static int wfs_write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* inode = lookup_path(&l, l.list_len, &direntry);

    if(inode == NULL){
        return -ENOENT;
    }

    if(!(inode->mode & S_IWUSR)){
        return -EACCES;
    }

    off_t start_block = offset/BLOCK_SIZE;
    off_t start_byte = offset - (start_block*BLOCK_SIZE);
    size_t block_index = start_block;

    size_t end_block = ((size + offset + BLOCK_SIZE-1) & ~(BLOCK_SIZE-1))/BLOCK_SIZE;
    size_t blocks_to_write = end_block - start_block;
    size_t block_end = IND_BLOCK;

    off_t* blocks = inode->blocks;
    
    int walking_indirect = 0;
    size_t written_bytes = 0;
    size_t blocks_written = 0;

    while(blocks_written < blocks_to_write) {
        if(block_index < block_end) {
            if(blocks[block_index]) {
                char* mem = get_dblock(blocks[block_index]);
                char* mem_end = mem+BLOCK_SIZE;
                if(start_block == block_index){
                    mem = &mem[start_byte];
                }
                while(written_bytes < size) {
                    if(mem == mem_end){
                        //we are done with this block.
                        break;
                    }
                    *mem = buf[written_bytes];
                    mem++;
                    written_bytes++;
                }
            }else{
                blocks[block_index] = alloc_dblock();
                if(!blocks[block_index]) {
                    return -ENOSPC;
                }
                continue;
            }

        }else if(!walking_indirect){
            if(blocks[IND_BLOCK]){
                blocks = (off_t*)get_dblock(blocks[IND_BLOCK]);
                block_index = start_block < IND_BLOCK? 0: start_block - IND_BLOCK;
                block_end = BLOCK_SIZE/sizeof(off_t);
                walking_indirect = 1;
                continue;
            }else{
                blocks[IND_BLOCK] = alloc_dblock();
                if(!blocks[IND_BLOCK]){
                    return -ENOSPC;
                }
                continue;
            }
        }
        block_index++;
        blocks_written++;
    }
    inode->size += written_bytes;
    return written_bytes;
}

static int wfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
    filler(buf, ".", NULL, 0);
    filler(buf,"..",NULL, 0);
    path_list_t l = get_path_list(path);
    dentry_t* direntry = NULL;
    inode_t* inode = lookup_path(&l, l.list_len, &direntry);

    printf("Looking\n");
    if(inode == NULL){
        printf("No path: %s\n", path);
        return -ENOENT;
    }

    printf("Inode mode: %s %u\n", path, inode->mode);
    if(!(inode->mode & __S_IFDIR)){
        return -ENOTDIR;
    }
    size_t block_index = 0;
    size_t block_end = IND_BLOCK;
    dentry_t* dirend = NULL;
    off_t* blocks = inode->blocks;
    int walking_indirect = 0;
    struct stat stats;

    while(block_index < block_end) {
        if(blocks[block_index]) {
            direntry = (dentry_t*)get_dblock(blocks[block_index]);
            dirend = (dentry_t*)((char*)direntry + BLOCK_SIZE);
            while(direntry < dirend){
                if(direntry->num != 0){
                    inode = get_inode(direntry->num*BLOCK_SIZE);
                    if(inode == NULL){
                        //fatal!
                        fprintf(stderr, "wfs_readdir(): NULL inode but dir has num\n");
                        break;
                    }
                    get_stats(inode, &stats);
                    filler(buf, direntry->name, &stats, 0);
                }
                direntry++;
            }
        }

        block_index++;
        if(block_index == block_end && !walking_indirect && blocks[block_index]){
            blocks = (off_t*)get_dblock(blocks[block_index]);
            block_index = 0;
            block_end = BLOCK_SIZE/sizeof(off_t);
        }
    }

    return 0;
}


static struct fuse_operations ops = {
  .getattr = wfs_getattr,
  .mknod   = wfs_mknod,
  .mkdir   = wfs_mkdir,
  .unlink  = wfs_unlink,
  .rmdir   = wfs_rmdir,
  .read    = wfs_read,
  .write   = wfs_write,
  .readdir = wfs_readdir,
};

void usage()
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "./wfs disk_path [FUSE options] mount_point\n");
    exit(-1);
}

int main(int argc, char** argv){
    
    if(argc < 4)
    {
        usage();
    }

    int fd = open(argv[1], O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if(fd < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        usage();
    }

    struct wfs_sb block;
    if(read(fd, (void*)&block, sizeof(struct wfs_sb)) != sizeof(struct wfs_sb)){
        fprintf(stderr, "error reading super block\n");
        fprintf(stderr, "please initialize disk image before running wfs\n");
        close(fd);
        exit(-1);
    }

    size_t disk_size = block.num_data_blocks * BLOCK_SIZE + 
                       block.num_inodes * BLOCK_SIZE + 
                       sizeof(super_block_t) + 
                       (block.num_inodes <<3) + 
                       (block.num_data_blocks << 3);
    if(disk_size == 0 || disk_size < MIN_DISK_SIZE)
    {
        fprintf(stderr, "low disk size, required = %u, given = %lu\n", MIN_DISK_SIZE, disk_size);
        close(fd);
        exit(-1);
    }

    void* map = mmap(NULL, disk_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(map == MAP_FAILED){
        fprintf(stderr, "unable to map disk to memory\n");
        close(fd);
        exit(-1);
    }

    root = (struct wfs_sb*)map;
    mem = (char*)map;
    fuse_main(argc-2, &argv[2], &ops, NULL);
}