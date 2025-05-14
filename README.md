# FUSE-based File System Implementation

This project demonstrates my implementation of a FUSE-based filesystem.  
It was heavily inspired by the [CS537 Spring 2024 Project 7 instructions](https://git.doit.wisc.edu/cdis/cs/courses/cs537/spring24/public/p7/-/blob/main/instructions/instructions.md?ref_type=heads).

## Implemented FUSE Callbacks

```c
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
```

## File System Design

The file system is designed as a tree structure where folders are nodes that can have children and files are leaf nodes. Each file and folder has an inode that stores information such as size, permissions, and file type. Both files and folders hold data blocks, where file data blocks store file content and directory data blocks store directory entry information.

## Core Functions

### getattr()
This function returns file attributes. While time attributes are not set, it handles permissions, file type, size, and links based on file attributes.

### mknod()
This function creates a new file. When sufficient disk space is available, it allocates a new inode for the file and creates a directory entry in the parent folder storing the filename and inode index. The initial file size is set to 0, and the parent folder size increases by the directory entry size. If the file already exists, it returns an error.

### mkdir()
This function is similar to mknod() but is used for directory creation. The main difference is that the file type is set to directory.

### unlink()
This function handles file deletion. When a file path exists, it deletes the file, frees all data blocks, frees the inode, and removes the directory entry from the parent directory. If the file doesn't exist, it returns an error.

### rmdir()
This function is similar to unlink() but handles directory deletion. It verifies the inode mode to ensure it's a folder, recursively deletes directory contents, and clears all directory entries while freeing data blocks.

### read(), write()
These functions handle file reading and writing operations. They verify file existence and read/write permissions. The read operation ensures it doesn't exceed the file size, while write operations continue as long as disk space is available. The implementation handles read/write operations that span multiple blocks.

### readdir()
This function prints directory contents, including "." and ".." entries, and uses a filter argument to return information.

## Disk Structure

```
          d_bitmap_ptr       d_blocks_ptr
               v                  v
+----+---------+---------+--------+--------------------------+
| SB | IBITMAP | DBITMAP | INODES |       DATA BLOCKS       |
+----+---------+---------+--------+--------------------------+
0    ^                   ^
i_bitmap_ptr        i_blocks_ptr
```

Each inode occupies 512 bytes, which is larger than actually needed. The system uses bitmaps to track allocated and free blocks/inodes, where an allocated block/inode has its corresponding index bit set to 1, and a free block/inode has it set to 0. The super block stores disk information.

## Testing and Conclusion

The file system has been verified using CS537 Spring 2024 P7 test cases. During testing, we encountered some known issues: unmounting can fail when the disk is still busy, and the mount directory may show "not empty" errors. To address these issues, we modified the test file to attempt unmounting multiple times while the disk is mounted.





