This project demonstrates my implementation of a FUSE-based filesystem.  
It was heavily inspired by the [CS537 Spring 2024 Project 7 instructions](https://git.doit.wisc.edu/cdis/cs/courses/cs537/spring24/public/p7/-/blob/main/instructions/instructions.md?ref_type=heads).

Below is the set of FUSE callbacks I implemented:

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

The file system is designed as a tree where folders are nodes with children, while files are leaves.
Each file and folder has an inode to store information about it.
This information includes size, permissions, file type etc.

Each file and folder holds data blocks. Data blocks of files hold file data, while those of directories hold directory entry information.

Functions:
getattr():
this function returns attributes of a file.
Time attributes are not set.
permissions, file type, size, links are set based on the attributes of the file.

mknod():
This function is used for creating a new file.
If enough space is available on the disk, a new inode is allocated for the file,
and a directory entry storing its name and inode index, is allocated in the parent folder.
The initial file size is 0, while the size of the parent folder is incremented to the size of a directory entry.
If the file exists, then an error is returned.

mkdir():
This is similar to mknod(), only that it is used to create a new directory.
The difference from mknod() is here the file type is set to directory. 

unlink():
This function is used to delete a file.
If the file path exists, the file is deleted, and all its data blocks are freed. Its inode is freed and its directory entry is removed from the parent directory.
If the file does not exist, an error is returned.

rmdir():
This is similar to unlink(), only that it applies to directories.
The mode of the inode is checked to ensure this is a folder.
Although our implementation recursively deletes directory contents, upon inspection, we found that the system already does this by default.
All the directory entries are cleared out and data blocks used freed.

read(), write():
These functions are used to read from and write to a file. The function checks whether the file exists, and that is is readable/writable and if not, an error is returned.
When reading, we make sure to not go beyond the file size.
When writing, we can write as long as the disk space is still available.
It was a challenging and interesting experience to deal with read/write routines spanning multiple blocks.

readdir():
For this function, the directory contents are printed. 
We also ensure that "." and ".." are included.
filter argument was used to return this information.


Making the file system (The disk)
We design the disk to match the tests given as shown below
          d_bitmap_ptr       d_blocks_ptr
               v                  v
+----+---------+---------+--------+--------------------------+
| SB | IBITMAP | DBITMAP | INODES |       DATA BLOCKS        |
+----+---------+---------+--------+--------------------------+
0    ^                   ^
i_bitmap_ptr        i_blocks_ptr

Each inode = 512 bytes, althougn an actual inode doesn't require that much space.
The bitmaps are used to keep track of allocated and free blocks/inodes.
An allocated block/inode has is corresponding index bit set to 1 and 0 otherwise.
The super block corresponds to the disk information.


Discusion and Conclusion:
The file system was tested through the terminal using the provided test cases in CS537 Spring 2024 P7.
Interestingly, sometimes unmounting the disk fails because it is still busy. This happened often when running the provided tests.
The subsequent test complains about the mount directory being unempty and it usual fails. Thus, we modify the test file to try unmounting several times as long as the disk is still mounted.





