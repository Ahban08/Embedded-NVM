#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "encryption.h"
#include <openssl/rand.h>

// Define a key and IV (these should be securely generated and stored in a real application)
unsigned char key[32];
unsigned char iv[16];

// Initialize key and IV with random values (for simplicity)
void initialize_crypto() {
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }
}

/*========== Initializing Data Structures ==========*/
//names of directories
char dir_list[ 256 ][ 256 ];
int curr_dir_idx = -1;

// the names of files
char files_list[ 256 ][ 256 ];
int curr_file_idx = -1;

// the contents of the files
char files_content[ 256 ][ 256 ];
int curr_file_content_idx = -1;

// Create the directory
void add_dir( const char *dir_name )
{
	curr_dir_idx++;
	strcpy( dir_list[ curr_dir_idx ], dir_name );
	printf("Directory added: %s\n", dir_name); // for debug
}

// Delete the directory
void remove_dir(const char *dir_name) {
    for (int i = 0; i <= curr_dir_idx; i++) {
        if (strcmp(dir_list[i], dir_name) == 0) {
            for (int j = i; j < curr_dir_idx; j++) {
                strcpy(dir_list[j], dir_list[j + 1]);
            }
            curr_dir_idx--;
            printf("Directory removed: %s\n", dir_name); // for debug
            break;
        }
    }
}

//check if this path is a directory
int is_dir( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
		if ( strcmp( path, dir_list[ curr_idx ] ) == 0 )
			return 1;
	
	return 0;
}

// Create the file
void add_file( const char *filename )
{
	curr_file_idx++;
	strcpy( files_list[ curr_file_idx ], filename );
	
    // [inode] : curr_file_idx = curr_file_content_idx 
	curr_file_content_idx++;
	strcpy( files_content[ curr_file_content_idx ], "" );

	printf("File added: %s\n", filename); // for debug
}

//check if this path is a file
int is_file( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return 1;
	
	return 0;
}

// Get node i
int get_file_index( const char *path )
{
	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return curr_idx;
	
	return -1;
}

// Write the file
static int write_to_file( const char *path, const char *new_content,  size_t size, off_t offset )
{
	int file_idx = get_file_index( path );
	printf("file_idx: %d\n",file_idx); // for debug
	if ( file_idx == -1 ) // No such file
		return -ENOENT;
	
	unsigned char ciphertext[256];
    int ciphertext_len = encrypt((unsigned char *)new_content, size, key, iv, ciphertext);

	// Update the file size if necessary
    // size_t new_size = offset + size;
	size_t new_size = offset + ciphertext_len;
	// Resize the file's content buffer if necessary
    if (new_size >= sizeof(files_content[file_idx])) {
        return -ENOMEM;  // Not enough memory
    }
	
	// Write the data to the file's content buffer
    // strncpy(files_content[file_idx] + offset, new_content, size);
    strncpy(files_content[file_idx] + offset, (char *)ciphertext, ciphertext_len);
    
    if (new_size > strlen(files_content[file_idx]))
        files_content[file_idx][new_size] = '\0';

    printf("Written to file %s: %s\n", path, new_content); // for debug
    printf("Encrypted content: %s\n", ciphertext); // for debug
	return size;
}

/*========== Implementing LSYSFS ==========*/
static int do_getattr( const char *path, struct stat *st )
{
	//  printf("do_getattr called on path: %s\n", path); // for debug

	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now
	
	if ( strcmp( path, "/" ) == 0 || is_dir( path ) == 1 )
	{
		st->st_mode = __S_IFDIR | 0755; // Directory with rwxr-xr-x permissions
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if ( is_file( path ) == 1 )
	{
		st->st_mode = __S_IFREG | 0644; // Regular file 
		// st->st_mode = __S_IFREG | 0666; // Regular file 
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}
	
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi )
{
	// printf("do_readdir called on path: %s\n", path); // for debug

	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory
	
	if ( strcmp( path, "/" ) == 0 ) // If the user is trying to show the files/directories of the root directory show the following
	{
		for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
			filler( buffer, dir_list[ curr_idx ], NULL, 0 );
	
		for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
			filler( buffer, files_list[ curr_idx ], NULL, 0 );
	}
	
	return 0;
}

static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	// printf("do_read called on path: %s\n", path); // for debug

	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 )
		return -1;
	
	unsigned char *content = files_content[ file_idx ];
	printf("Content before decrypted: %s\n", content + offset); // for debug

	unsigned char decrypted_data[256];
	int decrypted_data_len = decrypt(content + offset, strlen(content) - offset, key, iv, decrypted_data);

    //"offset" is the place in the file’s content where we are going to start reading from.
	// memcpy( buffer, content + offset, size );
    memcpy(buffer, decrypted_data + offset, decrypted_data_len);
    printf("Read from file  %s after decrypted: %s\n", path, buffer); // for debug

	// return strlen( content ) - offset;
    return decrypted_data_len;
}

static int do_mkdir( const char *path, mode_t mode )
{
	// printf("do_mkdir called on path: %s\n", path); // for debug

	path++;
	add_dir( path );
	
	return 0;
}

static int do_rmdir(const char *path) {
    // printf("do_rmdir called on path: %s\n", path); // for debug
	printf("Trying to remove directory: %s\n", path); // for debug

    if (is_dir(path)) {
		path++;
        remove_dir(path);
        return 0;
    } else {
        printf("Directory not found: %s\n", path); // for debug
        return -ENOENT;
    }
}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	// printf("do_mknod called on path: %s\n", path); // for debug

	path++;
	add_file( path );
	
	return 0;
}

static int do_write( const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info )
{
	// printf("do_write called on path: %s\n", path); // for debug

	write_to_file( path, buffer, size, offset);
	
	return size;
}

/*========== Implementing utimens ==========
  ========== for touching a new file =======*/
static int do_utimens(const char *path, const struct timespec ts[2])
{
    // printf("do_utimens called on path: %s\n", path); // for debug

    // Check if the path is for a file or directory
    if (is_file(path) == 1 || is_dir(path) == 1)
    {
        // Normally, I would update the times in my file system's metadata here.
        // For simplicity, we are just printing a message.
        printf("Updating times for %s: atime = %ld, mtime = %ld\n",
               path, ts[0].tv_sec, ts[1].tv_sec);
        return 0;
    }
    else
    {
        return -ENOENT;
    }
}

static struct fuse_operations operations = {
    .getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
	.rmdir    	= do_rmdir,
    .mknod		= do_mknod,
    .write		= do_write,
	.utimens    = do_utimens,
};

int main( int argc, char *argv[] )
{
	initialize_crypto();
	printf("Starting LSYSFS...\n");
	return fuse_main( argc, argv, &operations, NULL );
}