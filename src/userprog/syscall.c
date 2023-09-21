#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

void halt (void); //done
void exit (int exit_status); //done
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);//done
bool remove (const char *file); //done
int open (const char *file);//done
int filesize (int fd);//done
int read (int fd, void *buffer, unsigned size);//done
int write (int fd, const void *buffer, unsigned size);//done
void seek (int fd, unsigned position);//done
unsigned tell (int fd); //done
void close (int fd);//done

void *validate_address (const void *ptr);

void check_buffer (void *buff_to_check, unsigned size);

struct file_descriptor_container
{
    struct list_elem file_elem;
    struct file *file_addr;
    int file_descriptor;
};

static void syscall_handler (struct intr_frame *);

struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  const void * esp = f->esp;

  validate_address(esp);//check if the address is valid

  int args[3]; //to use when getting process arguments from stack

  //printf("syscall No = %p\n",(int *)esp);
  int syscallNO = *(int *)(esp);
  //printf("syscall No = %d\n",syscallNO);
  switch (syscallNO)
  {
    case SYS_HALT://
      halt();
      break;
    
    case SYS_EXIT:
      get_thread_args(f,args,1);
      exit(args[0]);
      break;

    case SYS_EXEC:
    {
      get_thread_args(f,args,1);
      void* phy_addr = validate_address(args[0]);
      validate_address(args[0]+1);

      f->eax = exec((const char *) phy_addr);
      break; 
    }
    
    case SYS_WAIT:

      get_thread_args(f, &args[0], 1);

      //return the status to the caller
      int temp = wait((pid_t) args[0]);
      //printf("%d\n",temp);
      f->eax = temp;
  
      break;
    
    case SYS_CREATE:
    {
      //get the name and size of the file
      get_thread_args(f, &args[0], 2);
      check_buffer((void *)args[0], args[1]);

      //validate the address
      void *phys_page_ptr = validate_address((const void *) args[0]);
  
      args[0] = (int) phys_page_ptr;

      // return the result
      f->eax = create((const char *) args[0], (unsigned) args[1]);
				
      break;
    }
    case SYS_REMOVE:
    {
        // get the file name
        get_thread_args(f, &args[0], 1);

        //validate address
        void *phys_page_ptr = validate_address((const void *) args[0]);
      
        args[0] = (int) phys_page_ptr;

        /* Return the result of the remove() function in the eax register. */
        f->eax = remove((const char *) args[0]);
      
      break;
    }
    
    case SYS_OPEN:
    {
      //get the name of the file
      get_thread_args(f, &args[0], 1);

      //validate address
      void* phys_page_ptr = validate_address((const void *) args[0]);
  
      args[0] = (int) phys_page_ptr;

      //return the value
      f->eax = open((const char *) args[0]);

      break;
    }
    
    case SYS_FILESIZE:
    {
      //get the fd
      get_thread_args(f, &args[0], 1);

      //validate_address((const void *) args[0]);
      //return the size
      f->eax = filesize(args[0]); 
      break;
    }
      
    
    case SYS_READ:
      {
        //get fd, buffer, length
        get_thread_args(f, &args[0], 3);

        //validate buffer
        check_buffer((void *)args[1], args[2]);

        //validate the address
        void * phys_page_ptr = validate_address((const void *) args[1]);
      
        args[1] = (int) phys_page_ptr;

        /* Return the result of the read() function in the eax register. */
        f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
				break;
        }
    
    case SYS_WRITE:
    {
      get_thread_args(f, &args[0], 3);

      // validate buffer
      check_buffer((void *)args[1], args[2]);

      // validate address
      void *phy_addr = validate_address((const void *) args[1]);
     
      args[1] = (int) phy_addr;

      //return the value
      f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
    
      break;
    }
    
    case SYS_SEEK:
      { 
        //get fd and position
        get_thread_args(f, &args[0], 2);

        seek(args[0], (unsigned) args[1]);
        break;
      }
    
    case SYS_TELL:
    {   // get fd
        get_thread_args(f, &args[0], 1);

        // return the next byte
        f->eax = tell(args[0]);
        break;
      }
    
    case SYS_CLOSE:
    { 
      //get fd
      get_thread_args(f, &args[0], 1);

      //close the file
      close(args[0]);
      break;
      }
  
    default:
      break;
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit (int status)
{
  struct thread *cur = thread_current ();
	cur->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  lock_acquire(&filesys_lock);  
  //create a new child process
	pid_t thread_id_of_child = process_execute(cmd_line);
  lock_release(&filesys_lock);
	return thread_id_of_child;
  
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  //create a file using the file system
  bool status = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return status;
}

bool remove(const char * file)
{
  lock_acquire(&filesys_lock);

  bool status = filesys_remove(file);
  lock_release(&filesys_lock);

  return status;
}

int open(const char *file)
{
  // acquire the lock to prevent multiple access.
  lock_acquire(&filesys_lock);

  //open the file under the given name
  struct file* file_opened = filesys_open(file);

  //if file does not exist
  if(file_opened == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  
  struct file_descriptor_container *new_container = malloc(sizeof(struct file_descriptor_container));

  int cur_fd = thread_current ()->next_file_discriptor;
  thread_current ()->next_file_discriptor++;

  //initialize the container
  new_container->file_addr = file_opened;
  new_container->file_descriptor = cur_fd;

  //track the new file using the list.
  list_push_front(&thread_current ()->file_descriptors, &new_container->file_elem);

  lock_release(&filesys_lock);
  return cur_fd;
}

int filesize (int fd)
{
  lock_acquire(&filesys_lock);

  // if no files are opened, return
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return -1;
  }

  struct list_elem *temp;

  // search for the file
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct file_descriptor_container *container = list_entry (temp, struct file_descriptor_container, file_elem);
      if (container->file_descriptor == fd)
      {
        lock_release(&filesys_lock);
        return (int) file_length(container->file_addr);
      }
  }

  lock_release(&filesys_lock);

  //if file can't be read
  return -1;
}

int read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);
  // for keyboard inputs
  if (fd == 0)
  {
    lock_release(&filesys_lock);
    return (int) input_getc();
  }

  struct list_elem *temp;

  // if fd belongs to std. out or no files are opened return
  if (fd == 1 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return 0;
  }

  // search for the file in file discriptors list
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct file_descriptor_container *t = list_entry (temp, struct file_descriptor_container, file_elem);
      if (t->file_descriptor == fd)
      {
        lock_release(&filesys_lock);

        //read data and return
        return (int) file_read(t->file_addr, buffer, size);;
      }
  }

  lock_release(&filesys_lock);

  //return if file is unreadable
  return -1;
}

int write (int fd, const void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);

  // for std. out (need to check this first as threads without files should be able to write to stdout)
	if(fd == 1)
	{
		putbuf(buffer, size); // write to std. out
    lock_release(&filesys_lock);
    return size;
	}

  // for std. in  or no file is opened
  if (fd == 0 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return 0;
  }

  struct list_elem *temp;
  // search for the file
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct file_descriptor_container *container = list_entry (temp, struct file_descriptor_container, file_elem);
      if (container->file_descriptor == fd)
      {
        // if the file is found write to it
        int no_of_bytes = (int)file_write(container->file_addr, buffer, size);

        lock_release(&filesys_lock);
        return no_of_bytes;
      }
  }

  lock_release(&filesys_lock);

  // if unable to write to the file
  return -1;
}

void seek (int fd, unsigned position)
{
  lock_acquire(&filesys_lock);

  // if no files are opened
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return;
  }

  struct list_elem *temp;

  // search for the file
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct file_descriptor_container *t = list_entry (temp, struct file_descriptor_container, file_elem);
      if (t->file_descriptor == fd)
      {
        // if the file is found
        file_seek(t->file_addr, position);
        lock_release(&filesys_lock);
        return;
      }
  }

  lock_release(&filesys_lock);

  /* If we can't seek, return. */
  return;
}

unsigned tell (int fd)
{
  lock_acquire(&filesys_lock);

  // if no file is opened
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return -1;
  }

  struct list_elem *temp;

  //search for the file
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct file_descriptor_container *container = list_entry (temp, struct file_descriptor_container, file_elem);
      if (container->file_descriptor == fd)
      {
        // if the file is found then find the next_pos to be written or read
        unsigned next_pos = (unsigned) file_tell(container->file_addr);

        lock_release(&filesys_lock);
        return next_pos;
      }
  }

  lock_release(&filesys_lock);
  //if the file is not found
  return -1;
}

void close (int fd)
{
  lock_acquire(&filesys_lock);

  // check if any file is open by cur. thread
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&filesys_lock);
    return;
  }

  struct list_elem *f_elem;
  //search in the file_descriptor list to extract the relavant file
  for (f_elem = list_front(&thread_current()->file_descriptors); f_elem != NULL; f_elem = list_next(f_elem))
  {
      struct file_descriptor_container *container = list_entry(f_elem, struct file_descriptor_container, file_elem);
      if (container->file_descriptor == fd)
      {
        //if the file is found close it return
        file_close(container->file_addr);
        list_remove(&container->file_elem);

        break;
      }
  }

  lock_release(&filesys_lock);

  return;
}
void *validate_address (const void *virtual_address)
{
  //check if the given pointer is within the user address space
  if(virtual_address == NULL || !is_user_vaddr(virtual_address) || virtual_address < (void *) 0x08048000 ) //||virtual_address == (void *)0x804efff
	{
    //if ptr is invalid syscall exit() to exit user program
    exit(-1);
    return 0;
	}

  void *phy_page_addr = (void *) pagedir_get_page(thread_current()->pagedir, virtual_address);

  //exit if the virtual address is unmapped

  if (phy_page_addr == NULL)
  {
    exit(-1);
    return 0;
  }
  //printf("validated - %p to %p\n",virtual_address,phy_page_addr);
  return phy_page_addr;
}

//this function is to get arguments from interrupt frame
void get_thread_args (struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      validate_address((const void *) ptr);
      args[i] = *ptr;
    }
}

void check_buffer (void *buff_to_check, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff_to_check;
  for (i = 0; i < size; i++)
    {
      validate_address((const void *) ptr);
      ptr++;
    }
}