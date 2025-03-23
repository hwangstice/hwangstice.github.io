---
title: "Protostar - Net"
description: "Writeup for Protostar Net"
pubDate: "March 23 2025"
image: /image/blog-cover/net.jpg
categories:
  - tech
tags:
  - Pwnable
  - Reverse
  - Wargame
---

You can solve all the Protostar Net challenges just by reading the source code, but where's the fun in that? I wanted to really get it, so I went ahead and reversed the game myself. And when everything finally made sense, it was such a cool feeling!

## Net 0

Description:

>This level takes a look at converting strings to little endian integers.<br>
>This level is at /opt/protostar/bin/net0

Source code:

```c
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run()
{
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
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

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

### Analysis

By reading the comments in `main()`, you can easily understand that it is running a process as **daemon**, and setting up the **socket communication** between Client and Server. However, the functions `background_process()`, `serve_forever()`, and `set_io()` don’t exist in standard libraries:

```shell
user@protostar:~$ man background_process
No manual entry for background_process
user@protostar:~$ man serve_forever
No manual entry for serve_forever
user@protostar:~$ man set_io
No manual entry for set_io
```

So where are they coming from?

Most likely from `../common/common.c`, which seems to have a bunch of useful functions for setting up the environment. 

Let's run the program to see what's happen:

```shell
user@protostar:/opt/protostar/bin$ ./net0
user@protostar:/opt/protostar/bin$ ps aux | grep net0
999       1390  0.0  0.0   1532   272 ?        Ss   22:04   0:00 /opt/protostar/bin/net0
user      1605  0.0  0.0   3300   736 pts/0    S+   22:23   0:00 grep net0
```

Nothing happens here, but it appears to be **running in the background**. 

Time to investigate further with `strace`:

![strace-find-proof](public/image/protostar-net/strace-find-proof.png)

Running `strace` as `root` reveals plenty of useful details. It first opens the `.pid` file with **Read and Write** permission (fd 3), then then drops root privileges by setting the group ID, user ID, and effective ID to 999. Finally, it calls `clone`, (similar to `fork`), creating a child process while the parent process exits leaving the child process **orphaned**. 

This literally refers to <a href="https://en.wikipedia.org/wiki/Orphan_process#:~:text=An%20orphan%20process%20is%20a,though%20it%20remains%20running%20itself." target="_blank">Orphan Process</a>. Because we did this intentionally, we also refered to this as a **daemon** (background process).

>It is sometimes desirable to intentionally orphan a process, usually to allow a long-running job to complete without further user attention, or to start an indefinitely running service or agent; such processes (without an associated session) are known as daemons, particularly if they are indefinitely running.

So, we can run `strace` with `-f` flag to follow the child processes created instead of staying in the parent process.

![strace-orphan-process](public/image/protostar-net/strace-child-process.png)

After `clone`,  the parent process exits, while the child process continues setting up its environment, **detaches from the terminal**, and eventually writes its PID into the `.pid` file.

Now the fun part starts when **socket communication** is established.

![socket-setup](public/image/protostar-net/socket-setup.png)

The socket binds to **port 2999**, listening for connections from any network (`0.0.0.0`). The message "Address already in use" appears because we previously ran `./net0`, meaning the process is still active.

Let's kill that process and rerun:

![socket-after-kill-net0](public/image/protostar-net/socket-after-kill-net0.png)

Now we will create a **TCP connection** to that port.

![after-tcp-connection](public/image/protostar-net/tcp-connection.png)

Once the **TCP connection** is established, the program **clones another process**. This new process handles the **Server-Client communication**, while the parent process remains available to accept new connections from other networks.

![way-to-exploit](public/image/protostar-net/way-to-exploit.png)

On the **Server side**, it just makes the **stdin** as the copy of **file descriptor 4**, which represents the **Server-Client connection**. This means that, **the Client** can send data back and forth to **the Server**. 

Nice! We now understand the working of three functions `background_process()`, `serve_forever()`, `set_io()`, we (Client) can **send the required number in little-endian format** to the Server to complete the challenge.

### Solution

Now that we understand how data flows between the Client and Server, we can craft an exploit. Our goal is to **send a number as a string in little-endian format** to the Server. 

Let's build our solution:

![solution](public/image/protostar-net/solution.png)

Here, I use `cat` to hold the screen to read from `stdin`. Then, I simply press `CTRL + D` to **send the little-endian format number as string** using `echo -e` to `nc 127.0.0.1 2999`.

## Net 1

Description:

>This level tests the ability to convert binary integers into ascii representation.<br>
>This level is at /opt/protostar/bin/net1

Source code:

```c
#include "../common/common.c"

#define NAME "net1"
#define UID 998
#define GID 998
#define PORT 2998

void run()
{
  char buf[12];
  char fub[12];
  char *q;

  unsigned int wanted;

  wanted = random();

  sprintf(fub, "%d", wanted);

  if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
      errx(1, ":(\n");
  }

  if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  q = strchr(buf, '\r'); if(q) *q = 0;
  q = strchr(buf, '\n'); if(q) *q = 0;

  if(strcmp(fub, buf) == 0) {
      printf("you correctly sent the data\n");
  } else {
      printf("you didn't send the data properly\n");
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

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

### Analysis

This level is very similar to **Net 0**, but this time, we're working with port **2998**.

Since we already understand the underlying working of three functions `background_process()`, `serve_forever()`, `set_io()` from **Net 0**, let's focus on how the `run()` function handles Server-Client interacton.

The program first generates a random unsigned integer `wanted` and writes it to `stdin`:

```c
if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
    errx(1, ":(\n");
}
```

But wait?! How does writing to `stdin` make sense? Well, since the connection between the Client and Server is already established, this actually sends `wanted` to the Client's `stdout`!

Our job as the client is simple:

1. Read the binary integer from `stdout`.
2. Convert it into string
3. Send it back to the Server.

This will be the key to beat this level!

### Solution

According to the <a href="https://docs.python.org/3/library/socket.html#timeouts-and-the-accept-method" target="_blank">Python socket documentation</a>, which perfectly fits our case, we can craft an exploit on the Client side to solve this challenge.

Here's my script:

```python
import socket
import struct

# Establish Client-Server Connection
HOST = '127.0.0.1'
PORT = 2998
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Receive 4-byte unsigned integer from Server
data = s.recv(4)

# Convert raw byte data to unsigned integer
n = struct.unpack("I", data)[0]

# Send the number back as a string with a newline
# to handle fgets()
s.send(str(n) + "\n")

# Receive message from Server (success or fail)
message = s.recv(1024)
print message
```

Run the script and receive the success message!

```shell
user@protostar:~$ python script.py
you correctly sent the data
```

## Net 2

Description:

>This code tests the ability to add up 4 unsigned 32-bit integers. Hint: Keep in mind that it wraps.<br>
>This level is at /opt/protostar/bin/net2

Source code:

```c
#include "../common/common.c"

#define NAME "net2"
#define UID 997
#define GID 997
#define PORT 2997

void run()
{
  unsigned int quad[4];
  int i;
  unsigned int result, wanted;

  result = 0;
  for(i = 0; i < 4; i++) {
      quad[i] = random();
      result += quad[i];

      if(write(0, &(quad[i]), sizeof(result)) != sizeof(result)) {
          errx(1, ":(\n");
      }
  }

  if(read(0, &wanted, sizeof(result)) != sizeof(result)) {
      errx(1, ":<\n");
  }


  if(result == wanted) {
      printf("you added them correctly\n");
  } else {
      printf("sorry, try again. invalid\n");
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

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

### Analysis

This level is similar to **Net 0**, but now we're working with port **2997**. The server generates four random 32-bit unsigned integers, adds them together, and sends each number to the client. The client's job is to read these numbers, compute their sum, and send it back.

However, there’s an important detail: since the numbers are **unsigned 32-bit integers**, their sum might exceed **32 bits**, causing an **Integer Overflow**. In C, when an unsigned integer overflows, any extra bits beyond **32 bits** are discarded automatically. To ensure we handle this correctly on the client side, we can **simulate this behavior** by applying `& 0xffffffff`. This operation keeps only the **lower 32 bits**, making sure our sum behaves exactly like an overflow in a 32-bit system.

So, our approach is simple:

1. Read four numbers from the server.
2. Add them together while ensuring overflow is handled.
3. Send the final sum back to the server.

By doing this, we can correctly match the server's expected result and pass the challenge.

### Solution

Here's my script:

```shell
import socket
import struct

# Establish Client-Server Connection
HOST = '127.0.0.1'
PORT = 2997
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Receive data from Server & Sum data
sum = 0
for i in range(4):
        n = s.recv(4)
        sum += struct.unpack("I", n)[0]

# Send sum back to Server + Handle Integer Overflow
s.send(struct.pack("I", sum & 0xFFFFFFFF))

# Receive message from Server (success or fail)
message = s.recv(1024)
print message
```

And the success message:

```shell
user@protostar:~$ python script.py
you added them correctly
```