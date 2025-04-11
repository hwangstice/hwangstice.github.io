---
title: "OverTheWire - Leviathan"
description: "Writeup for OverTheWire Leviathan"
pubDate: "April 12 2025"
image: /image/blog-cover/leviathan.jpg
categories:
  - tech
tags:
  - Wargame
  - Reverse
---

I'm super excited right now because I just learned new techniques, and I also got to play around with **radare2** for the first time. It feels amazing to really understand how a binary actually works and then come up with a way to exploit it. Nothing beats that feeling!

## Level 0 &rarr; Level 1

First of all, we must log into **leviathan0** with the following SSH Information, and the password is **leviathan0**.

![ssh-information](public/image/overthewire-leviathan/ssh-information.png)

Using the `ls -la` command to list all the hidden files and folders, we find a suspicious folder called `.backup`. Inside it, there's an HTML file that stands out because it's pretty large, around **131KB**. Maybe in there contains the password. We run `grep` and get the password for the next level.

![level0-solution](public/image/overthewire-leviathan/level0-solution.png)

> &#10140; **3QJ3TgzHDq**

## Level 1 &rarr; Level 2

In the home directory, we find an executable file named `check`. It's a setuid file, which means when we run it, it executes with the permissions of the file's owner.

![level1-ls-command](public/image/overthewire-leviathan/leviathan1-ls-command.png)

As the user **leviathan1**, we have permission to read and run this file. So, let's try executing it and see what it does.

![leviathan1-run-file](public/image/overthewire-leviathan/leviathan1-run-file.png)

It asks us for the password. If the password is wrong, we receive a string **"Wrong password, Good Bye ..."**.

Let's open the binary in **radare2**, and check it out in the Visual Mode.

![level1-radare2-running](public/image/overthewire-leviathan/level1-radare2-running.png)

There's a call to **strcmp()**, which takes **s1** and **s2** as the arguments. For **s1**, it is our input from the terminal, and **s2** is a string stays on the stack.

![level1-strcmp](public/image/overthewire-leviathan/level1-strcmp.png)

If the two string don't match, we receive the fail message. Otherwise, we get a shell **/bin/sh**, which run with **leviathan2**'s permissions.

![level1-strcmp-branch](public/image/overthewire-leviathan/level1-strcmp-branch.png)

So, what is the correct input? Looking at the binary, we see the password is `sex`. 

![level1-shell-password](public/image/overthewire-leviathan/level1-password.png)

When we run the file again, enter the password, and we get the shell and access the next level's password.

![level1-solution](public/image/overthewire-leviathan/level1-solution.png)

>&#10140; **NsN1HwFoyN**

## Level 2 &rarr; Level 3

> In this level, **TOCTOU Attack** is used.

We find a file in home directory called `printfile`, which is a setuid file. This means that the file is running with **leviathan3**'s privileges even though we're still **leviathan2**.

![level2-overview](public/image/overthewire-leviathan/level2-overview.png)

Looks like the binary can read the content in a specific file. Let's have a check for that. We create a file in `/tmp` with the string **"hello world!"**.

![level2-readfile](public/image/overthewire-leviathan/level2-read-file.png)

Umm, everything seems fine, there's nothing much we can exploit from this. Let's read the binary in **radare2**.

![level2-radare2](public/image/overthewire-leviathan/level1-radare2-running.png)

Inside the code, we have a call to <a href="https://man7.org/linux/man-pages/man2/access.2.html" target="_blank">access() function</a>. This function checks if the file can be read **based on the real user ID** (which is **leviathan2** in our case), using **mode 4** (read permission).

![level2-access](public/image/overthewire-leviathan/level2-access.png)

This means that as user **leviathan2**, we cannot read the file owned by **leviathan3**.

![level2-access-restriction](public/image/overthewire-leviathan/level2-access-restriction.png)

But when we bypass the check of **access()**, we have privileges escalation, where it sets the **real uid** to the **effective uid (leviathan3)**. At this very moment, we can actually read the password file for the next level.

![level2-bypass-access](public/image/overthewire-leviathan/level2-bypass-access.png)

So, right now, our program have this general structure:
1. Take input
2. Condition to check
3. Read the file

From here, we will go into **TOCTOU Attack**, where we trick the program by changing the file **after the access() check** but **before the actual read**.

![level2-TOCTOU](public/image/overthewire-leviathan/level2-TOCTOU.png)

This works because we make the most of the concept of **race condition**, where multiple processes run and access resources at the same time. This means that we will create two process, one to bypass the check, and one try to read the password file.

To do that, we will use the `ln -sf` command, which creates a **symlink**, and create a file named `symlink` in `/tmp` to make the symlink.

![level2-toctou-attack](public/image/overthewire-leviathan/level2-toctou-attack.png)

Now, we just need to read the file `leviathan2-output` to get the password.

![level2-output-solution](public/image/overthewire-leviathan/level2-output-solution.png)

>&#10140; **f0n8h2iWLP**

## Level 3 &rarr; Level 4

Again, in the home directory, we have a setuid file called `level3`. When running this file, we are asked to enter the password.

![level3-overview](public/image/overthewire-leviathan/level3-overview.png)

Nothing much we can see here, let's check the binary in **radare2** in Visual Mode.

![level3-radare2-setup](public/image/overthewire-leviathan/level3-radare2-setup.png)

In `main`, there is nothing much special here. Just some **mov instructions** for the false password purpose?

![level3-false-password](public/image/overthewire-leviathan/level3-false-password.png)

There's even a call to **strcmp()** between **kaka** and **morenothing**, which is definitely not equal.

![level3-strcmp](public/image/overthewire-leviathan/level3-strcmp.png)

But wait, the function **do_stuff** looks interesting. Let's move to there.

![level3-do_stuff](public/image/overthewire-leviathan/level3-so_stuff.png)

There's a call to **strcmp()**, which compares **s1 (our input)** and **s2 (hard-coded string)**.

Depends on the input password that we will receive the shell or fail message.

![level3-strcmp-output](public/image/overthewire-leviathan/level3-strcmp-result.png)

If you look closely, the variables **var_113h** and **var_110h** are actually close to **s2** on the stack frame.

![level3-output-dump](public/image/overthewire-leviathan/level3-variable-dump.png)

Here is how the stack looks like.

![level3-stack-frame](public/image/overthewire-leviathan/level3-stack-frame.png)

So, our input password must be `snlprintf`. 

![level3-input-password](public/image/overthewire-leviathan/level3-input-solution.png)

And we just need to read the password when we get the shell.

![level3-solution](public/image/overthewire-leviathan/level3-solution.png)

>&#10140; **WG1egElCvO**

## Level 4 &rarr; Level 5

We have a setuid file inside `.trash` directory called `bin`.

![level4-home-directory](public/image/overthewire-leviathan/level4-home-directory.png)

When run the file, we get a series of 8-bit binary. Let's use an <a href="https://www.rapidtables.com/convert/number/binary-to-string.html" target="_blank">online converter tool</a> to convert this binary.

![level4-password](public/image/overthewire-leviathan/level4-password.png)

This might be the password, let's have a check for that. 

![level4-login-next-level](public/image/overthewire-leviathan/level4-login-next-level.png)

Use the this password `0dyxT7F4QD`, and we get next level's shell.

![level4-success-login](public/image/overthewire-leviathan/level4-success-login.png)

>&#10140; **0dyxT7F4QD**

## Level 5 &rarr; Level 6

> In this level, **TOCTOU Attack** is used.

Again, in the home directory, we have a setuid file called `leviathan5`. When attempting to run that file, it told us about **cannot find /tmp/file.log**. So, after creating that file with content **hello world!**, it actually prints that string out.

![level5-home-directory](public/image/overthewire-leviathan/level5-home-directory.png)

Let's run the binary in **radare2** with Visual Mode.

![level5-r2](public/image/overthewire-leviathan/level5-r2.png)

First, it opens the file `/tmp/file.log`, and checks whether the file exists or not. 

![level5-first-r2](public/image/overthewire-leviathan/level5-first-r2.png)

If you think closely, the check for file existence is obviously **The Check in TOCTOU Attack**. Then it opens the file, reads the content of the file until reaching **EOF**. After that it sets privilege of **effective user ID** to **current real user ID**, and a call to **unlink()**.

![level5-r2-second](public/image/overthewire-leviathan/level5-r2-second.png)

In general, the structure of our program is as follow:
1. Check file `/tmp/file.log` existence
2. Read `/tmp/file.log` content
3. Drop privilege and return

So, the solution is that we will create a **symlink** right after we pass the check and before we drop privilege.

![level5-idea-solution](public/image/overthewire-leviathan/level5-create-symlink-idea.png)

Let's head to our solution.

![level5-solution](public/image/overthewire-leviathan/level5-solution.png)

>&#10140; **szo7HDB88w**

## Level 6 &rarr; Level 7

Checking the home directory, there is setuid file called `leviathan6`, which asks us to **enter a 4-digit code**. 

![level6-overview](public/image/overthewire-leviathan/level6-overview.png)

We can just use the bruteforce method to find that **4-digit code**, but where's the fun xD.

Let's read the binary in **radare2** and see what happens.

![level6-r2](public/image/overthewire-leviathan/level6-r2.png)

So, we have to make sure to enter the **4-digit code** with our binary run. Then, we have a call to **strcmp()**, which compares between **eax** and **var_ch**, where **eax** is our **4-digit input**, and **var_ch** is a hard-coded number. 

![level6-r2-check](public/image/overthewire-leviathan/level6-r2-check.png)

If you look carefully, the value for **var_ch** is `0x1bd3`, which is `7123` in decimal. So the 4-digit we need to enter is `7123`.

When enter that number, we will get the shell and can read the password for the next level.

![level6-r2-reason](public/image/overthewire-leviathan/level6-r2-reason.png)

Here is the solution.

![level6-solution](public/image/overthewire-leviathan/level6-solution.png)

>&#10140; **qEs5Io5yM8**

## Level 7

![finish-leviathan](public/image/overthewire-leviathan/level7-game-finish.png)

Now, we have cleared all levels in **OverTheWire Leviathan**. 

I make this blog to solidify my knowledge only, and there are tons of writeups about this game too, so maybe this won't break the rule ?! HAHA 🙂‍↕️

## Reference

- <a href="https://hackmd.io/@whoisthatguy/toctou" target="_blank">TOCTOU Attack</a>