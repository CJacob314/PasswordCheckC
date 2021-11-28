# PasswordCheckC
A quick and fun project I wrote while bored.

It is based off of the api [here](https://api.pwnedpasswords.com/range/), which allows for safe checking of password security.

This program (as you can see), never sends your plain-text password, **OR** your password hash, anywhere. Here's how it works:

1. Your plain-text password is sent through the SHA-1 hashing algorithm. *Please note that this is not a secure algorithm for, say, storing users' hashes in a database*.
2. Only the first 20 hash bits (out of **160** total) are sent to the api, which returns a list of leaked hashes which begin with the same 20 bits.
3. *PasswordCheckC* compares your full hash (<ins>**only stored in RAM locally while the process is running**</ins>) with all those returned from the api.
4. *PasswordCheckC* then lets you know, via `stderr` output, whether or not your password hash was leaked in a public database breach (*one the api has found*), and how many times.


### Some Notes
* I use sockets directly in my code (rather than libcurl), because my aim was to compile a fully statically-linked version of the program. This has not been successful yet, as statically linking `libssl` is difficult, though coding my own SSL encryption is more so. 😆
