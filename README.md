
github repo : https://github.com/cerenaluc/comp304

I added ta as contributor with username mktip
I also indicated solutions of parts with commands
compile: gcc -o shell-ish shell-ish.c

For part1
I implemented basic shell features. I added path resolving with execv. 
I also added background process support with & and the cd builtin.
ex: pwd, echo hello 

For part2
I implemented pipes and redirections. I wrote apply_redirections for < > >> cases
ex: echo "test" > myfile.txt, cat myfile.txt

For part3a
I implemented cut as a builtin command. It reads from stdin and prints the fields the user wants.
I added -d for delimiter and -f for field selection. Fields are 1-indexed.

For part3b
I implemented chatroom using named pipes. Each user gets their own FIFO in the room folder. 
I used select() to listen to both stdin and the pipe at the same time.
fork() to send messages to other users
type exit to leave

For part3c
I implemented bookmark as my custom command. while studying the lecture notes on process creation and
environment variables I thought it would be useful to have a way to save and revisit directories quickly
Bookmarks are stored in ~/.shellish_bookmarks
How to use
bookmark add <name> <path>
bookmark list
bookmark go <name>
bookmark remove <name>

ex:
bookmark add home /home/ceren
bookmark add docs /home/ceren/Documents
bookmark list
bookmark go docs
bookmark remove home


