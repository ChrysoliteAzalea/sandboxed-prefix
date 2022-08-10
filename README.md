# sandboxed-prefix

**sandboxed-prefix** is a program that can be used to sandbox Wine applications. It sets up seccomp and Landlock restrictions and then executes Wine.

## Compiling

Firstly, you need to compile the shared libraries from the **landlock-functions** submodule. You can use these commands:

``cd landlock-functions/

gcc ll_wrapper.c -c -fpic -o ll_wrapper.o

gcc ll_wrapper.o -shared -o libllwrapper.so

gcc add_rule.c -c -fpic -o add_rule.o

gcc add_rule.o -shared -o libaddrule.so
``

These libraries can be placed in /usr/local/lib/ directory, so the program can compile and run correctly using these libraries.

Then, you can compile the **sandboxed-prefix** itself, using the following command:

``
gcc sandboxed-prefix.c -lllwrapper -laddrule -lapparmor -lseccomp
``

A build system support will be added later.
