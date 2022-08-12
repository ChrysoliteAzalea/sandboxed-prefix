# sandboxed-prefix

**sandboxed-prefix** is a program that can be used to sandbox Wine applications. It sets up seccomp and Landlock restrictions and then executes Wine.

## Compiling

You can compile this program using the following command:

``
gcc sandboxed-prefix.c -lapparmor -lseccomp -o sandboxed-prefix
``

A build system support will be added later.

# Warning! This is a purely experimental project that has not been tested in any real use-cases yet!
