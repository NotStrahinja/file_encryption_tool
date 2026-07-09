# file_encryption_tool
A simple file encryption tool written in Zig

## Usage
To compile, run this command:
```console
$ zig build-exe main.zig
```

To encrypt a file, you can run this:

```console
$ ./main -e file.txt -p Password123
```

And to decrypt, you run this:

```console
$ ./main -d file.txt.enc -p Password123
```

The current default extension is `.enc`, but I may add the option to change that as well.

## Features
This tool uses XChaCha20-Poly1305 for the file encryption and message authentication.

It uses Argon2id for deriving the key from a password you provide in the command line.
