# Building

## Ubuntu 20.04 or higher

Install dependencies:
```sh
export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get install -y \
  ccache \
  clang \
  clang-format \
  cmake \
  doxygen \
  git \
  graphviz
```

Clone repository and navigate inside:
```sh
git clone https://github.com/OmniBlade/unassemblize.git
cd unassemblize/
```

Generate build configuration
```sh
mkdir build && cd build
cmake ..

# workaround for "gcc: error: unrecognized command line option '-fcolor-diagnostics'"
sed -i 's/-fcolor-diagnostics//' _deps/lief-build/CMakeFiles/LIB_LIEF.dir/flags.make
```

Compile:
```sh
make --jobs $(nproc)

wait...

[100%] Built target unassemblize
```

Run executable:
```
$ ./unassemblize

unassemblize r6 ~201fc23
    x86 Unassembly tool

Usage:
  unassemblize [OPTIONS] [INPUT]
Options:
  -o --output     Filename for single file output. Default is program.S
  -f --format     Assembly output format.
  -c --config     Configuration file describing how to dissassemble the input
                  file and containing extra symbol info. Default: config.json
  -s --start      Starting address of a single function to dissassemble in
                  hexidecimal notation.
  -e --end        Ending address of a single function to dissassemble in
                  hexidecimal notation.
  -v --verbose    Verbose output on current state of the program.
  --section       Section to target for dissassembly, defaults to '.text'.
  --listsections  Prints a list of sections in the exe then exits.
  -d --dumpsyms   Dumps symbols stored in the executable to the config file.
                  then exits.
  -h --help       Displays this help.
```
