# Graph Based Intrusion Detection System (GIDS)

This repository contains a C implementation of a graph-based intrusion detection system for cybersecurity research and experimentation.

## Features

- Graph-based modeling of network/system events
- Intrusion detection logic implemented in C
- Simple CLI for running detection on input data

## Requirements

- GCC (or any C compiler)
- Unix-like environment (Linux, macOS) or Windows with compatible build tools

## Build

From the repository root, compile the C sources. Adjust the command below if your source files are in a subdirectory or have different names:

```sh
# compile all .c files in the repo into an executable named gids
gcc -o gids *.c
```

If the project provides a Makefile, run:

```sh
make
```

## Usage

Run the compiled program with the required input files. Replace the example arguments below with the real input files and options used by this project:

```sh
# example
./gids input_data.txt
```

If the repository includes sample data or configuration files, refer to those for exact usage and options.

## Project structure

- src/ (optional): C source files
- include/ (optional): Header files
- data/ (optional): Sample input data

Adjust these locations based on the repository layout.

## Contributing

Contributions are welcome. Please open issues to discuss changes or submit pull requests with clear descriptions and tests where appropriate.

## License

This repository does not include a license file. If you want to apply an open-source license, add a LICENSE file (for example, MIT) and update this section.

## Contact

For questions, open an issue or contact the repository owner.
