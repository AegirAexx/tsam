 _____ ____    _    __  __      ____            _           _    _____
|_   _/ ___|  / \  |  \/  |    |  _ \ _ __ ___ (_) ___  ___| |_ |_   _|_      _____
  | | \___ \ / _ \ | |\/| |    | |_) | '__/ _ \| |/ _ \/ __| __|  | | \ \ /\ / / _ \
  | |  ___) / ___ \| |  | |    |  __/| | | (_) | |  __/ (__| |_   | |  \ V  V / (_) |
  |_| |____/_/   \_\_|  |_|    |_|   |_|  \___// |\___|\___|\__|  |_|   \_/\_/ \___/
                                             |__/

Project two is a command line tool for scanning servers and finding open UDP ports.

It is configured to solve a puzzle set up on skel.ru.is(130.208.243.61). By knocking
on ports and delivering custom payloads we are able to get the oracle to reveal it's
secret.

Dependencies / Requirements:
- POSIX compliant shell. Like bash or zsh.
- coreutils.
- build-essential.


Install / Uninstall:

The program has one binary that has to be compiled from source and is written in C/C++.

To install the program run:

    make

To uninstall the program run:

    make clean

For your convience we've added a couple of shell scripts to run the program with two different outputs, verbose or not.

The project files:

├── project
    ├── makefile
    ├── run
    ├── run_verbose
    ├── README.txt
    └── scanner.cpp

- To compile, run: "make"

- To remove, run: "make clean"

Usage:
The program takes three arguements in this order, IP, Low Port and High Port. It also accepts, optionally, a fourth arguement that is a flag for a more verbose output, "--verbose" or "-v".

- To execute, run: "sudo ./scanner [Destination IP Address] [Low Port] [High Port]"

- Example: "sudo ./scanner 130.208.243.61 4000 4100"


Two shortcuts to run the program on skel.ru.is with different outputs:

- Basic, run: "./run 4000 4100"

- Verbose, run: "./run_verbose 4000 4100"

Flow of the program:

 TODO: FLOW OF THE PROGRAM IN A BRIEF SUMMARY
 DAGUR:taka fram ad forritid okkar er undirbuid til ad lesa hverskonar ICMP skilabod eru ad berast
...the program then finishes and terminates gracefully. DAGUR:


Authors:
Aegir Tomasson <aegir15@ru.is>
Dagur Kristjansson <dagur17@ru.is>

T-409-TSAM-20193

Teacher:
Jacky Mallett (jacky@ru.is)

TA:
 TODO: ADD SANDRA

Disclaimer

 TODO: ADD DISCLAIMER. PETER AND SOME CODE SOURCES. CUMSUM?? DOC PAGES??
Bob Loblaw style disclaimer... DAGUR:

Any similarities between us and Bjarne Stroustrup are purely coincidental.