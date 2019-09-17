 _____ ____    _    __  __      ____            _           _    _____
|_   _/ ___|  / \  |  \/  |    |  _ \ _ __ ___ (_) ___  ___| |_ |_   _|_      _____
  | | \___ \ / _ \ | |\/| |    | |_) | '__/ _ \| |/ _ \/ __| __|  | | \ \ /\ / / _ \
  | |  ___) / ___ \| |  | |    |  __/| | | (_) | |  __/ (__| |_   | |  \ V  V / (_) |
  |_| |____/_/   \_\_|  |_|    |_|   |_|  \___// |\___|\___|\__|  |_|   \_/\_/ \___/
                                             |__/

T-409-TSAM-2019-3

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

For your convience we've added a shell script to run the program with less typing
needed to execute.

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

The program takes three arguements in this order, IP, Low Port and High Port.
- To execute, run: "sudo ./scanner [Destination IP Address] [Low Port] [High Port]"
- Example: "sudo ./scanner 130.208.243.61 4000 4100"


Shortcuts to run the program on skel.ru.is:
- Basic, run: "./run 4000 4100"


Flow of the program:

This program includes a port scanner that scans for open ports. In the first version of
the scanner we just listened for the 4 UDP packets and ignored the ICMP messages. This
was of course a lot faster version of a scanner but after TA Benedikt told us that this
was not the correct method we switched to listening for ICMP instead.
We rewrote our scanner to do just that, also we dynamically receive and send all the
information from the ports, parsing the strings inorder to solve the puzzles.
The flow of our program could best be described in 5 parts, or waves as we like to call
them.

1st wave

First off we send an empty message to all the ports that are defined in the range given
by the user. We read all the ICMP packages that we receive and check if the ICMP code is
3 (port unreachable). If a port sends us such a packet we conclude that it is closed.
We knock on each port 5 times and wait 500 ms between knocks. This takes a little bit of
a time but the server was responding very slowly in the late hours and the long wait was
necessary to ensure that we received a message from all ports that were closed.

2nd wave

We mark all the ports that have not sent us an ICMP package as open.
We then send all the open ports a message and receive the UDP package that they send us
and save the message in an openPorts struct along with the port number and which of the
4 types of ports we are dealing with (Evilbit, Checksum, Port forward or Orracle) and
some boolean flags we use to send various messages.
In this stage we also receive a port from one of the open ports and we store that info
in the corresponding port struct.

3rd wave

Now we know which port is which we send again to the open ports. If you are the Evilbit
port then we send you a message with the evil bit set and we receive another port which
we store in the port struct.
If you are the checksum port we send you a port with the given checksum and receive a
secret phrase that we store in the port struct.

4th wave

Here we send the Oracle the port numbers that we received from the Evilbit port and the
Port forwarding port.
We store the new message that we receive in the port struct. This contains the order of
ports we should send to in order to receive the final phrase.

5th wave

We send to the ports in the order we received in the part before and we receive a final
ICMP packet and a UDP message. Which we then write to the screen.


Authors:
Aegir Tomasson <aegir15@ru.is>
Dagur Kristjansson <dagur17@ru.is>


Teacher:
Jacky Mallett (jacky@ru.is)


TA:
Sandra Ros Hrefnu Jonsdottir

Total time spent on project: 40 hours.


Disclaimer

We discussed the project with a lot of TA's and fellow students but we spent the most time
with a group of students (Petur Orn Gudmundsson and Throstur Sveinbjornsson). We discussed
the project a lot and some similarities in code could exist.

Also we used the code that TA Einar Orn Sveinbjornsson shared. Our checksum calculating
function and our send function is heavily unfluenced from that code.