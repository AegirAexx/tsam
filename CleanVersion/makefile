#Default
all: scanner

#Compile scanner program
scanner: scanner.cpp
		g++ -O2 -Wall -std=gnu++11 -pthread scanner.cpp -o scanner

#Uninstall
clean:
		rm -v scanner