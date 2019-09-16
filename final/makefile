#Default
all: scanner

#Compile scanner program
server: scanner.cpp
		g++ -O2 -Wall -std=gnu++17 -pthread scanner.cpp -o scanner

#Uninstall
clean:
		rm -v scanner