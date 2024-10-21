all: encrypt.exe decrypt.exe

WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG    = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a
SOURCE   = Source/*.cpp
HEADERS  = Source/*.hpp

encrypt.exe: Makefile encrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o Executables/$@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) encrypt.cpp $(SOURCE)

decrypt.exe: Makefile decrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o Executables/$@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) decrypt.cpp $(SOURCE)

clean:
	rm -f Executables/encrypt.exe Executables/decrypt.exe Executables/*.key

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run your application.
run:
	Executables/encrypt.exe

