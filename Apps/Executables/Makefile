all: AESencryption.exe AESdecryption.exe

WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG    = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a
SOURCE   = ../Settings.cpp ../../Source/*.cpp
HEADERS  = ../Settings.hpp ../../Source/*.hpp

AESencryption.exe: Makefile ../encryption.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) ../encryption.cpp $(SOURCE)

AESdecryption.exe: Makefile ../decryption.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) ../decryption.cpp $(SOURCE)

EntropyComparison.exe: Makefile ../EntropyComparison.cpp ../../Source/File.cpp ../../Source/File.hpp ../../Source/AES.cpp ../../Source/AES.hpp
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) ../EntropyComparison.cpp ../../Source/File.cpp ../../Source/AES.cpp

clean:
	rm -f AESencryption.exe AESdecryption.exe

clean_all:
	rm -f AESencryption.exe AESdecryption.exe *.key

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run encryption application.
run_encryption:
	./AESencryption.exe

# Builder uses this target to run decryption application.
run_decryption:
	./AESdecryption.exe
