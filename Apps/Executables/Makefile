all: AESencryption.exe AESdecryption.exe

WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG    = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a
SOURCE   = ../../Source/*.cpp
HEADERS  = ../../Source/*.hpp

AESencryption.exe: Makefile ../encrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) ../encrypt.cpp $(SOURCE)

AESdecryption.exe: Makefile ../decrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) ../decrypt.cpp $(SOURCE)

clean:
	rm -f AESencryption.exe AESdecryption.exe

clean_all:
	rm -f AESencryption.exe AESdecryption.exe *.key

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run encryption application.
run_encryption:
	AESencryption.exe

# Builder uses this target to run decryption application.
run_decryption:
	AESdecryption.exe
