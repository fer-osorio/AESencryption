all: encrypt


WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a
SOURCE = encrypt.cpp Source/AES_256.cpp Source/Bitmap.cpp
HEADERS = Source/AES_256.hpp Source/Bitmap.hpp Source/OperationsGF256.hpp

encrypt: Makefile $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) $(SOURCE)

clean:
	rm -f encrypt Encryption.bmp

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run your application.
run:
	./encrypt

