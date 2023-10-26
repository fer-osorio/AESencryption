all: encrypt decrypt

WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a
SOURCE = Source/AES.cpp Source/Bitmap.cpp Source/AESkey.cpp
HEADERS = Source/AES.hpp Source/Bitmap.hpp Source/OperationsGF256.hpp \
          Source/AESkey.hpp

encrypt: Makefile encrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) encrypt.cpp $(SOURCE)

decrypt: Makefile decrypt.cpp $(SOURCE) $(HEADERS)
	$(CXX) -o $@ $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) decrypt.cpp $(SOURCE)

clean:
	rm -f encrypt decrypt *.kiv

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run your application.
run:
	./encrypt

