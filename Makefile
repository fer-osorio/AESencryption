all: AESencryption.exe AESdecryption.exe Statistics.exe

WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
DEBUG    = -ggdb -fno-omit-frame-pointer
OPTIMIZE = -O2
STANDARD = -std=c++2a

SOURCE   = Apps/Settings.cpp Source/*.cpp
HEADERS  = Apps/Settings.hpp Source/*.hpp
ENCRYPTF = Apps/encryption.cpp
DECRYPTF = Apps/decryption.cpp
STATSF	 = Apps/Statistics.cpp
GRAF	 = Apps/Grafiken.cpp
EXEDIR	 = Apps/Executables/
EXERPATH = Apps/Executables/$@

AESencryption.exe: Makefile $(ENCRYPTF) $(SOURCE) $(HEADERS)
	$(CXX) -o $(EXERPATH) $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) $(ENCRYPTF) $(SOURCE)

AESdecryption.exe: Makefile $(DECRYPTF) $(SOURCE) $(HEADERS)
	$(CXX) -o $(EXERPATH) $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) $(DECRYPTF) $(SOURCE)

Statistics.exe: Makefile $(STATSF) Source/File.cpp Source/File.hpp Source/AES.cpp Source/AES.hpp
	$(CXX) -o $(EXERPATH) $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) $(STATSF) Source/File.cpp Source/AES.cpp

Grafiken.exe: Makefile $(GRAF) Source/File.cpp Source/File.hpp Source/AES.cpp Source/AES.hpp
	$(CXX) -o $(EXERPATH) $(WARNINGS) $(DEBUG) $(OPTIMIZE) $(STANDARD) $(GRAF) Source/File.cpp Source/AES.cpp `pkg-config --cflags --libs plplot-c++`

clean:
	rm -f $(EXEDIR)*.exe

clean_all:
	rm -f $(EXEDIR)*.exe $(EXEDIR)*.aes

# Builder will call this to install the application before running.
install:
	echo "Installing is not supported"

# Builder uses this target to run encryption application.
run_encryption:
	$(EXEDIR)/AESencryption.exe

# Builder uses this target to run decryption application.
run_decryption:
	$(EXEDIR)/AESdecryption.exe
