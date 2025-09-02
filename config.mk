CXX = g++
CC = gcc

# g++ Compiler flags
CXX_WARNINGS = -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors
CXX_DEBUG    = -ggdb -fno-omit-frame-pointer
CXX_OPTIMIZE = -O2
CXX_STANDARD = -std=c++17
CXX_FLAGS = $(CXX_WARNINGS) $(CXX_DEBUG) $(CXX_OPTIMIZE) $(CXX_STANDARD)

# gcc Compiler flags
C_WARNINGS= -Wall -Wextra
C_DEBUG	  = -ggdb -fno-omit-frame-pointer
C_OPTIMIZE= -O2
C_STANDARD= -std=c11

CFLAGS = $(C_WARNINGS) $(C_DEBUG) $(C_OPTIMIZE) $(C_STANDARD)

# Include paths
#COMMON_INCLUDES = -I$(PROJECT_ROOT)/include
#C_INCLUDES = $(COMMON_INCLUDES) -I$(PROJECT_ROOT)/data-encryption/include
#CXX_INCLUDES = $(COMMON_INCLUDES) -I$(PROJECT_ROOT)/file-handlers/include
