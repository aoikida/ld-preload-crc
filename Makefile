CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -fPIC -Wall -Wextra -pthread
LDFLAGS ?= -shared -ldl

TARGET = libsei_preload.so
SRC = libsei_preload.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
