
.PHONY: all clean

all: app

app : app.cpp
	g++ -std=c++11 app.cpp recipient.cpp utils.cpp crypto.cpp -I../ -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o psapp
