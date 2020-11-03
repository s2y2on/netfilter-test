all: netfilter-test

netfilter-test: netfilter-test.o
	g++ -g -o netfilter-test netfilter-test.o -lnetfilter_queue

netfilter-test.o:
	g++ -c -g -o netfilter-test.o netfilter.cpp

clean:
	rm -r netfilter-test
	rm -r netfilter-test.o
