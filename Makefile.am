ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

AM_CPPFLAGS = $(DEPS_CFLAGS) -Wall -ggdb

# Everything will get built into here
bin_PROGRAMS = arg
arg_SOURCES = uthash.h \
	packet.h \
	packet.c \
	sha1.h \
	sha1.c \
	utility.h \
	utility.c \
	crypto.h \
	crypto.c \
	protocol.h \
	protocol.c \
	hopper.h \
	hopper.c \
	nat.h \
	nat.c \
	director.h \
	director.c \
	init.c

# Default test to do whatever it is we want to do most often
# for now, just do local test
test : start

# Control ARG gateways
start : all
	sudo ./arg

# Start tests with/without ARG running
test-arg-on : start
	./scripts/start-tests.sh

test-arg-off : stop
	./scripts/start-tests.sh

# Helper targets to control systems
clean-vms :
	./scripts/run-on-all.sh ./scripts/helper/clean-files.sh

shutdown :
	./scripts/run-on-all.sh ./scripts/helper/shutdown.sh
	
reboot :
	./scripts/run-on-all.sh ./scripts/helper/reboot.sh

