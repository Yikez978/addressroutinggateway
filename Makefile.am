ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

AM_CPPFLAGS = $(DEPS_CFLAGS) -Wall -O3

# Everything will get built into here
bin_PROGRAMS = arg gen_gate_config
arg_SOURCES = uthash.h \
	arg_error.h \
	arg_error.c \
	settings.h \
	settings.c \
	packet.h \
	packet.c \
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

gen_gate_config_SOURCES = settings.h \
	gen_gate_config.c

arg-local : stop

remote : 
	scripts/executer.sh run-make

# Default test to do whatever it is we want to do most often
# for now, just do local test
testA : stop arg
	sudo ./arg conf/main-gateA.conf 

testB : stop arg
	sudo ./arg conf/main-gateB.conf

test : start

# Control ARG gateways
start : arg
	sudo ./arg

stop : 
	-killall arg

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

