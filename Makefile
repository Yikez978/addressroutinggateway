c_files := $(filter-out $(wildcard *.mod.c),$(wildcard *.c))
obj-m += arg.o
#arg-objs := $(patsubst %.c,%.o,$(c_files))
arg-objs := init.o utility.o director.o hopper.o nat.o
 
all :
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean :
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f *.o *.ko
	rm -f modules.order

# Make on dev machine from OSX
push : 
	./scripts/run-on-all.sh -t dev scripts/helper/false.sh .

remote : 
	./scripts/run-on-all.sh -t dev scripts/helper/make.sh .

# Ensure dropbox has synced fully and make the main all target include that check
dropbox-sync : 
	./scripts/wait-for-db.sh

safe : dropbox-sync all

# Default test to do whatever it is we want to do most often
# for now, just do local test
test : local-test

# Testing on laptop VM
local-test : local-start

local-start : all local-stop
	sudo insmod arg.ko

local-stop : 
	-lsmod | grep arg >/dev/null && sudo rmmod -w arg

local-monitor :
	tail -f /var/log/kern.log | grep ARG

# Control ARG gateways
start : all
	./scripts/start-arg-servers.sh

stop : 
	./scripts/stop-arg-servers.sh

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

