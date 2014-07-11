all: check_submodules
	$(MAKE) -C deps/pflua all

check:
	$(MAKE) -C deps/pflua check
	$(MAKE) -C src check

clean:
	$(MAKE) -C deps/pflua clean
	$(MAKE) -C src clean

check_submodules:
	@if [ ! -f deps/pflua/Makefile ]; then \
	    echo "Can't find deps/pflua/. You might need to: git submodule update --init"; exit 1; \
	fi

.SERIAL: all
