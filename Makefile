all: check_luajit check

check_luajit:
	@if [ ! -f ../pflua/deps/luajit/Makefile ]; then \
	    echo "Can't find ../pflua/deps/luajit/. This code works in tandem with pflua code"; exit 1; \
	fi

check:
	(cd src && $(MAKE) check)

clean:
	(cd src; $(MAKE) clean)

.SERIAL: all
