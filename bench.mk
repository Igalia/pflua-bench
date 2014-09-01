GUILE=guile

PATH:=$(top_srcdir)/deps/pflua/deps/luajit/usr/local/bin:$(PATH)
ENGINES:=libpcap linux-bpf linux-ebpf bpf-lua pflua
CSV:=$(addsuffix .csv, $(ENGINES))

all: $(PNG)

csv: $(CSV)

maintainer-clean:
	rm -f $(CSV) $(PNG)

%.csv: $(top_srcdir)/bench.lua $(SAVEFILE) filters
	luajit $(top_srcdir)/bench.lua $(SAVEFILE) filters $* > $@.tmp
	mv $@.tmp $@

$(PNG): Makefile $(top_srcdir)/bench.mk $(CSV)
	$(MAKE) check-png-deps
	~/src/guile-charting/examples/plot-data.scm $(TITLE) "$@" $(CSV)

check-png-deps:
	@$(GUILE) -c '(exit (string-prefix? "2." (effective-version)))' 2>/dev/null || ( \
	  echo "Guile 2.x required to make graphs.  Try 'sudo apt-get install guile-2.0'."; \
	  echo; \
	  exit 1 )
	@$(GUILE) -c '(use-modules (cairo))' 2>/dev/null || ( \
	  echo "Guile-Cairo required to make graphs."; \
	  echo "Install from http://www.nongnu.org/guile-cairo/; probably you will"; \
	  echo "want to run its configure with --prefix=/usr."; \
	  echo; \
	  exit 1 )
	@$(GUILE) -c '(use-modules (charting))' 2>/dev/null || ( \
	  echo "Guile-Charting required to make graphs."; \
	  echo "Check out from https://gitorious.org/guile-charting."; \
	  echo "I recommend not installing it.  Instead after configuring"; \
	  echo "and building, run this make target within the 'env' script"; \
	  echo "in the guile-charting build directory."; \
	  exit 1 )
