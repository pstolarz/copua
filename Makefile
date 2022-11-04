.PHONY: all clean distclean init

all:
	$(MAKE) -C src all

clean:
	$(MAKE) -C src clean

distclean:
	$(MAKE) -C src distclean

init:
	$(MAKE) -C src init
