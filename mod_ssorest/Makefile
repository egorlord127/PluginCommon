DEFS=-DBIG_JOINS=1 $(SHARED_CACHING)
INCLUDES= \
    -I. \
    -I../include \


LIBS=

SOURCES= \
    mod_ssorest.c \
    ../src/SSORestPlugin.c \

main:
	apxs $(INCLUDES) $(DEFS) -c $(SOURCES) $(LIBS)

#   the default target
all: main

#   install the shared object file into Apache 
install: main
	sudo apxs -i mod_ssorest.la
clean:
	for i in . ../src; do \
		$(RM) $$i/*.{o,so,a,la,lo,slo} core; \
		$(RM) -rf $$i/.libs; \
	done

