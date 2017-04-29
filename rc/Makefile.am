EXTRA_DIST = \
	flytrap.init.in \
	flytrap.logrotate.in \
	flytrap.rc.in \
	flytrap.systemd.in

GENFILES = flytrap.init flytrap.logrotate flytrap.rc flytrap.systemd
CLEANFILES = $(GENFILES) edit-stamp
noinst_DATA = edit-stamp

edit-stamp: $(GENFILES) Makefile
	$(SED) -i- \
	    -e "s@\$${exec_prefix}@${exec_prefix}@" \
	    $(GENFILES)
	touch edit-stamp
