AC_PREREQ([2.61])
AC_INIT([tunsocks], [1.0], [russ.dill@gmail.com], [tunsocks], [https://github.com/russdill/tunsocks])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CC
AC_CONFIG_FILES([Makefile])

AC_SEARCH_LIBS([event_add], [event])

AC_ARG_ENABLE([pcap],
        AS_HELP_STRING([--disable-pcap],[Disable optional PCAP support]),
                [case "${enableval}" in
                        yes) have_pcap=yes ;;
                        no) have_pcap=no ;;
                        *) AC_MSG_ERROR(bad value ${enableval} for --disable-pcap) ;;
                esac],
                [have_pcap=auto])

if test "x${have_pcap}" != xno ; then
	AC_CHECK_LIB(
		[pcap],
		[pcap_open_dead],
		[have_pcap=yes],
		[if test "x$have_pcap" = xyes ; then
			AC_MSG_ERROR([*** libpcap not found.])
		fi])

        if test "x$have_pcap" = xyes ; then
                PCAP_LIBS="-lpcap"
                AC_DEFINE(HAVE_PCAP, 1, [PCAP available])
        else
                have_pcap=no
        fi
else
        PCAP_LIBS=
fi

AC_SUBST(PCAP_LIBS)
AM_CONDITIONAL([HAVE_PCAP], [test "x$have_pcap" != xno])

AC_OUTPUT
