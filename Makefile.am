#
# Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = compactor inspector

dist_doc_DATA = LICENSE.txt ChangeLog.txt KNOWN_ISSUES.txt README.adoc

if BUILD_DOCS
        dist_man_MANS = doc/compactor.1 doc/inspector.1
        dist_doc_DATA += doc/user-guide.html
endif

user_guide_sources = \
        $(srcdir)/doc/user-guide/user-guide.adoc \
        $(srcdir)/doc/user-guide/overview.adoc \
        $(srcdir)/doc/user-guide/installation.adoc \
        $(srcdir)/doc/user-guide/configuring.adoc \
        $(srcdir)/doc/user-guide/running.adoc \
        $(srcdir)/doc/user-guide/appendices.adoc

dslocalstatedir=$(localstatedir)/lib/$(PACKAGE)
dsconfdir=$(sysconfdir)/$(PACKAGE)
dsconf_DATA = compactor.conf
dist_noinst_DATA = etc/compactor.conf.in doc/compactor.adoc doc/inspector.adoc $(user_guide_sources)
conffile=$(dsconfdir)/compactor.conf

%.conf :: etc/%.conf.in ; sed -e "s|@DSLOCALSTATEDIR@|$(dslocalstatedir)|g" $< > $@

check_PROGRAMS = compactor-tests
check_SCRIPTS = test-scripts/check-config-info.sh \
                test-scripts/check-dnscap.sh \
                test-scripts/check-outputs.sh \
                test-scripts/check-template.sh \
                test-scripts/check-testcontent.sh \
                test-scripts/inspector-outputs.sh \
                test-scripts/same-output.sh \
                test-scripts/same-output-gzip.sh \
                test-scripts/same-output-xz.sh \
                test-scripts/same-file-output.sh \
                test-scripts/same-pcap-cbor-pcap.sh \
                test-scripts/same-qr-dump.sh \
                test-scripts/tmp-output.sh \
                test-scripts/same-tshark-output.sh \
                test-scripts/same-live.sh \
                test-scripts/verify-cbor02.sh \
                test-scripts/verify-cddl.sh

if ENABLE_PSEUDOANONYMISATION
        check_SCRIPTS += test-scripts/pseudoanon-tshark-output.sh \
                         test-scripts/pseudoanon-inspector-output.sh
        dist_check_SCRIPTS = $(check_SCRIPTS)
else
        dist_check_SCRIPTS = $(check_SCRIPTS)
        dist_check_SCRIPTS += test-scripts/pseudoanon-tshark-output.sh \
                              test-scripts/pseudoanon-inspector-output.sh
endif

dist_check_DATA = doc/c-dns-working.cddl \
                  test-scripts/dns.pcap.xz \
                  test-scripts/dnscap.pcap.xz \
                  test-scripts/gold.pcap.xz \
                  test-scripts/gold.cbor.xz \
                  test-scripts/gold.cbor02.xz \
                  test-scripts/gold.pcap.info \
                  test-scripts/malformed.pcap.xz \
                  test-scripts/matching.pcap.xz \
                  test-scripts/testcontent.pcap.xz \
                  test-scripts/testcontent.diag \
                  test-scripts/testcontent.debugqr \
                  test-scripts/unmatched.pcap.xz \
                  test-scripts/nsd-live.dump.xz \
                  test-scripts/nsd-live.raw.pcap.xz \
                  test-scripts/nsd-live.ignored.pcap.xz \
                  test-scripts/nsd-live.info \
                  test-scripts/knot-live.raw.pcap.xz \
                  test-scripts/knot-live.ignored.pcap.xz \
                  test-scripts/knot-live.info \
                  test-scripts/knot-live.anon.info \
                  test-scripts/check-live-pcap.sh \
                  test-scripts/test.tpl


EXTRA_DIST = getversion.sh .version

check_DATA = dns.pcap \
             dnscap.pcap \
             gold.pcap \
             gold.cbor \
             gold.cbor02 \
             malformed.pcap \
             matching.pcap \
             testcontent.pcap \
             unmatched.pcap \
             nsd-live.dump \
             nsd-live.raw.pcap \
             nsd-live.ignored.pcap \
             knot-live.raw.pcap \
             knot-live.ignored.pcap

CLEANFILES = $(check_DATA) $(dist_man_MANS)

% :: test-scripts/%.xz ; xz --decompress --to-stdout $< > $@

AM_TESTS_ENVIRONMENT = \
        GEOIPDIR=$(geoipdir); export GEOIPDIR;

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

AM_CPPFLAGS = -I$(srcdir)/src $(BOOST_CPPFLAGS) -DCONFFILE=\"$(conffile)\" \
              $(OPENSSL_INCLUDES) -DGEOIPDIR=\"$(geoipdir)\"

%.1 :: %.adoc ; @ASCIIDOC@ -b manpage -d manpage -o $@ $<

doc/user-guide.html : $(user_guide_sources) ; @ASCIIDOC@ -b html5 -d article -a appversion=$(PACKAGE_VERSION) -o $@ $(srcdir)/doc/user-guide/user-guide.adoc

doc/user-guide.pdf : $(user_guide_sources) ; @ASCIIDOC@ -b pdf -d article -r asciidoctor-pdf -a appversion=$(PACKAGE_VERSION) -o $@ $(srcdir)/doc/user-guide/user-guide.adoc

.PHONY: user-guide user-guide-html user-guide-pdf

user-guide : user-guide-html user-guide-pdf
user-guide-html : doc/user-guide.html
user-guide-pdf : doc/user-guide.pdf

compactor_headers = \
        src/addressevent.hpp \
        src/baseoutputwriter.hpp \
        src/bytestring.hpp \
        src/capturedns.hpp \
        src/cborencoder.hpp \
        src/channel.hpp \
        src/blockcbor.hpp \
        src/blockcbordata.hpp \
        src/blockcborwriter.hpp \
        src/configuration.hpp \
        src/dnsmessage.hpp \
        src/ipaddress.hpp \
        src/log.hpp \
        src/makeunique.hpp \
        src/matcher.hpp \
        src/nocopypacket.hpp \
        src/no-register-warning.hpp \
        src/packetstatistics.hpp \
        src/packetstream.hpp \
        src/pcapwriter.hpp \
        src/pseudoanonymise.hpp \
        src/queryresponse.hpp \
        src/rotatingfilename.hpp \
        src/sniffers.hpp \
        src/streamwriter.hpp

inspector_headers = \
        src/addressevent.hpp \
        src/capturedns.hpp \
        src/cbordecoder.hpp \
        src/backend.hpp \
        src/blockcbor.hpp \
        src/blockcbordata.hpp \
        src/blockcborreader.hpp \
        src/configuration.hpp \
        src/dnsmessage.hpp \
        src/geoip.hpp \
        src/ipaddress.hpp \
        src/log.hpp \
        src/makeunique.hpp \
        src/no-register-warning.hpp \
        src/pcapwriter.hpp \
        src/pseudoanonymise.hpp \
        src/queryresponse.hpp \
        src/streamwriter.hpp \
        src/template-backend.hpp

# _internal_test items work by #including the corresponding .cpp to get
# access to its internals. You can't have the _internal_test.cpp and the .cpp
# in the executable because you'll get duplicate definitions and linker
# complaints.
src_with_internal_tests = \
        src/matcher.cpp

src_without_internal_tests = \
        src/baseoutputwriter.cpp \
        src/bytestring.cpp \
        src/capturedns.cpp \
        src/cbordecoder.cpp \
        src/cborencoder.cpp \
        src/blockcbor.cpp \
        src/blockcbordata.cpp \
        src/blockcborwriter.cpp \
        src/configuration.cpp \
        src/dnsmessage.cpp \
        src/ipaddress.cpp \
        src/log.cpp \
        src/packetstream.cpp \
        src/pseudoanonymise.cpp \
        src/rotatingfilename.cpp \
        src/sniffers.cpp \
        src/streamwriter.cpp

compactor_SOURCES = \
        $(compactor_headers) \
        $(src_without_internal_tests) \
        $(src_with_internal_tests) \
        src/compactor.cpp

compactor_CXXFLAGS = @PTHREAD_CFLAGS@ -DBOOST_LOG_DYN_LINK
compactor_LDADD = \
        $(BOOST_FILESYSTEM_LIB) \
        $(BOOST_IOSTREAMS_LIB) \
        $(BOOST_LOG_LIB) \
        $(BOOST_PROGRAM_OPTIONS_LIB) \
        $(BOOST_SYSTEM_LIB) \
        $(BOOST_THREAD_LIB) \
        $(PCAP_LIB) \
        $(LZMA_LIB) \
        $(TCMALLOC_LIB) \
        @PTHREAD_LIBS@ \
        $(libtins_LIBS)
compactor_LDFLAGS = \
        $(BOOST_LDFLAGS)
if ENABLE_PSEUDOANONYMISATION
compactor_LDADD += \
        $(OPENSSL_LIBS)
compactor_LDFLAGS += \
        $(OPENSSL_LDFLAGS)
endif

compactor_tests_SOURCES = \
        $(compactor_headers) \
        tests/catch.hpp \
        tests/catch_main.cpp \
        $(src_without_internal_tests) \
        tests/baseoutputwriter_test.cpp \
        tests/capturedns_test.cpp \
        tests/cbordecoder_test.cpp \
        tests/cborencoder_test.cpp \
        tests/channel_test.cpp \
        tests/blockcbordata_test.cpp \
        tests/dnsmessage_test.cpp \
        tests/ipaddress_test.cpp \
        tests/matcher_test.cpp \
        tests/matcher_internal_test.cpp \
        tests/packetstream_test.cpp \
        tests/rotatingfilename_test.cpp
if ENABLE_PSEUDOANONYMISATION
compactor_tests_SOURCES += \
        tests/pseudoanonymise_test.cpp
endif

compactor_tests_CXXFLAGS = @PTHREAD_CFLAGS@ -DBOOST_LOG_DYN_LINK
compactor_tests_LDADD = \
        $(BOOST_FILESYSTEM_LIB) \
        $(BOOST_IOSTREAMS_LIB) \
        $(BOOST_LOG_LIB) \
        $(BOOST_PROGRAM_OPTIONS_LIB) \
        $(BOOST_SYSTEM_LIB) \
        $(BOOST_THREAD_LIB) \
        $(PCAP_LIB) \
        $(LZMA_LIB) \
        $(TCMALLOC_LIB) \
        @PTHREAD_LIBS@ \
        $(libtins_LIBS)
compactor_tests_LDFLAGS = \
        $(BOOST_LDFLAGS)
if ENABLE_PSEUDOANONYMISATION
compactor_tests_LDADD += \
        $(OPENSSL_LIBS)
compactor_tests_LDFLAGS += \
        $(OPENSSL_LDFLAGS)
endif

inspector_SOURCES = \
        $(inspector_headers) \
        src/backend.cpp \
        src/baseoutputwriter.cpp \
        src/rotatingfilename.cpp \
        src/bytestring.cpp \
        src/capturedns.cpp \
        src/cbordecoder.cpp \
        src/cborencoder.cpp \
        src/blockcbor.cpp \
        src/blockcbordata.cpp \
        src/blockcborreader.cpp \
        src/configuration.cpp \
        src/geoip.cpp \
        src/ipaddress.cpp \
        src/dnsmessage.cpp \
        src/inspector.cpp \
        src/log.cpp \
        src/pseudoanonymise.cpp \
        src/streamwriter.cpp \
        src/template-backend.cpp

inspector_CXXFLAGS = @PTHREAD_CFLAGS@ -DBOOST_LOG_DYN_LINK
inspector_LDADD = \
        $(BOOST_FILESYSTEM_LIB) \
        $(BOOST_IOSTREAMS_LIB) \
        $(BOOST_LOG_LIB) \
        $(BOOST_PROGRAM_OPTIONS_LIB) \
        $(BOOST_SYSTEM_LIB) \
        $(BOOST_THREAD_LIB) \
        $(LZMA_LIB) \
        @PTHREAD_LIBS@ \
        $(libtins_LIBS) \
        $(CTEMPLATE_LIB) \
        $(MAXMINDDB_LIB)
inspector_LDFLAGS = \
        $(BOOST_LDFLAGS)
if ENABLE_PSEUDOANONYMISATION
inspector_LDADD += \
        $(OPENSSL_LIBS)
inspector_LDFLAGS += \
        $(OPENSSL_LDFLAGS)
endif

.PHONY: cppcheck

CPPCHECK_DIRS = $(srcdir)/src
CPPCHECK_INCLUDE_DIRS = -I$(srcdir)/src
CPPCHECK_CMD = cppcheck \
        --std=c++11 --language=c++ \
        --xml --xml-version=2 \
        --inline-suppr
CPPCHECK_FLAGS = -U DLT_PKTAP --suppress=missingIncludeSystem

cppcheck: ; $(CPPCHECK_CMD) $(CPPCHECK_INCLUDE_DIRS) $(CPPCHECK_FLAGS) --enable=all $(CPPCHECK_DIRS)

@DX_RULES@
