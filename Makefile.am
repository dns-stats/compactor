#
# Copyright 2016-2020 Internet Corporation for Assigned Names and Numbers.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = compactor inspector

dist_doc_DATA = LICENSE.txt ChangeLog.txt KNOWN_ISSUES.txt

if BUILD_DOCS
        dist_man_MANS = doc/compactor.1 doc/inspector.1
        dist_doc_DATA += doc/user-guide.html doc/overview.png README.html
endif

common_doc_sources = \
        doc/user-guide/compactor-command-options.adoc \
        doc/user-guide/compactor-capture-from-network.adoc \
        doc/user-guide/compactor-outputs.adoc \
        doc/user-guide/compactor-query-response-matching.adoc

user_guide_sources = \
	$(common_doc_sources) \
        doc/user-guide/overview.adoc \
        doc/user-guide/overview.png \
        doc/user-guide/installation.adoc \
        doc/user-guide/configuring.adoc \
        doc/user-guide/running.adoc \
        doc/user-guide/appendices.adoc

dslocalstatedir=$(localstatedir)/lib/$(PACKAGE)
dsconfdir=$(sysconfdir)/$(PACKAGE)
dsconf_DATA = etc/compactor.conf \
              etc/excluded_fields.conf.sample \
              etc/default_values.conf
dist_dsconf_DATA = etc/compactor.conf \
	           etc/excluded_fields.conf.sample \
                   etc/default_values.conf
dist_noinst_DATA = README.adoc \
                   doc/compactor.adoc doc/inspector.adoc \
                   $(user_guide_sources)

conffile=$(dsconfdir)/compactor.conf
excludesfile=$(dsconfdir)/excluded_fields.conf
defaultsfile=$(dsconfdir)/default_values.conf

%.conf :: %.conf.in ; mkdir -p `dirname $@`; sed -e "s|@DSLOCALSTATEDIR@|$(dslocalstatedir)|g" $< > $@
%.adoc :: %.adoc.in ; mkdir -p `dirname $@`; sed -e "s|@ETCPATH@|$(dsconfdir)|" -e "s|@VARLIBPATH@|$(dslocalstatedir)|g" $< > $@

%.1 : %.adoc ; @ASCIIDOC@ -b manpage -d manpage -o $@ $<
%.html : %.adoc ; @ASCIIDOC@ -b html5 -d article -a appversion=$(PACKAGE_VERSION) -o $@ $<
%.pdf : %.adoc ; @ASCIIDOC@ -b pdf -d article -r asciidoctor-pdf -a appversion=$(PACKAGE_VERSION) -o $@ $<

% :: test-scripts/%.xz ; xz --decompress --to-stdout $< > $@

check_PROGRAMS = compactor-tests
check_SCRIPTS = test-scripts/check-config-info.sh \
                test-scripts/check-defaults-required.sh \
                test-scripts/check-dnscap.sh \
                test-scripts/check-outputs.sh \
                test-scripts/check-query-only.sh \
                test-scripts/check-response-opt.sh \
                test-scripts/check-template.sh \
                test-scripts/check-testcontent.sh \
                test-scripts/check-testcontent-endtime.sh \
                test-scripts/check-testcontent-exclude.sh \
                test-scripts/check-addressprefix.sh \
                test-scripts/inspector-outputs.sh \
                test-scripts/output-size-limit.sh \
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
                test-scripts/verify-cbor05.sh \
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

dist_check_DATA = doc/c-dns.cddl \
                  test-scripts/GeoLite2-ASN.mmdb.xz \
                  test-scripts/GeoLite2-City.mmdb.xz \
                  test-scripts/dns.pcap.xz \
                  test-scripts/dnscap.pcap.xz \
                  test-scripts/gold.pcap.xz \
                  test-scripts/gold.cbor.xz \
                  test-scripts/gold.cbor02.xz \
                  test-scripts/gold.cbor05.xz \
                  test-scripts/gold.pcap.info \
                  test-scripts/malformed.pcap.xz \
                  test-scripts/matching.pcap.xz \
                  test-scripts/oldfmtgold.pcap.xz \
                  test-scripts/testcontent.pcap.xz \
                  test-scripts/testcontent.diag \
                  test-scripts/testcontent-endtime.diag \
                  test-scripts/testcontent-exclude.conf \
                  test-scripts/testcontent-exclude.diag \
                  test-scripts/testcontent-exclude-sig.conf \
                  test-scripts/testcontent-exclude-sig.diag \
                  test-scripts/testcontent-exclude-sigflags.conf \
                  test-scripts/testcontent-exclude-sigflags.diag \
                  test-scripts/testcontent.debugqr \
                  test-scripts/addressprefix.diag \
                  test-scripts/addressprefix.debugqr \
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
                  test-scripts/template.dump \
                  test-scripts/template.pcap \
                  test-scripts/test-csv.tpl \
                  test-scripts/test-block.tpl \
                  test-scripts/test.defaults


EXTRA_DIST = getversion.sh .version

check_DATA = GeoLite2-ASN.mmdb \
             GeoLite2-City.mmdb \
             dns.pcap \
             dnscap.pcap \
             gold.pcap \
             gold.cbor \
             gold.cbor02 \
             gold.cbor05 \
             malformed.pcap \
             matching.pcap \
             oldfmtgold.pcap \
             testcontent.pcap \
             unmatched.pcap \
             nsd-live.dump \
             nsd-live.raw.pcap \
             nsd-live.ignored.pcap \
             knot-live.raw.pcap \
             knot-live.ignored.pcap

CLEANFILES = $(check_DATA) $(dist_man_MANS) \
	     $(common_doc_sources) \
	     $(user_guide_sources) \
	     etc/compactor.conf \
	     doc/user-guide.html doc/user-guide.pdf \
	     doc/inspector.adoc doc/compactor.adoc

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

AM_CPPFLAGS = -I$(srcdir)/src $(BOOST_CPPFLAGS) \
	      -DCONFFILE=\"$(conffile)\" \
	      -DEXCLUDESFILE=\"$(excludesfile)\" \
	      -DDEFAULTSFILE=\"$(defaultsfile)\" \
              $(OPENSSL_INCLUDES) -DGEOIPDIR=\"$(geoipdir)\"

doc/user-guide.html: $(user_guide_sources) etc/compactor.conf etc/excluded_fields.conf.sample etc/default_values.conf
doc/user-guide.pdf: $(user_guide_sources) etc/compactor.conf etc/excluded_fields.conf.sample etc/default_values.conf

doc/compactor.1: $(common_doc_sources)
doc/inspector.1: $(common_doc_sources)

README.html: README.adoc ; @ASCIIDOC@ -b html5 -d article -o $@ $<

.PHONY: user-guide user-guide-html user-guide-pdf manpages

user-guide : user-guide-html user-guide-pdf
user-guide-html : doc/user-guide.html
user-guide-pdf : doc/user-guide.pdf
manpages: $(dist_man_MANS)

# To speed builds, build common files into a static library.
noinst_LIBRARIES = libcdns.a

libcdns_a_headers = \
        src/addressevent.hpp \
        src/baseoutputwriter.hpp \
        src/bytestring.hpp \
        src/capturedns.hpp \
        src/cbordecoder.hpp \
        src/cborencoder.hpp \
        src/blockcbor.hpp \
        src/blockcbordata.hpp \
        src/configuration.hpp \
        src/dnsmessage.hpp \
        src/ipaddress.hpp \
        src/log.hpp \
        src/makeunique.hpp \
        src/no-register-warning.hpp \
        src/pseudoanonymise.hpp \
        src/queryresponse.hpp \
        src/rotatingfilename.hpp \
        src/streamwriter.hpp \
        src/util.hpp

libcdns_a_SOURCES = \
        $(libcdns_a_headers) \
        src/baseoutputwriter.cpp \
        src/bytestring.cpp \
        src/capturedns.cpp \
        src/cbordecoder.cpp \
        src/cborencoder.cpp \
        src/blockcbor.cpp \
        src/blockcbordata.cpp \
        src/configuration.cpp \
        src/dnsmessage.cpp \
        src/ipaddress.cpp \
        src/log.cpp \
        src/pseudoanonymise.cpp \
        src/rotatingfilename.cpp \
        src/streamwriter.cpp \
	src/util.cpp

libcdns_a_CXXFLAGS = -DBOOST_LOG_DYN_LINK

compactor_headers = \
        src/blockcborwriter.hpp \
        src/channel.hpp \
        src/matcher.hpp \
        src/nocopypacket.hpp \
        src/packetstatistics.hpp \
        src/packetstream.hpp \
        src/pcapwriter.hpp \
        src/sniffers.hpp

inspector_headers = \
        src/backend.hpp \
        src/blockcborreader.hpp \
        src/geoip.hpp \
        src/pcapwriter.hpp \
        src/template-backend.hpp

# _internal_test items work by #including the corresponding .cpp to get
# access to its internals. You can't have the _internal_test.cpp and the .cpp
# in the executable because you'll get duplicate definitions and linker
# complaints.
compactor_src_with_internal_tests = \
        src/matcher.cpp

compactor_src_without_internal_tests = \
        src/blockcborwriter.cpp \
        src/packetstream.cpp \
        src/sniffers.cpp

compactor_SOURCES = \
        $(compactor_headers) \
        $(compactor_src_without_internal_tests) \
        $(compactor_src_with_internal_tests) \
        src/compactor.cpp

compactor_CXXFLAGS = @PTHREAD_CFLAGS@ -DBOOST_LOG_DYN_LINK

compactor_LDADD = \
        libcdns.a \
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
        tests/catch.hpp \
        tests/catch_main.cpp \
        $(compactor_src_without_internal_tests) \
        tests/baseoutputwriter_test.cpp \
        tests/capturedns_test.cpp \
        tests/cbordecoder_test.cpp \
        tests/cborencoder_test.cpp \
        tests/channel_test.cpp \
        tests/blockcbor_test.cpp \
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
        libcdns.a \
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
        src/blockcborreader.cpp \
        src/geoip.cpp \
        src/inspector.cpp \
        src/template-backend.cpp

inspector_CXXFLAGS = @PTHREAD_CFLAGS@ -DBOOST_LOG_DYN_LINK
inspector_LDADD = \
        libcdns.a \
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
	--relative-paths=$(srcdir) \
        --suppressions-list=$(srcdir)/cppcheck-suppressions.txt
CPPCHECK_FLAGS = -U DLT_PKTAP

cppcheck: ; $(CPPCHECK_CMD) $(CPPCHECK_INCLUDE_DIRS) $(CPPCHECK_FLAGS) --enable=all $(CPPCHECK_DIRS)

@DX_RULES@
