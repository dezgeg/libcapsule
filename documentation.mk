# ============================================================================
# standalone man pages from docbook source:
XSLTPROC_FLAGS = \
        --nonet \
        --stringparam man.output.quietly 1 \
        --stringparam funcsynopsis.style ansi \
        --stringparam man.th.extra1.suppress 1 \
        --stringparam man.authors.section.enabled 1 \
        --stringparam man.copyright.section.enabled 0

XSLT_DOMAIN = docbook.sourceforge.net
XSLT_MAN = http://$(XSLT_DOMAIN)/release/xsl/current/manpages/docbook.xsl
XSLT_CAPARGS = --stringparam fsinfo "\#include <capsule.h>" --stringparam target
XSLTPROC_STD = $(XSLTPROC) $(XSLTPROC_FLAGS)

%.1: doc/%.xml
	$(AM_V_GEN) $(XSLTPROC_STD) $(XSLT_MAN) $<

xml/capsule.xml: docs

%.3.xml: xml/capsule.xml doc/devhelp2man.xslt
	$(AM_V_GEN) $(XSLTPROC_STD) $(XSLT_CAPARGS) $* doc/devhelp2man.xslt $< > $@

%.3: %.3.xml
	$(AM_V_GEN) $(XSLTPROC_STD) $(XSLT_MAN) $<

man_MANS    = capsule-init-project.1 capsule-mkstublib.1
man_MANS   += capsule_dlmopen.3
man_MANS   += capsule_init.3
man_MANS   += capsule_relocate.3
man_MANS   += capsule_shim_dlopen.3

CLEANFILES += $(man_MANS)
