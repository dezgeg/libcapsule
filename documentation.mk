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

%.1: doc/%.xml
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) $(XSLT_MAN) $<

%.3: xml/%.xml docs
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) $(XSLT_MAN) $<

man_MANS    = capsule-init-project.1 capsule-mkstublib.1
CLEANFILES += $(man_MANS)
