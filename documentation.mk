XSLTPROC_FLAGS = \
        --nonet \
        --stringparam man.output.quietly 1 \
        --stringparam funcsynopsis.style ansi \
        --stringparam man.th.extra1.suppress 1 \
        --stringparam man.authors.section.enabled 0 \
        --stringparam man.copyright.section.enabled 0

XSLT_MAN = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

include gtk-doc.make

%.1: doc/%.xml
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) $(XSLT_MAN) $<

man_MANS    = capsule-init-project.1 capsule-mkstublib.1
CLEANFILES += $(man_MANS)
