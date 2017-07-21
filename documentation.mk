# ============================================================================
# standalone man pages from docbook source:
XSLTPROC_FLAGS = \
        --nonet \
        --stringparam man.output.quietly 1 \
        --stringparam funcsynopsis.style ansi \
        --stringparam man.th.extra1.suppress 1 \
        --stringparam man.authors.section.enabled 0 \
        --stringparam man.copyright.section.enabled 0

XSLT_MAN = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

%.1: doc/%.xml
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) $(XSLT_MAN) $<

%.3: xml/%.xml docs
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) $(XSLT_MAN) $<
# ============================================================================
# gtk-doc configuration: see /usr/share/doc/gtk-doc-tools/examples/Makefile.am
DOC_MODULE           = libcapsule
DOC_MAIN_SGML_FILE   = $(DOC_MODULE)-docs.xml
DOC_SOURCE_DIR       = capsule
SCAN_OPTIONS         =
MKDB_OPTIONS         = --xml-mode --output-format=xml
MKTMPL_OPTIONS       =
MKHTML_OPTIONS       =
FIXXREF_OPTIONS      =
HFILE_GLOB           =
CFILE_GLOB           =
EXTRA_HFILES         =
IGNORE_HFILES        =
HTML_IMAGES          =
content_files        =
expand_content_files =
GTKDOC_CFLAGS        =
GTKDOC_LIBS          =

-include gtk-doc.make

# ============================================================================
man_MANS    = capsule-init-project.1 capsule-mkstublib.1
CLEANFILES += $(man_MANS)
