<!-- Based on callouts.xsl. Fixes man page callouts for DocBook 1.72 XSL -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:param name="man.output.quietly" select="1"/>
<xsl:param name="refentry.meta.get.quietly" select="1"/>

<xsl:template match="co">
	<xsl:value-of select="concat('&#x2593;fB(',substring-after(@id,'-'),')&#x2593;fR')"/>
</xsl:template>
<xsl:template match="calloutlist">
	<xsl:text>&#x2302;sp&#10;</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>&#10;</xsl:text>
</xsl:template>
<xsl:template match="callout">
	<xsl:value-of select="concat('&#x2593;fB',substring-after(@arearefs,'-'),'. &#x2593;fR')"/>
	<xsl:apply-templates/>
	<xsl:text>&#x2302;br&#10;</xsl:text>
</xsl:template>

</xsl:stylesheet>
