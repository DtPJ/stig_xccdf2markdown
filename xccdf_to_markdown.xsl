<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:cdf="http://checklists.nist.gov/xccdf/1.1">

  <xsl:output method="text" encoding="UTF-8"/>

  <!-- Root -->
  <xsl:template match="/">
    <xsl:apply-templates select="cdf:Benchmark"/>
  </xsl:template>

  <!-- Benchmark -->
  <xsl:template match="cdf:Benchmark">
<xsl:text>---&#10;</xsl:text>
<xsl:text>title: </xsl:text><xsl:value-of select="cdf:title"/><xsl:text>&#10;</xsl:text>
<xsl:text>version: </xsl:text><xsl:value-of select="cdf:version"/><xsl:text>&#10;</xsl:text>

<xsl:text>release: </xsl:text>
<xsl:choose>
  <xsl:when test="cdf:plain-text[@id='release-info']">
    <xsl:variable name="rel" select="substring-after(cdf:plain-text[@id='release-info'],'Release:')"/>
    <xsl:variable name="trimmedRel" select="normalize-space($rel)"/>
    <xsl:value-of select="substring-before(concat($trimmedRel,' '),' ')"/>
  </xsl:when>
</xsl:choose>
<xsl:text>&#10;</xsl:text>

<xsl:text>date: </xsl:text>
<xsl:choose>
  <xsl:when test="cdf:status/@date">
    <xsl:variable name="trimmedDate" select="normalize-space(cdf:status/@date)"/>
    <xsl:value-of select="substring-before(concat($trimmedDate,' '),' ')"/>
  </xsl:when>
</xsl:choose>
<xsl:text>&#10;</xsl:text>

<xsl:text>tags:&#10;</xsl:text>
<xsl:call-template name="emit-tags">
  <xsl:with-param name="text" select="cdf:title"/>
</xsl:call-template>
<xsl:text>  - stig&#10;</xsl:text>
<xsl:text>---&#10;&#10;</xsl:text>

# <xsl:value-of select="cdf:title"/>
<xsl:text>&#10;&#10;</xsl:text>
**Version:** <xsl:value-of select="cdf:version"/>
<xsl:text>&#10;</xsl:text>
**Release Info:** <xsl:value-of select="cdf:plain-text[@id='release-info']"/>
<xsl:text>&#10;&#10;</xsl:text>
**Description:** <xsl:value-of select="cdf:description"/>
<xsl:text>&#10;&#10;</xsl:text>
<xsl:apply-templates select="cdf:Group"/>
  </xsl:template>

  <!-- Group -->
  <xsl:template match="cdf:Group">
## Group: <xsl:value-of select="@id"/> – <xsl:value-of select="cdf:title"/>
<xsl:text>&#10;&#10;</xsl:text>
<xsl:apply-templates select="cdf:Rule"/>
  </xsl:template>

  <!-- Rule -->
  <xsl:template match="cdf:Rule">
### <xsl:value-of select="cdf:title"/>
<xsl:text>&#10;&#10;</xsl:text>

#### Rule ID
<xsl:value-of select="@id"/>
<xsl:text>&#10;</xsl:text>

#### STIG-ID
<xsl:value-of select="cdf:version"/>
<xsl:text>&#10;</xsl:text>

#### Severity
<xsl:choose>
  <xsl:when test="@severity='high'">CAT I</xsl:when>
  <xsl:when test="@severity='medium'">CAT II</xsl:when>
  <xsl:when test="@severity='low'">CAT III</xsl:when>
  <xsl:otherwise><xsl:value-of select="@severity"/></xsl:otherwise>
</xsl:choose>
<xsl:text>&#10;</xsl:text>

#### Vulnerability Discussion
<xsl:value-of select="substring-after(substring-before(cdf:description,'&lt;/VulnDiscussion&gt;'),'&lt;VulnDiscussion&gt;')"/>
<xsl:text>&#10;&#10;</xsl:text>

#### Fix Text
<xsl:value-of select="cdf:fixtext"/>
<xsl:text>&#10;&#10;</xsl:text>

#### Check Content
<xsl:value-of select="cdf:check/cdf:check-content"/>
<xsl:text>&#10;&#10;</xsl:text>

<xsl:if test="cdf:ident[@system='http://cyber.mil/cci']">
#### CCI
<xsl:for-each select="cdf:ident[@system='http://cyber.mil/cci']">
- <xsl:value-of select="."/>
<xsl:text>&#10;</xsl:text>
</xsl:for-each>
<xsl:text>&#10;</xsl:text>
</xsl:if>

<xsl:if test="cdf:ident[@system='http://cyber.mil/legacy']">
#### Legacy ID
<xsl:for-each select="cdf:ident[@system='http://cyber.mil/legacy']">
- <xsl:value-of select="."/>
<xsl:text>&#10;</xsl:text>
</xsl:for-each>
<xsl:text>&#10;</xsl:text>
</xsl:if>

---
<xsl:text>&#10;&#10;</xsl:text>
  </xsl:template>

  <!-- Helper to emit tags with stop-word filtering, number merging, hyphen preservation, red-hat merge, and parenthesis handling -->
  <xsl:template name="emit-tags">
    <xsl:param name="text"/>
    <xsl:param name="prev" select="''"/>
    <xsl:variable name="lower" select="translate($text,
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      'abcdefghijklmnopqrstuvwxyz')"/>
    <xsl:choose>
      <xsl:when test="contains($lower,' ')">
        <xsl:variable name="token" select="normalize-space(substring-before($lower,' '))"/>
        <xsl:variable name="rest" select="substring-after($lower,' ')"/>
        <xsl:choose>
          <!-- merge numbers with previous token -->
          <xsl:when test="string(number($token)) != 'NaN' and string-length($prev) &gt; 0">
            <xsl:text>  - </xsl:text>
            <xsl:value-of select="concat($prev,'-',$token)"/>
            <xsl:text>&#10;</xsl:text>
            <xsl:call-template name="emit-tags">
              <xsl:with-param name="text" select="$rest"/>
            </xsl:call-template>
          </xsl:when>
          <!-- merge "red hat" into "red-hat" -->
          <xsl:when test="$token='red' and starts-with($rest,'hat')">
            <xsl:text>  - red-hat&#10;</xsl:text>
            <xsl:call-template name="emit-tags">
              <xsl:with-param name="text" select="substring-after($rest,'hat')"/>
            </xsl:call-template>
          </xsl:when>
          <!-- handle parenthesis -->
          <xsl:when test="starts-with($token,'(')">
            <xsl:variable name="inner" select="translate($token,'()','')"/>
            <xsl:text>  - </xsl:text>
            <xsl:value-of select="$inner"/>
            <xsl:text>&#10;</xsl:text>
            <xsl:call-template name="emit-tags">
              <xsl:with-param name="text" select="$rest"/>
            </xsl:call-template>
          </xsl:when>
          <xsl:otherwise>
            <!-- skip generic stop-words -->
            <xsl:if test="not($token='security' or $token='technical' or 
                              $token='implementation' or $token='guide')">
              <xsl:text>  - </xsl:text>
              <xsl:value-of select="$token"/>
              <xsl:text>&#10;</xsl:text>
              <xsl:call-template name="emit-tags">
                <xsl:with-param name="text" select="$rest"/>
                <xsl:with-param name="prev" select="$token"/>
              </xsl:call-template>
            </xsl:if>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="token" select="normalize-space($lower)"/>
        <xsl:variable name="inner" select="translate($token,'()','')"/>
        <xsl:if test="string-length($inner) &gt; 0 and 
                      not($inner='security' or $inner='technical' or 
                          $inner='implementation' or $inner='guide')">
          <xsl:text>  - </xsl:text>
          <xsl:value-of select="$inner"/>
          <xsl:text>&#10;</xsl:text>
        </xsl:if>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
