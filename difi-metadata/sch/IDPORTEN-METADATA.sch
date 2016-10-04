<schema xmlns="http://purl.oclc.org/dsdl/schematron" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:u="utils"
  schemaVersion="iso" queryBinding="xslt2">

  <title>Rules for ID-porten metadata</title>

  <ns uri="urn:oasis:names:tc:SAML:2.0:metadata" prefix="md"/>
  <ns uri="http://www.w3.org/2000/09/xmldsig#" prefix="ds"/>
  <ns uri="utils" prefix="u"/>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyHTTP">
    <param name="url"/>
    <value-of select="substring($url, 0, 6) = 'http:'"/>
  </function>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyHTTPS">
    <param name="url"/>
    <value-of select="substring($url, 0, 7) = 'https:'"/>
  </function>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:listInList">
    <param name="values"/>
    <param name="validValues"/>

    <variable name="result" select="for $v in tokenize($values, '\s') return not(empty(index-of(tokenize($validValues, '\s'), $v)))"/>
    <value-of select="empty(index-of($result, false()))"/>
  </function>

  <pattern>
    <rule context="md:EntityDescriptor">
      <assert id="IDPORTEN-METADATA-R001" test="@entityID" flag="fatal">EntityID not set.</assert>
    </rule>
    <rule context="md:EntityDescriptor/@entityID">
      <assert id="IDPORTEN-METADATA-R002" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">EntityID not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R003" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">EntityID not HTTPS.</assert>
    </rule>
    <rule context="md:SPSSODescriptor">
      <assert id="IDPORTEN-METADATA-R010" test="md:KeyDescriptor[@use='signing']" flag="fatal">Key descriptor for signing is missing.</assert>
      <assert id="IDPORTEN-METADATA-R011" test="md:KeyDescriptor[@use='encryption']" flag="fatal">Key descriptor for encryption is missing.</assert>
      <assert id="IDPORTEN-METADATA-R012" test="@AuthnRequestsSigned = 'true'" flag="fatal">AuthnRequestsSigned MUST be supported.</assert>
      <assert id="IDPORTEN-METADATA-R013" test="@WantAssertionsSigned = 'true'" flag="fatal">WantAssertionsSigned MUST be supported.</assert>
    </rule>
    <rule context="md:SPSSODescriptor/@protocolSupportEnumeration">
      <assert id="IDPORTEN-METADATA-R014" test="false() or xs:boolean(u:listInList(., 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol'))" flag="fatal">List of supported protocols contains invalid protocols.</assert>
    </rule>
    <rule context="ds:X509Data">
      <assert id="IDPORTEN-METADATA-R020" test="ds:X509Certificate" flag="fatal">Only X509 certificate allowed.</assert>
    </rule>
    <rule context="md:SingleLogoutService">
      <!-- <assert id="IDPORTEN-METADATA-R030" test="@Location" flag="fatal">Logout service location set.</assert> -->
    </rule>
    <rule context="md:SingleLogoutService/@Location">
      <assert id="IDPORTEN-METADATA-R031" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">Location of SingleLogoutService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R032" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">Location of SingleLogoutService is not HTTPS.</assert>
    </rule>
    <rule context="md:SingleLogoutService/@ResponseLocation">
      <assert id="IDPORTEN-METADATA-R033" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">ResponseLocation of SingleLogoutService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R034" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">ResponseLocation of SingleLogoutService is not HTTPS.</assert>
    </rule>
    <rule context="md:SingleLogoutService/@Binding">
      <assert id="IDPORTEN-METADATA-R035" test="index-of(tokenize('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', '\s'), string(.))" flag="fatal">Invalid binding value for SingleLogoutService.</assert>
    </rule>
    <rule context="md:AssertionConsumerService">
      <!-- <assert id="IDPORTEN-METADATA-R040" test="@Location" flag="fatal">Consumer service location set.</assert> -->
    </rule>
    <rule context="md:AssertionConsumerService/@Location">
      <assert id="IDPORTEN-METADATA-R041" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">Location of AssertionConsumerService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R042" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">Location of AssertionConsumerService is not HTTPS.</assert>
    </rule>
    <rule context="md:AssertionConsumerService/@ResponseLocation">
      <assert id="IDPORTEN-METADATA-R043" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">ResponseLocation of AssertionConsumerService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R044" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">ResponseLocation of AssertionConsumerService is not HTTPS.</assert>
    </rule>
    <rule context="md:AssertionConsumerService/@Binding">
      <assert id="IDPORTEN-METADATA-R045" test="index-of(tokenize('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', '\s'), string(.))" flag="fatal">Invalid binding value for AssertionConsumerService.</assert>
    </rule>
  </pattern>
</schema>
