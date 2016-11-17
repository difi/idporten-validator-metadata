<schema xmlns="http://purl.oclc.org/dsdl/schematron" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:u="utils"
  schemaVersion="iso" queryBinding="xslt2">

  <title>Rules for ID-porten metadata</title>

  <ns uri="urn:oasis:names:tc:SAML:2.0:metadata" prefix="md"/>
  <ns uri="http://www.w3.org/2000/09/xmldsig#" prefix="ds"/>
  <ns uri="http://www.w3.org/2001/04/xmlenc#" prefix="xenc"/>
  <ns uri="utils" prefix="u"/>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyHTTP">
    <param name="url"/>
    <value-of select="substring($url, 0, 6) = 'http:'"/>
  </function>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyHTTPS">
    <param name="url"/>
    <value-of select="substring($url, 0, 7) = 'https:'"/>
  </function>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyUrl">
    <param name="url"/>
    <value-of select="not(matches($url, '[ ]'))"/>
  </function>

  <function xmlns="http://www.w3.org/1999/XSL/Transform" name="u:verifyHostname">
    <param name="url"/>
    <variable name="hostname" select="lower-case(tokenize($url, '[/:]')[4])"/>
    <value-of select="matches($hostname, '^[a-z0-9\-\.]+$') and not($hostname = 'localhost') and not(matches($hostname,'\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}'))"/>
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
      <assert id="IDPORTEN-METADATA-R002" test="not(matches(lower-case(.), '[æøå ]'))" flag="fatal">Attribute entityID contains illegal characters.</assert>
    </rule>
    <rule context="md:SPSSODescriptor">
      <assert id="IDPORTEN-METADATA-R010" test="md:KeyDescriptor[@use='signing']" flag="fatal">Key descriptor for signing is missing.</assert>
      <assert id="IDPORTEN-METADATA-R011" test="md:KeyDescriptor[@use='encryption']" flag="fatal">Key descriptor for encryption is missing.</assert>
      <assert id="IDPORTEN-METADATA-R012" test="@AuthnRequestsSigned = 'true'" flag="fatal">AuthnRequestsSigned MUST be supported.</assert>
      <assert id="IDPORTEN-METADATA-R013" test="@WantAssertionsSigned = 'true'" flag="fatal">WantAssertionsSigned MUST be supported.</assert>
      <assert id="IDPORTEN-METADATA-R015" test="md:SingleLogoutService" flag="fatal">Must specify SingleLogoutService.</assert>
      <assert id="IDPORTEN-METADATA-R016" test="md:NameIDFormat" flag="fatal">Must specify NameIDFormat.</assert>
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
      <assert id="IDPORTEN-METADATA-R036" test="xs:boolean(u:verifyHostname(.)) and xs:boolean(u:verifyUrl(.))" flag="warning">Must use a proper hostname and contain no space(s).</assert>
    </rule>
    <rule context="md:SingleLogoutService/@ResponseLocation">
      <assert id="IDPORTEN-METADATA-R033" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">ResponseLocation of SingleLogoutService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R034" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">ResponseLocation of SingleLogoutService is not HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R037" test="xs:boolean(u:verifyHostname(.)) and xs:boolean(u:verifyUrl(.))" flag="warning">Must use a proper hostname and contain no space(s).</assert>
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
      <assert id="IDPORTEN-METADATA-R045" test="xs:boolean(u:verifyHostname(.)) and xs:boolean(u:verifyUrl(.))" flag="warning">Must use a proper hostname and contain no space(s).</assert>
    </rule>
    <rule context="md:AssertionConsumerService/@ResponseLocation">
      <assert id="IDPORTEN-METADATA-R043" test="xs:boolean(u:verifyHTTP(.)) or xs:boolean(u:verifyHTTPS(.))" flag="fatal">ResponseLocation of AssertionConsumerService is not HTTP or HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R044" test="not(xs:boolean(u:verifyHTTP(.))) or xs:boolean(u:verifyHTTPS(.))" flag="warning">ResponseLocation of AssertionConsumerService is not HTTPS.</assert>
      <assert id="IDPORTEN-METADATA-R046" test="xs:boolean(u:verifyHostname(.)) and xs:boolean(u:verifyUrl(.))" flag="warning">Must use a proper hostname and contain no space(s).</assert>
    </rule>
    <rule context="md:AssertionConsumerService/@Binding">
      <assert id="IDPORTEN-METADATA-R045" test="index-of(tokenize('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', '\s'), string(.))" flag="fatal">Invalid binding value (<value-of select="." />) for AssertionConsumerService.</assert>
    </rule>
    <rule context="md:NameIDFormat">
      <assert id="IDPORTEN-METADATA-R050" test="index-of(tokenize('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent urn:oasis:names:tc:SAML:2.0:nameid-format:transient', '\s'), .)" flag="warning">Invalid value (<value-of select="." />) for NameIDFormat.</assert>
    </rule>
    <rule context="md:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc']">
      <assert id="IDPORTEN-METADATA-R062" test="index-of(tokenize('128 192 256', '\s'), string(xenc:KeySize))" flag="fatal">Key size <value-of select="xenc:KeySize"/> is not a valid value.</assert>
    </rule>
    <rule context="md:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#tripledes-cbc']">
      <assert id="IDPORTEN-METADATA-R063" test="index-of(tokenize('0 112 168', '\s'), string(xenc:KeySize))" flag="fatal">Key size <value-of select="xenc:KeySize"/> is not a valid value.</assert>
    </rule>
    <rule context="md:EncryptionMethod">
      <assert id="IDPORTEN-METADATA-R060" test="@Algorithm" flag="fatal">Encryption algorithm not set.</assert>
      <assert id="IDPORTEN-METADATA-R061" test="not(@Algorithm)" flag="fatal">Invalid algorithm '<value-of select="@Algorithm"/>'.</assert>
    </rule>
  </pattern>
</schema>
