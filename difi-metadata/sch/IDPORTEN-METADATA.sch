<schema xmlns="http://purl.oclc.org/dsdl/schematron"
  schemaVersion="iso" queryBinding="xslt2">

  <title>Rules for ID-porten metadata</title>

  <ns uri="urn:oasis:names:tc:SAML:2.0:metadata" prefix="md"/>
  <ns uri="http://www.w3.org/2000/09/xmldsig#" prefix="ds"/>

  <pattern>
    <rule context="md:SPSSODescriptor">
      <assert id="IDPORTEN-METADATA-R001" test="md:KeyDescriptor[@use='encryption']" flag="fatal">Key descriptor for encryption is missing.</assert>
    </rule>
  </pattern>
</schema>
