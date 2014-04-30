//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The HTTPRequestHeaderFieldsType captures parsed HTTP request header fields.
 * 
 * <p>Java class for HTTPResponseHeaderFieldsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="HTTPResponseHeaderFieldsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Access_Control_Allow_Origin" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Accept_Ranges" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Age" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Cache_Control" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Connection" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Encoding" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Language" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Length" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Location" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_MD5" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Disposition" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Range" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Content_Type" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Date" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="ETag" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Expires" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Last_Modified" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Link" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Location" type="{http://cybox.mitre.org/objects#URIObject-2}URIObjectType" minOccurs="0"/>
 *         &lt;element name="P3P" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Pragma" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Proxy_Authenticate" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Refresh" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Retry_After" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Server" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Set_Cookie" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Strict_Transport_Security" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Trailer" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Transfer_Encoding" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Vary" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Via" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Warning" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="WWW_Authenticate" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="X_Frame_Options" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="X_XSS_Protection" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="X_Content_Type_Options" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="X_Powered_By" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="X_UA_Compatible" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "HTTPResponseHeaderFieldsType", namespace = "http://cybox.mitre.org/objects#HTTPSessionObject-2", propOrder = {
    "accessControlAllowOrigin",
    "acceptRanges",
    "age",
    "cacheControl",
    "connection",
    "contentEncoding",
    "contentLanguage",
    "contentLength",
    "contentLocation",
    "contentMD5",
    "contentDisposition",
    "contentRange",
    "contentType",
    "date",
    "eTag",
    "expires",
    "lastModified",
    "link",
    "location",
    "p3P",
    "pragma",
    "proxyAuthenticate",
    "refresh",
    "retryAfter",
    "server",
    "setCookie",
    "strictTransportSecurity",
    "trailer",
    "transferEncoding",
    "vary",
    "via",
    "warning",
    "wwwAuthenticate",
    "xFrameOptions",
    "xxssProtection",
    "xContentTypeOptions",
    "xPoweredBy",
    "xuaCompatible"
})
public class HTTPResponseHeaderFieldsType {

    @XmlElement(name = "Access_Control_Allow_Origin")
    protected StringObjectPropertyType accessControlAllowOrigin;
    @XmlElement(name = "Accept_Ranges")
    protected StringObjectPropertyType acceptRanges;
    @XmlElement(name = "Age")
    protected IntegerObjectPropertyType age;
    @XmlElement(name = "Cache_Control")
    protected StringObjectPropertyType cacheControl;
    @XmlElement(name = "Connection")
    protected StringObjectPropertyType connection;
    @XmlElement(name = "Content_Encoding")
    protected StringObjectPropertyType contentEncoding;
    @XmlElement(name = "Content_Language")
    protected StringObjectPropertyType contentLanguage;
    @XmlElement(name = "Content_Length")
    protected IntegerObjectPropertyType contentLength;
    @XmlElement(name = "Content_Location")
    protected StringObjectPropertyType contentLocation;
    @XmlElement(name = "Content_MD5")
    protected StringObjectPropertyType contentMD5;
    @XmlElement(name = "Content_Disposition")
    protected StringObjectPropertyType contentDisposition;
    @XmlElement(name = "Content_Range")
    protected StringObjectPropertyType contentRange;
    @XmlElement(name = "Content_Type")
    protected StringObjectPropertyType contentType;
    @XmlElement(name = "Date")
    protected DateTimeObjectPropertyType date;
    @XmlElement(name = "ETag")
    protected StringObjectPropertyType eTag;
    @XmlElement(name = "Expires")
    protected DateTimeObjectPropertyType expires;
    @XmlElement(name = "Last_Modified")
    protected DateTimeObjectPropertyType lastModified;
    @XmlElement(name = "Link")
    protected StringObjectPropertyType link;
    @XmlElement(name = "Location")
    protected URIObjectType location;
    @XmlElement(name = "P3P")
    protected StringObjectPropertyType p3P;
    @XmlElement(name = "Pragma")
    protected StringObjectPropertyType pragma;
    @XmlElement(name = "Proxy_Authenticate")
    protected StringObjectPropertyType proxyAuthenticate;
    @XmlElement(name = "Refresh")
    protected StringObjectPropertyType refresh;
    @XmlElement(name = "Retry_After")
    protected IntegerObjectPropertyType retryAfter;
    @XmlElement(name = "Server")
    protected StringObjectPropertyType server;
    @XmlElement(name = "Set_Cookie")
    protected StringObjectPropertyType setCookie;
    @XmlElement(name = "Strict_Transport_Security")
    protected StringObjectPropertyType strictTransportSecurity;
    @XmlElement(name = "Trailer")
    protected StringObjectPropertyType trailer;
    @XmlElement(name = "Transfer_Encoding")
    protected StringObjectPropertyType transferEncoding;
    @XmlElement(name = "Vary")
    protected StringObjectPropertyType vary;
    @XmlElement(name = "Via")
    protected StringObjectPropertyType via;
    @XmlElement(name = "Warning")
    protected StringObjectPropertyType warning;
    @XmlElement(name = "WWW_Authenticate")
    protected StringObjectPropertyType wwwAuthenticate;
    @XmlElement(name = "X_Frame_Options")
    protected StringObjectPropertyType xFrameOptions;
    @XmlElement(name = "X_XSS_Protection")
    protected StringObjectPropertyType xxssProtection;
    @XmlElement(name = "X_Content_Type_Options")
    protected StringObjectPropertyType xContentTypeOptions;
    @XmlElement(name = "X_Powered_By")
    protected StringObjectPropertyType xPoweredBy;
    @XmlElement(name = "X_UA_Compatible")
    protected StringObjectPropertyType xuaCompatible;

    /**
     * Gets the value of the accessControlAllowOrigin property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getAccessControlAllowOrigin() {
        return accessControlAllowOrigin;
    }

    /**
     * Sets the value of the accessControlAllowOrigin property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setAccessControlAllowOrigin(StringObjectPropertyType value) {
        this.accessControlAllowOrigin = value;
    }

    /**
     * Gets the value of the acceptRanges property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getAcceptRanges() {
        return acceptRanges;
    }

    /**
     * Sets the value of the acceptRanges property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setAcceptRanges(StringObjectPropertyType value) {
        this.acceptRanges = value;
    }

    /**
     * Gets the value of the age property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getAge() {
        return age;
    }

    /**
     * Sets the value of the age property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setAge(IntegerObjectPropertyType value) {
        this.age = value;
    }

    /**
     * Gets the value of the cacheControl property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCacheControl() {
        return cacheControl;
    }

    /**
     * Sets the value of the cacheControl property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCacheControl(StringObjectPropertyType value) {
        this.cacheControl = value;
    }

    /**
     * Gets the value of the connection property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getConnection() {
        return connection;
    }

    /**
     * Sets the value of the connection property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setConnection(StringObjectPropertyType value) {
        this.connection = value;
    }

    /**
     * Gets the value of the contentEncoding property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentEncoding() {
        return contentEncoding;
    }

    /**
     * Sets the value of the contentEncoding property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentEncoding(StringObjectPropertyType value) {
        this.contentEncoding = value;
    }

    /**
     * Gets the value of the contentLanguage property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentLanguage() {
        return contentLanguage;
    }

    /**
     * Sets the value of the contentLanguage property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentLanguage(StringObjectPropertyType value) {
        this.contentLanguage = value;
    }

    /**
     * Gets the value of the contentLength property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getContentLength() {
        return contentLength;
    }

    /**
     * Sets the value of the contentLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setContentLength(IntegerObjectPropertyType value) {
        this.contentLength = value;
    }

    /**
     * Gets the value of the contentLocation property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentLocation() {
        return contentLocation;
    }

    /**
     * Sets the value of the contentLocation property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentLocation(StringObjectPropertyType value) {
        this.contentLocation = value;
    }

    /**
     * Gets the value of the contentMD5 property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentMD5() {
        return contentMD5;
    }

    /**
     * Sets the value of the contentMD5 property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentMD5(StringObjectPropertyType value) {
        this.contentMD5 = value;
    }

    /**
     * Gets the value of the contentDisposition property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentDisposition() {
        return contentDisposition;
    }

    /**
     * Sets the value of the contentDisposition property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentDisposition(StringObjectPropertyType value) {
        this.contentDisposition = value;
    }

    /**
     * Gets the value of the contentRange property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentRange() {
        return contentRange;
    }

    /**
     * Sets the value of the contentRange property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentRange(StringObjectPropertyType value) {
        this.contentRange = value;
    }

    /**
     * Gets the value of the contentType property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getContentType() {
        return contentType;
    }

    /**
     * Sets the value of the contentType property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setContentType(StringObjectPropertyType value) {
        this.contentType = value;
    }

    /**
     * Gets the value of the date property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getDate() {
        return date;
    }

    /**
     * Sets the value of the date property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setDate(DateTimeObjectPropertyType value) {
        this.date = value;
    }

    /**
     * Gets the value of the eTag property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getETag() {
        return eTag;
    }

    /**
     * Sets the value of the eTag property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setETag(StringObjectPropertyType value) {
        this.eTag = value;
    }

    /**
     * Gets the value of the expires property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getExpires() {
        return expires;
    }

    /**
     * Sets the value of the expires property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setExpires(DateTimeObjectPropertyType value) {
        this.expires = value;
    }

    /**
     * Gets the value of the lastModified property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getLastModified() {
        return lastModified;
    }

    /**
     * Sets the value of the lastModified property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setLastModified(DateTimeObjectPropertyType value) {
        this.lastModified = value;
    }

    /**
     * Gets the value of the link property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getLink() {
        return link;
    }

    /**
     * Sets the value of the link property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setLink(StringObjectPropertyType value) {
        this.link = value;
    }

    /**
     * Gets the value of the location property.
     * 
     * @return
     *     possible object is
     *     {@link URIObjectType }
     *     
     */
    public URIObjectType getLocation() {
        return location;
    }

    /**
     * Sets the value of the location property.
     * 
     * @param value
     *     allowed object is
     *     {@link URIObjectType }
     *     
     */
    public void setLocation(URIObjectType value) {
        this.location = value;
    }

    /**
     * Gets the value of the p3P property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getP3P() {
        return p3P;
    }

    /**
     * Sets the value of the p3P property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setP3P(StringObjectPropertyType value) {
        this.p3P = value;
    }

    /**
     * Gets the value of the pragma property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getPragma() {
        return pragma;
    }

    /**
     * Sets the value of the pragma property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setPragma(StringObjectPropertyType value) {
        this.pragma = value;
    }

    /**
     * Gets the value of the proxyAuthenticate property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getProxyAuthenticate() {
        return proxyAuthenticate;
    }

    /**
     * Sets the value of the proxyAuthenticate property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setProxyAuthenticate(StringObjectPropertyType value) {
        this.proxyAuthenticate = value;
    }

    /**
     * Gets the value of the refresh property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getRefresh() {
        return refresh;
    }

    /**
     * Sets the value of the refresh property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setRefresh(StringObjectPropertyType value) {
        this.refresh = value;
    }

    /**
     * Gets the value of the retryAfter property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getRetryAfter() {
        return retryAfter;
    }

    /**
     * Sets the value of the retryAfter property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setRetryAfter(IntegerObjectPropertyType value) {
        this.retryAfter = value;
    }

    /**
     * Gets the value of the server property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getServer() {
        return server;
    }

    /**
     * Sets the value of the server property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setServer(StringObjectPropertyType value) {
        this.server = value;
    }

    /**
     * Gets the value of the setCookie property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getSetCookie() {
        return setCookie;
    }

    /**
     * Sets the value of the setCookie property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setSetCookie(StringObjectPropertyType value) {
        this.setCookie = value;
    }

    /**
     * Gets the value of the strictTransportSecurity property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getStrictTransportSecurity() {
        return strictTransportSecurity;
    }

    /**
     * Sets the value of the strictTransportSecurity property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setStrictTransportSecurity(StringObjectPropertyType value) {
        this.strictTransportSecurity = value;
    }

    /**
     * Gets the value of the trailer property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getTrailer() {
        return trailer;
    }

    /**
     * Sets the value of the trailer property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setTrailer(StringObjectPropertyType value) {
        this.trailer = value;
    }

    /**
     * Gets the value of the transferEncoding property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getTransferEncoding() {
        return transferEncoding;
    }

    /**
     * Sets the value of the transferEncoding property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setTransferEncoding(StringObjectPropertyType value) {
        this.transferEncoding = value;
    }

    /**
     * Gets the value of the vary property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getVary() {
        return vary;
    }

    /**
     * Sets the value of the vary property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setVary(StringObjectPropertyType value) {
        this.vary = value;
    }

    /**
     * Gets the value of the via property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getVia() {
        return via;
    }

    /**
     * Sets the value of the via property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setVia(StringObjectPropertyType value) {
        this.via = value;
    }

    /**
     * Gets the value of the warning property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getWarning() {
        return warning;
    }

    /**
     * Sets the value of the warning property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setWarning(StringObjectPropertyType value) {
        this.warning = value;
    }

    /**
     * Gets the value of the wwwAuthenticate property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getWWWAuthenticate() {
        return wwwAuthenticate;
    }

    /**
     * Sets the value of the wwwAuthenticate property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setWWWAuthenticate(StringObjectPropertyType value) {
        this.wwwAuthenticate = value;
    }

    /**
     * Gets the value of the xFrameOptions property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getXFrameOptions() {
        return xFrameOptions;
    }

    /**
     * Sets the value of the xFrameOptions property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setXFrameOptions(StringObjectPropertyType value) {
        this.xFrameOptions = value;
    }

    /**
     * Gets the value of the xxssProtection property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getXXSSProtection() {
        return xxssProtection;
    }

    /**
     * Sets the value of the xxssProtection property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setXXSSProtection(StringObjectPropertyType value) {
        this.xxssProtection = value;
    }

    /**
     * Gets the value of the xContentTypeOptions property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getXContentTypeOptions() {
        return xContentTypeOptions;
    }

    /**
     * Sets the value of the xContentTypeOptions property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setXContentTypeOptions(StringObjectPropertyType value) {
        this.xContentTypeOptions = value;
    }

    /**
     * Gets the value of the xPoweredBy property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getXPoweredBy() {
        return xPoweredBy;
    }

    /**
     * Sets the value of the xPoweredBy property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setXPoweredBy(StringObjectPropertyType value) {
        this.xPoweredBy = value;
    }

    /**
     * Gets the value of the xuaCompatible property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getXUACompatible() {
        return xuaCompatible;
    }

    /**
     * Sets the value of the xuaCompatible property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setXUACompatible(StringObjectPropertyType value) {
        this.xuaCompatible = value;
    }

}
