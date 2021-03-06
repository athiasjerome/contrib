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
import org.mitre.cybox.common_2.DateObjectPropertyType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.RegionalRegistryType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The WhoisObjectType type is intended to characterize Whois information for a domain.
 * 
 * <p>Java class for WhoisObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WhoisObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Lookup_Date" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Domain_Name" type="{http://cybox.mitre.org/objects#URIObject-2}URIObjectType" minOccurs="0"/>
 *         &lt;element name="Domain_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Server_Name" type="{http://cybox.mitre.org/objects#URIObject-2}URIObjectType" minOccurs="0"/>
 *         &lt;element name="IP_Address" type="{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType" minOccurs="0"/>
 *         &lt;element name="DNSSEC" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisDNSSECTypeEnum" minOccurs="0"/>
 *         &lt;element name="Nameservers" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisNameserversType" minOccurs="0"/>
 *         &lt;element name="Status" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisStatusesType" minOccurs="0"/>
 *         &lt;element name="Updated_Date" type="{http://cybox.mitre.org/common-2}DateObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Creation_Date" type="{http://cybox.mitre.org/common-2}DateObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Expiration_Date" type="{http://cybox.mitre.org/common-2}DateObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Regional_Internet_Registry" type="{http://cybox.mitre.org/common-2}RegionalRegistryType" minOccurs="0"/>
 *         &lt;element name="Sponsoring_Registrar" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Registrar_Info" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisRegistrarInfoType" minOccurs="0"/>
 *         &lt;element name="Registrants" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisRegistrantsType" minOccurs="0"/>
 *         &lt;element name="Contact_Info" type="{http://cybox.mitre.org/objects#WhoisObject-2}WhoisContactType" minOccurs="0"/>
 *         &lt;element name="Remarks" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WhoisObjectType", namespace = "http://cybox.mitre.org/objects#WhoisObject-2", propOrder = {
    "lookupDate",
    "domainName",
    "domainID",
    "serverName",
    "ipAddress",
    "dnssec",
    "nameservers",
    "status",
    "updatedDate",
    "creationDate",
    "expirationDate",
    "regionalInternetRegistry",
    "sponsoringRegistrar",
    "registrarInfo",
    "registrants",
    "contactInfo",
    "remarks"
})
public class WhoisObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Lookup_Date")
    protected DateTimeObjectPropertyType lookupDate;
    @XmlElement(name = "Domain_Name")
    protected URIObjectType domainName;
    @XmlElement(name = "Domain_ID")
    protected StringObjectPropertyType domainID;
    @XmlElement(name = "Server_Name")
    protected URIObjectType serverName;
    @XmlElement(name = "IP_Address")
    protected AddressObjectType ipAddress;
    @XmlElement(name = "DNSSEC")
    protected WhoisDNSSECTypeEnum dnssec;
    @XmlElement(name = "Nameservers")
    protected WhoisNameserversType nameservers;
    @XmlElement(name = "Status")
    protected WhoisStatusesType status;
    @XmlElement(name = "Updated_Date")
    protected DateObjectPropertyType updatedDate;
    @XmlElement(name = "Creation_Date")
    protected DateObjectPropertyType creationDate;
    @XmlElement(name = "Expiration_Date")
    protected DateObjectPropertyType expirationDate;
    @XmlElement(name = "Regional_Internet_Registry")
    protected RegionalRegistryType regionalInternetRegistry;
    @XmlElement(name = "Sponsoring_Registrar")
    protected StringObjectPropertyType sponsoringRegistrar;
    @XmlElement(name = "Registrar_Info")
    protected WhoisRegistrarInfoType registrarInfo;
    @XmlElement(name = "Registrants")
    protected WhoisRegistrantsType registrants;
    @XmlElement(name = "Contact_Info")
    protected WhoisContactType contactInfo;
    @XmlElement(name = "Remarks")
    protected StringObjectPropertyType remarks;

    /**
     * Gets the value of the lookupDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getLookupDate() {
        return lookupDate;
    }

    /**
     * Sets the value of the lookupDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setLookupDate(DateTimeObjectPropertyType value) {
        this.lookupDate = value;
    }

    /**
     * Gets the value of the domainName property.
     * 
     * @return
     *     possible object is
     *     {@link URIObjectType }
     *     
     */
    public URIObjectType getDomainName() {
        return domainName;
    }

    /**
     * Sets the value of the domainName property.
     * 
     * @param value
     *     allowed object is
     *     {@link URIObjectType }
     *     
     */
    public void setDomainName(URIObjectType value) {
        this.domainName = value;
    }

    /**
     * Gets the value of the domainID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getDomainID() {
        return domainID;
    }

    /**
     * Sets the value of the domainID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setDomainID(StringObjectPropertyType value) {
        this.domainID = value;
    }

    /**
     * Gets the value of the serverName property.
     * 
     * @return
     *     possible object is
     *     {@link URIObjectType }
     *     
     */
    public URIObjectType getServerName() {
        return serverName;
    }

    /**
     * Sets the value of the serverName property.
     * 
     * @param value
     *     allowed object is
     *     {@link URIObjectType }
     *     
     */
    public void setServerName(URIObjectType value) {
        this.serverName = value;
    }

    /**
     * Gets the value of the ipAddress property.
     * 
     * @return
     *     possible object is
     *     {@link AddressObjectType }
     *     
     */
    public AddressObjectType getIPAddress() {
        return ipAddress;
    }

    /**
     * Sets the value of the ipAddress property.
     * 
     * @param value
     *     allowed object is
     *     {@link AddressObjectType }
     *     
     */
    public void setIPAddress(AddressObjectType value) {
        this.ipAddress = value;
    }

    /**
     * Gets the value of the dnssec property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisDNSSECTypeEnum }
     *     
     */
    public WhoisDNSSECTypeEnum getDNSSEC() {
        return dnssec;
    }

    /**
     * Sets the value of the dnssec property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisDNSSECTypeEnum }
     *     
     */
    public void setDNSSEC(WhoisDNSSECTypeEnum value) {
        this.dnssec = value;
    }

    /**
     * Gets the value of the nameservers property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisNameserversType }
     *     
     */
    public WhoisNameserversType getNameservers() {
        return nameservers;
    }

    /**
     * Sets the value of the nameservers property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisNameserversType }
     *     
     */
    public void setNameservers(WhoisNameserversType value) {
        this.nameservers = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisStatusesType }
     *     
     */
    public WhoisStatusesType getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisStatusesType }
     *     
     */
    public void setStatus(WhoisStatusesType value) {
        this.status = value;
    }

    /**
     * Gets the value of the updatedDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public DateObjectPropertyType getUpdatedDate() {
        return updatedDate;
    }

    /**
     * Sets the value of the updatedDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public void setUpdatedDate(DateObjectPropertyType value) {
        this.updatedDate = value;
    }

    /**
     * Gets the value of the creationDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public DateObjectPropertyType getCreationDate() {
        return creationDate;
    }

    /**
     * Sets the value of the creationDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public void setCreationDate(DateObjectPropertyType value) {
        this.creationDate = value;
    }

    /**
     * Gets the value of the expirationDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public DateObjectPropertyType getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets the value of the expirationDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public void setExpirationDate(DateObjectPropertyType value) {
        this.expirationDate = value;
    }

    /**
     * Gets the value of the regionalInternetRegistry property.
     * 
     * @return
     *     possible object is
     *     {@link RegionalRegistryType }
     *     
     */
    public RegionalRegistryType getRegionalInternetRegistry() {
        return regionalInternetRegistry;
    }

    /**
     * Sets the value of the regionalInternetRegistry property.
     * 
     * @param value
     *     allowed object is
     *     {@link RegionalRegistryType }
     *     
     */
    public void setRegionalInternetRegistry(RegionalRegistryType value) {
        this.regionalInternetRegistry = value;
    }

    /**
     * Gets the value of the sponsoringRegistrar property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getSponsoringRegistrar() {
        return sponsoringRegistrar;
    }

    /**
     * Sets the value of the sponsoringRegistrar property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setSponsoringRegistrar(StringObjectPropertyType value) {
        this.sponsoringRegistrar = value;
    }

    /**
     * Gets the value of the registrarInfo property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisRegistrarInfoType }
     *     
     */
    public WhoisRegistrarInfoType getRegistrarInfo() {
        return registrarInfo;
    }

    /**
     * Sets the value of the registrarInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisRegistrarInfoType }
     *     
     */
    public void setRegistrarInfo(WhoisRegistrarInfoType value) {
        this.registrarInfo = value;
    }

    /**
     * Gets the value of the registrants property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisRegistrantsType }
     *     
     */
    public WhoisRegistrantsType getRegistrants() {
        return registrants;
    }

    /**
     * Sets the value of the registrants property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisRegistrantsType }
     *     
     */
    public void setRegistrants(WhoisRegistrantsType value) {
        this.registrants = value;
    }

    /**
     * Gets the value of the contactInfo property.
     * 
     * @return
     *     possible object is
     *     {@link WhoisContactType }
     *     
     */
    public WhoisContactType getContactInfo() {
        return contactInfo;
    }

    /**
     * Sets the value of the contactInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link WhoisContactType }
     *     
     */
    public void setContactInfo(WhoisContactType value) {
        this.contactInfo = value;
    }

    /**
     * Gets the value of the remarks property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getRemarks() {
        return remarks;
    }

    /**
     * Sets the value of the remarks property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setRemarks(StringObjectPropertyType value) {
        this.remarks = value;
    }

}
