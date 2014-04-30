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


/**
 * The IP_Info type specifies information about the IP address and its associated subnet mask used by a network interface.
 * 
 * <p>Java class for IPInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IPInfoType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="IP_Address" type="{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType" minOccurs="0"/>
 *         &lt;element name="Subnet_Mask" type="{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IPInfoType", namespace = "http://cybox.mitre.org/objects#SystemObject-2", propOrder = {
    "ipAddress",
    "subnetMask"
})
public class IPInfoType {

    @XmlElement(name = "IP_Address")
    protected AddressObjectType ipAddress;
    @XmlElement(name = "Subnet_Mask")
    protected AddressObjectType subnetMask;

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
     * Gets the value of the subnetMask property.
     * 
     * @return
     *     possible object is
     *     {@link AddressObjectType }
     *     
     */
    public AddressObjectType getSubnetMask() {
        return subnetMask;
    }

    /**
     * Sets the value of the subnetMask property.
     * 
     * @param value
     *     allowed object is
     *     {@link AddressObjectType }
     *     
     */
    public void setSubnetMask(AddressObjectType value) {
        this.subnetMask = value;
    }

}
