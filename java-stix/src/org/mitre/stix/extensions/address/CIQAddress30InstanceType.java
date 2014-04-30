//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.extensions.address;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import oasis.names.tc.ciq.xal._3.AddressType;
import org.mitre.stix.common_1.AddressAbstractType;


/**
 * The CIQAddress3.0InstanceType provides an extension to the AddressAbstractType which imports and leverages version 3.0 of the OASIS CIQ-PIL schema for structured characterization of Addresses.
 * 
 * <p>Java class for CIQAddress3.0InstanceType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CIQAddress3.0InstanceType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://stix.mitre.org/common-1}AddressAbstractType">
 *       &lt;sequence>
 *         &lt;element name="Location" type="{urn:oasis:names:tc:ciq:xal:3}AddressType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CIQAddress3.0InstanceType", propOrder = {
    "location"
})
public class CIQAddress30InstanceType
    extends AddressAbstractType
{

    @XmlElement(name = "Location")
    protected AddressType location;

    /**
     * Gets the value of the location property.
     * 
     * @return
     *     possible object is
     *     {@link AddressType }
     *     
     */
    public AddressType getLocation() {
        return location;
    }

    /**
     * Sets the value of the location property.
     * 
     * @param value
     *     allowed object is
     *     {@link AddressType }
     *     
     */
    public void setLocation(AddressType value) {
        this.location = value;
    }

}
