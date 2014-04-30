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
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;


/**
 * Internet Protocol version 4 (IPv4) is a connectionless protocol for use on packet-switched link layer networks (e.g., Ethernet). REF: RFC 791; http://en.wikipedia.org/wiki/IPv4.
 * 
 * <p>Java class for IPv4PacketType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IPv4PacketType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="IPv4_Header" type="{http://cybox.mitre.org/objects#PacketObject-2}IPv4HeaderType" minOccurs="0"/>
 *         &lt;element name="Data" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IPv4PacketType", propOrder = {
    "iPv4Header",
    "data"
})
public class IPv4PacketType {

    @XmlElement(name = "IPv4_Header")
    protected IPv4HeaderType iPv4Header;
    @XmlElement(name = "Data")
    protected HexBinaryObjectPropertyType data;

    /**
     * Gets the value of the iPv4Header property.
     * 
     * @return
     *     possible object is
     *     {@link IPv4HeaderType }
     *     
     */
    public IPv4HeaderType getIPv4Header() {
        return iPv4Header;
    }

    /**
     * Sets the value of the iPv4Header property.
     * 
     * @param value
     *     allowed object is
     *     {@link IPv4HeaderType }
     *     
     */
    public void setIPv4Header(IPv4HeaderType value) {
        this.iPv4Header = value;
    }

    /**
     * Gets the value of the data property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getData() {
        return data;
    }

    /**
     * Sets the value of the data property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setData(HexBinaryObjectPropertyType value) {
        this.data = value;
    }

}