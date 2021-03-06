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
 * The Internet layer is the group of methods, protocols, and specifications that are used to transport packets from the originating host across network boundaries. Not all protocols are currently defined, just those most commonly used: IPv4, ICMPv4, IPv6, ICMPv6. Other protocols will be added as needed. (http://en.wikipedia.org/wiki/Internet_layer).
 * 
 * <p>Java class for InternetLayerType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="InternetLayerType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="IPv4" type="{http://cybox.mitre.org/objects#PacketObject-2}IPv4PacketType" minOccurs="0"/>
 *         &lt;element name="ICMPv4" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4PacketType" minOccurs="0"/>
 *         &lt;element name="IPv6" type="{http://cybox.mitre.org/objects#PacketObject-2}IPv6PacketType" minOccurs="0"/>
 *         &lt;element name="ICMPv6" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv6PacketType" minOccurs="0"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InternetLayerType", propOrder = {
    "iPv4",
    "icmPv4",
    "iPv6",
    "icmPv6"
})
public class InternetLayerType {

    @XmlElement(name = "IPv4")
    protected IPv4PacketType iPv4;
    @XmlElement(name = "ICMPv4")
    protected ICMPv4PacketType icmPv4;
    @XmlElement(name = "IPv6")
    protected IPv6PacketType iPv6;
    @XmlElement(name = "ICMPv6")
    protected ICMPv6PacketType icmPv6;

    /**
     * Gets the value of the iPv4 property.
     * 
     * @return
     *     possible object is
     *     {@link IPv4PacketType }
     *     
     */
    public IPv4PacketType getIPv4() {
        return iPv4;
    }

    /**
     * Sets the value of the iPv4 property.
     * 
     * @param value
     *     allowed object is
     *     {@link IPv4PacketType }
     *     
     */
    public void setIPv4(IPv4PacketType value) {
        this.iPv4 = value;
    }

    /**
     * Gets the value of the icmPv4 property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4PacketType }
     *     
     */
    public ICMPv4PacketType getICMPv4() {
        return icmPv4;
    }

    /**
     * Sets the value of the icmPv4 property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4PacketType }
     *     
     */
    public void setICMPv4(ICMPv4PacketType value) {
        this.icmPv4 = value;
    }

    /**
     * Gets the value of the iPv6 property.
     * 
     * @return
     *     possible object is
     *     {@link IPv6PacketType }
     *     
     */
    public IPv6PacketType getIPv6() {
        return iPv6;
    }

    /**
     * Sets the value of the iPv6 property.
     * 
     * @param value
     *     allowed object is
     *     {@link IPv6PacketType }
     *     
     */
    public void setIPv6(IPv6PacketType value) {
        this.iPv6 = value;
    }

    /**
     * Gets the value of the icmPv6 property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv6PacketType }
     *     
     */
    public ICMPv6PacketType getICMPv6() {
        return icmPv6;
    }

    /**
     * Sets the value of the icmPv6 property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv6PacketType }
     *     
     */
    public void setICMPv6(ICMPv6PacketType value) {
        this.icmPv6 = value;
    }

}
