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
 * Logical Protocols characterizes the logical protocol of a link layer connection. One example of a logical protocol is ARP.
 * 
 * <p>Java class for LogicalProtocolType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="LogicalProtocolType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="ARP_RARP" type="{http://cybox.mitre.org/objects#PacketObject-2}ARPType" minOccurs="0"/>
 *         &lt;element name="NDP" type="{http://cybox.mitre.org/objects#PacketObject-2}NDPType" minOccurs="0"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "LogicalProtocolType", propOrder = {
    "arprarp",
    "ndp"
})
public class LogicalProtocolType {

    @XmlElement(name = "ARP_RARP")
    protected ARPType arprarp;
    @XmlElement(name = "NDP")
    protected NDPType ndp;

    /**
     * Gets the value of the arprarp property.
     * 
     * @return
     *     possible object is
     *     {@link ARPType }
     *     
     */
    public ARPType getARPRARP() {
        return arprarp;
    }

    /**
     * Sets the value of the arprarp property.
     * 
     * @param value
     *     allowed object is
     *     {@link ARPType }
     *     
     */
    public void setARPRARP(ARPType value) {
        this.arprarp = value;
    }

    /**
     * Gets the value of the ndp property.
     * 
     * @return
     *     possible object is
     *     {@link NDPType }
     *     
     */
    public NDPType getNDP() {
        return ndp;
    }

    /**
     * Sets the value of the ndp property.
     * 
     * @param value
     *     allowed object is
     *     {@link NDPType }
     *     
     */
    public void setNDP(NDPType value) {
        this.ndp = value;
    }

}
