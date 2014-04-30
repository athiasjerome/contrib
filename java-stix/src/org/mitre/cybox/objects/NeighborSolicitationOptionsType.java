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
 * Neighbor Solicitation messages include zero or more options, some of which may appear multiple times in the same message.
 * 
 * <p>Java class for NeighborSolicitationOptionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NeighborSolicitationOptionsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="Src_Link_Addr" type="{http://cybox.mitre.org/objects#PacketObject-2}NDPLinkAddrType" minOccurs="0"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NeighborSolicitationOptionsType", propOrder = {
    "srcLinkAddr"
})
public class NeighborSolicitationOptionsType {

    @XmlElement(name = "Src_Link_Addr")
    protected NDPLinkAddrType srcLinkAddr;

    /**
     * Gets the value of the srcLinkAddr property.
     * 
     * @return
     *     possible object is
     *     {@link NDPLinkAddrType }
     *     
     */
    public NDPLinkAddrType getSrcLinkAddr() {
        return srcLinkAddr;
    }

    /**
     * Sets the value of the srcLinkAddr property.
     * 
     * @param value
     *     allowed object is
     *     {@link NDPLinkAddrType }
     *     
     */
    public void setSrcLinkAddr(NDPLinkAddrType value) {
        this.srcLinkAddr = value;
    }

}
