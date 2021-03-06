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
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * Network layer information (relative to the OSI network model) which is typically captured in all types of network flow records.
 * 
 * <p>Java class for NetworkLayerInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetworkLayerInfoType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Src_Socket_Address" type="{http://cybox.mitre.org/objects#SocketAddressObject-1}SocketAddressObjectType" minOccurs="0"/>
 *         &lt;element name="Dest_Socket_Address" type="{http://cybox.mitre.org/objects#SocketAddressObject-1}SocketAddressObjectType" minOccurs="0"/>
 *         &lt;element name="IP_Protocol" type="{http://cybox.mitre.org/objects#PacketObject-2}IANAAssignedIPNumbersType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetworkLayerInfoType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "srcSocketAddress",
    "destSocketAddress",
    "ipProtocol"
})
@XmlSeeAlso({
    NetworkFlowLabelType.class
})
public class NetworkLayerInfoType {

    @XmlElement(name = "Src_Socket_Address")
    protected SocketAddressObjectType srcSocketAddress;
    @XmlElement(name = "Dest_Socket_Address")
    protected SocketAddressObjectType destSocketAddress;
    @XmlElement(name = "IP_Protocol")
    protected IANAAssignedIPNumbersType ipProtocol;

    /**
     * Gets the value of the srcSocketAddress property.
     * 
     * @return
     *     possible object is
     *     {@link SocketAddressObjectType }
     *     
     */
    public SocketAddressObjectType getSrcSocketAddress() {
        return srcSocketAddress;
    }

    /**
     * Sets the value of the srcSocketAddress property.
     * 
     * @param value
     *     allowed object is
     *     {@link SocketAddressObjectType }
     *     
     */
    public void setSrcSocketAddress(SocketAddressObjectType value) {
        this.srcSocketAddress = value;
    }

    /**
     * Gets the value of the destSocketAddress property.
     * 
     * @return
     *     possible object is
     *     {@link SocketAddressObjectType }
     *     
     */
    public SocketAddressObjectType getDestSocketAddress() {
        return destSocketAddress;
    }

    /**
     * Sets the value of the destSocketAddress property.
     * 
     * @param value
     *     allowed object is
     *     {@link SocketAddressObjectType }
     *     
     */
    public void setDestSocketAddress(SocketAddressObjectType value) {
        this.destSocketAddress = value;
    }

    /**
     * Gets the value of the ipProtocol property.
     * 
     * @return
     *     possible object is
     *     {@link IANAAssignedIPNumbersType }
     *     
     */
    public IANAAssignedIPNumbersType getIPProtocol() {
        return ipProtocol;
    }

    /**
     * Sets the value of the ipProtocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link IANAAssignedIPNumbersType }
     *     
     */
    public void setIPProtocol(IANAAssignedIPNumbersType value) {
        this.ipProtocol = value;
    }

}
