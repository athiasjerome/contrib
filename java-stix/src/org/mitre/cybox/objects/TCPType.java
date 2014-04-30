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
import org.mitre.cybox.common_2.DataSegmentType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;


/**
 * TCP provides reliable, ordered delivery of a stream of bytes from a program on one computer to another program on another computer. http://en.wikipedia.org/wiki/Transmission_Control_Protocol.
 * 
 * <p>Java class for TCPType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TCPType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="TCP_Header" type="{http://cybox.mitre.org/objects#PacketObject-2}TCPHeaderType" minOccurs="0"/>
 *         &lt;element name="Options" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Data" type="{http://cybox.mitre.org/common-2}DataSegmentType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TCPType", propOrder = {
    "tcpHeader",
    "options",
    "data"
})
public class TCPType {

    @XmlElement(name = "TCP_Header")
    protected TCPHeaderType tcpHeader;
    @XmlElement(name = "Options")
    protected HexBinaryObjectPropertyType options;
    @XmlElement(name = "Data")
    protected DataSegmentType data;

    /**
     * Gets the value of the tcpHeader property.
     * 
     * @return
     *     possible object is
     *     {@link TCPHeaderType }
     *     
     */
    public TCPHeaderType getTCPHeader() {
        return tcpHeader;
    }

    /**
     * Sets the value of the tcpHeader property.
     * 
     * @param value
     *     allowed object is
     *     {@link TCPHeaderType }
     *     
     */
    public void setTCPHeader(TCPHeaderType value) {
        this.tcpHeader = value;
    }

    /**
     * Gets the value of the options property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getOptions() {
        return options;
    }

    /**
     * Sets the value of the options property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setOptions(HexBinaryObjectPropertyType value) {
        this.options = value;
    }

    /**
     * Gets the value of the data property.
     * 
     * @return
     *     possible object is
     *     {@link DataSegmentType }
     *     
     */
    public DataSegmentType getData() {
        return data;
    }

    /**
     * Sets the value of the data property.
     * 
     * @param value
     *     allowed object is
     *     {@link DataSegmentType }
     *     
     */
    public void setData(DataSegmentType value) {
        this.data = value;
    }

}
