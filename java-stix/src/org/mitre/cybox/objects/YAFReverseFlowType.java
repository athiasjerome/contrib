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
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.common_2.PlatformSpecificationType;


/**
 * These elements correspond to the reverse flow captured by in YAF record.
 * 
 * <p>Java class for YAFReverseFlowType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="YAFReverseFlowType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Reverse_Octet_Total_Count" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Reverse_Packet_Total_Count" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Reverse_Payload_Entropy" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Reverse_Flow_Delta_Milliseconds" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="TCP_Reverse_Flow" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}YAFTCPFlowType" minOccurs="0"/>
 *         &lt;element name="Reverse_Vlan_ID_MAC_Addr" type="{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType" minOccurs="0"/>
 *         &lt;element name="Reverse_Passive_OS_Fingerprinting" type="{http://cybox.mitre.org/common-2}PlatformSpecificationType" minOccurs="0"/>
 *         &lt;element name="Reverse_First_Packet" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Reverse_N_Bytes_Payload" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "YAFReverseFlowType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "reverseOctetTotalCount",
    "reversePacketTotalCount",
    "reversePayloadEntropy",
    "reverseFlowDeltaMilliseconds",
    "tcpReverseFlow",
    "reverseVlanIDMACAddr",
    "reversePassiveOSFingerprinting",
    "reverseFirstPacket",
    "reverseNBytesPayload"
})
public class YAFReverseFlowType {

    @XmlElement(name = "Reverse_Octet_Total_Count")
    protected IntegerObjectPropertyType reverseOctetTotalCount;
    @XmlElement(name = "Reverse_Packet_Total_Count")
    protected IntegerObjectPropertyType reversePacketTotalCount;
    @XmlElement(name = "Reverse_Payload_Entropy")
    protected IntegerObjectPropertyType reversePayloadEntropy;
    @XmlElement(name = "Reverse_Flow_Delta_Milliseconds")
    protected IntegerObjectPropertyType reverseFlowDeltaMilliseconds;
    @XmlElement(name = "TCP_Reverse_Flow")
    protected YAFTCPFlowType tcpReverseFlow;
    @XmlElement(name = "Reverse_Vlan_ID_MAC_Addr")
    protected AddressObjectType reverseVlanIDMACAddr;
    @XmlElement(name = "Reverse_Passive_OS_Fingerprinting")
    protected PlatformSpecificationType reversePassiveOSFingerprinting;
    @XmlElement(name = "Reverse_First_Packet")
    protected HexBinaryObjectPropertyType reverseFirstPacket;
    @XmlElement(name = "Reverse_N_Bytes_Payload")
    protected HexBinaryObjectPropertyType reverseNBytesPayload;

    /**
     * Gets the value of the reverseOctetTotalCount property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getReverseOctetTotalCount() {
        return reverseOctetTotalCount;
    }

    /**
     * Sets the value of the reverseOctetTotalCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setReverseOctetTotalCount(IntegerObjectPropertyType value) {
        this.reverseOctetTotalCount = value;
    }

    /**
     * Gets the value of the reversePacketTotalCount property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getReversePacketTotalCount() {
        return reversePacketTotalCount;
    }

    /**
     * Sets the value of the reversePacketTotalCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setReversePacketTotalCount(IntegerObjectPropertyType value) {
        this.reversePacketTotalCount = value;
    }

    /**
     * Gets the value of the reversePayloadEntropy property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getReversePayloadEntropy() {
        return reversePayloadEntropy;
    }

    /**
     * Sets the value of the reversePayloadEntropy property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setReversePayloadEntropy(IntegerObjectPropertyType value) {
        this.reversePayloadEntropy = value;
    }

    /**
     * Gets the value of the reverseFlowDeltaMilliseconds property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getReverseFlowDeltaMilliseconds() {
        return reverseFlowDeltaMilliseconds;
    }

    /**
     * Sets the value of the reverseFlowDeltaMilliseconds property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setReverseFlowDeltaMilliseconds(IntegerObjectPropertyType value) {
        this.reverseFlowDeltaMilliseconds = value;
    }

    /**
     * Gets the value of the tcpReverseFlow property.
     * 
     * @return
     *     possible object is
     *     {@link YAFTCPFlowType }
     *     
     */
    public YAFTCPFlowType getTCPReverseFlow() {
        return tcpReverseFlow;
    }

    /**
     * Sets the value of the tcpReverseFlow property.
     * 
     * @param value
     *     allowed object is
     *     {@link YAFTCPFlowType }
     *     
     */
    public void setTCPReverseFlow(YAFTCPFlowType value) {
        this.tcpReverseFlow = value;
    }

    /**
     * Gets the value of the reverseVlanIDMACAddr property.
     * 
     * @return
     *     possible object is
     *     {@link AddressObjectType }
     *     
     */
    public AddressObjectType getReverseVlanIDMACAddr() {
        return reverseVlanIDMACAddr;
    }

    /**
     * Sets the value of the reverseVlanIDMACAddr property.
     * 
     * @param value
     *     allowed object is
     *     {@link AddressObjectType }
     *     
     */
    public void setReverseVlanIDMACAddr(AddressObjectType value) {
        this.reverseVlanIDMACAddr = value;
    }

    /**
     * Gets the value of the reversePassiveOSFingerprinting property.
     * 
     * @return
     *     possible object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public PlatformSpecificationType getReversePassiveOSFingerprinting() {
        return reversePassiveOSFingerprinting;
    }

    /**
     * Sets the value of the reversePassiveOSFingerprinting property.
     * 
     * @param value
     *     allowed object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public void setReversePassiveOSFingerprinting(PlatformSpecificationType value) {
        this.reversePassiveOSFingerprinting = value;
    }

    /**
     * Gets the value of the reverseFirstPacket property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getReverseFirstPacket() {
        return reverseFirstPacket;
    }

    /**
     * Sets the value of the reverseFirstPacket property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setReverseFirstPacket(HexBinaryObjectPropertyType value) {
        this.reverseFirstPacket = value;
    }

    /**
     * Gets the value of the reverseNBytesPayload property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getReverseNBytesPayload() {
        return reverseNBytesPayload;
    }

    /**
     * Sets the value of the reverseNBytesPayload property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setReverseNBytesPayload(HexBinaryObjectPropertyType value) {
        this.reverseNBytesPayload = value;
    }

}
