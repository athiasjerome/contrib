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
import org.mitre.cybox.common_2.ObjectPropertiesType;


/**
 * Defines the fields necessary to summarize network traffic, expressed as flows of multiple packets. Does not include the packet payload data (i.e. the actual data that was uploaded/downloaded to and from the Dest IP to Source IP as included in packet monitoring tools, such as Wireshark).
 * 
 * <p>Java class for NetworkFlowObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetworkFlowObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Network_Flow_Label" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}NetworkFlowLabelType" minOccurs="0"/>
 *         &lt;choice minOccurs="0">
 *           &lt;element name="Unidirectional_Flow_Record" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}UnidirectionalRecordType" minOccurs="0"/>
 *           &lt;element name="Bidirectional_Flow_Record" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}BidirectionalRecordType" minOccurs="0"/>
 *         &lt;/choice>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetworkFlowObjectType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "networkFlowLabel",
    "unidirectionalFlowRecord",
    "bidirectionalFlowRecord"
})
public class NetworkFlowObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Network_Flow_Label")
    protected NetworkFlowLabelType networkFlowLabel;
    @XmlElement(name = "Unidirectional_Flow_Record")
    protected UnidirectionalRecordType unidirectionalFlowRecord;
    @XmlElement(name = "Bidirectional_Flow_Record")
    protected BidirectionalRecordType bidirectionalFlowRecord;

    /**
     * Gets the value of the networkFlowLabel property.
     * 
     * @return
     *     possible object is
     *     {@link NetworkFlowLabelType }
     *     
     */
    public NetworkFlowLabelType getNetworkFlowLabel() {
        return networkFlowLabel;
    }

    /**
     * Sets the value of the networkFlowLabel property.
     * 
     * @param value
     *     allowed object is
     *     {@link NetworkFlowLabelType }
     *     
     */
    public void setNetworkFlowLabel(NetworkFlowLabelType value) {
        this.networkFlowLabel = value;
    }

    /**
     * Gets the value of the unidirectionalFlowRecord property.
     * 
     * @return
     *     possible object is
     *     {@link UnidirectionalRecordType }
     *     
     */
    public UnidirectionalRecordType getUnidirectionalFlowRecord() {
        return unidirectionalFlowRecord;
    }

    /**
     * Sets the value of the unidirectionalFlowRecord property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnidirectionalRecordType }
     *     
     */
    public void setUnidirectionalFlowRecord(UnidirectionalRecordType value) {
        this.unidirectionalFlowRecord = value;
    }

    /**
     * Gets the value of the bidirectionalFlowRecord property.
     * 
     * @return
     *     possible object is
     *     {@link BidirectionalRecordType }
     *     
     */
    public BidirectionalRecordType getBidirectionalFlowRecord() {
        return bidirectionalFlowRecord;
    }

    /**
     * Sets the value of the bidirectionalFlowRecord property.
     * 
     * @param value
     *     allowed object is
     *     {@link BidirectionalRecordType }
     *     
     */
    public void setBidirectionalFlowRecord(BidirectionalRecordType value) {
        this.bidirectionalFlowRecord = value;
    }

}
