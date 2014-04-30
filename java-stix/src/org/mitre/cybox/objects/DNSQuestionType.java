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
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The DNSQuestionType specifies the components of a DNS Question, including the domain name queried, type, and class.
 * 
 * <p>Java class for DNSQuestionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DNSQuestionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="QName" type="{http://cybox.mitre.org/objects#URIObject-2}URIObjectType" minOccurs="0"/>
 *         &lt;element name="QType" type="{http://cybox.mitre.org/objects#DNSQueryObject-2}DNSRecordType" minOccurs="0"/>
 *         &lt;element name="QClass" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DNSQuestionType", namespace = "http://cybox.mitre.org/objects#DNSQueryObject-2", propOrder = {
    "qName",
    "qType",
    "qClass"
})
public class DNSQuestionType {

    @XmlElement(name = "QName")
    protected URIObjectType qName;
    @XmlElement(name = "QType")
    protected DNSRecordType qType;
    @XmlElement(name = "QClass")
    protected StringObjectPropertyType qClass;

    /**
     * Gets the value of the qName property.
     * 
     * @return
     *     possible object is
     *     {@link URIObjectType }
     *     
     */
    public URIObjectType getQName() {
        return qName;
    }

    /**
     * Sets the value of the qName property.
     * 
     * @param value
     *     allowed object is
     *     {@link URIObjectType }
     *     
     */
    public void setQName(URIObjectType value) {
        this.qName = value;
    }

    /**
     * Gets the value of the qType property.
     * 
     * @return
     *     possible object is
     *     {@link DNSRecordType }
     *     
     */
    public DNSRecordType getQType() {
        return qType;
    }

    /**
     * Sets the value of the qType property.
     * 
     * @param value
     *     allowed object is
     *     {@link DNSRecordType }
     *     
     */
    public void setQType(DNSRecordType value) {
        this.qType = value;
    }

    /**
     * Gets the value of the qClass property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getQClass() {
        return qClass;
    }

    /**
     * Sets the value of the qClass property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setQClass(StringObjectPropertyType value) {
        this.qClass = value;
    }

}
