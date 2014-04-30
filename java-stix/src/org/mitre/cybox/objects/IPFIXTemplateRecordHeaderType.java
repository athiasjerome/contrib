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


/**
 * Specifies the fields in a Template Record Header, Template_ID and Field_Count, as explained in RFC 5101, section 3.4.1.
 * 
 * <p>Java class for IPFIXTemplateRecordHeaderType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IPFIXTemplateRecordHeaderType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Template_ID" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Field_Count" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IPFIXTemplateRecordHeaderType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "templateID",
    "fieldCount"
})
public class IPFIXTemplateRecordHeaderType {

    @XmlElement(name = "Template_ID")
    protected IntegerObjectPropertyType templateID;
    @XmlElement(name = "Field_Count")
    protected HexBinaryObjectPropertyType fieldCount;

    /**
     * Gets the value of the templateID property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getTemplateID() {
        return templateID;
    }

    /**
     * Sets the value of the templateID property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setTemplateID(IntegerObjectPropertyType value) {
        this.templateID = value;
    }

    /**
     * Gets the value of the fieldCount property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getFieldCount() {
        return fieldCount;
    }

    /**
     * Sets the value of the fieldCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setFieldCount(HexBinaryObjectPropertyType value) {
        this.fieldCount = value;
    }

}
