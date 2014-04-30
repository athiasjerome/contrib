//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.oval.xmlschema.oval_definitions_5;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;


/**
 * The PossibleValueType complex type is used to outline a single expected value of an external variable. The required hint attribute gives a short description of what the value means or represents.
 * 
 * <p>Java class for PossibleValueType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PossibleValueType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>anySimpleType">
 *       &lt;attribute name="hint" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PossibleValueType", propOrder = {
    "value"
})
public class PossibleValueType {

    @XmlValue
    @XmlSchemaType(name = "anySimpleType")
    protected Object value;
    @XmlAttribute(name = "hint", required = true)
    protected String hint;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * Gets the value of the hint property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getHint() {
        return hint;
    }

    /**
     * Sets the value of the hint property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setHint(String value) {
        this.hint = value;
    }

}
