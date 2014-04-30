//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The DomainNameObjectType type is intended to characterize network domain names.
 * 
 * <p>Java class for DomainNameObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DomainNameObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Value" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType"/>
 *       &lt;/sequence>
 *       &lt;attribute name="type" type="{http://cybox.mitre.org/objects#DomainNameObject-1}DomainNameTypeEnum" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DomainNameObjectType", namespace = "http://cybox.mitre.org/objects#DomainNameObject-1", propOrder = {
    "value"
})
public class DomainNameObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Value", required = true)
    protected StringObjectPropertyType value;
    @XmlAttribute(name = "type")
    protected DomainNameTypeEnum type;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setValue(StringObjectPropertyType value) {
        this.value = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link DomainNameTypeEnum }
     *     
     */
    public DomainNameTypeEnum getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link DomainNameTypeEnum }
     *     
     */
    public void setType(DomainNameTypeEnum value) {
        this.type = value;
    }

}
