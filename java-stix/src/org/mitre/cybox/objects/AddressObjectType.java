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
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The AddressObjectType is intended to characterize cyber addresses.
 * 
 * <p>Java class for AddressObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AddressObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Address_Value" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="VLAN_Name" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="VLAN_Num" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="category" type="{http://cybox.mitre.org/objects#AddressObject-2}CategoryTypeEnum" default="ipv4-addr" />
 *       &lt;attribute name="is_source" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_destination" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_spoofed" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AddressObjectType", namespace = "http://cybox.mitre.org/objects#AddressObject-2", propOrder = {
    "addressValue",
    "vlanName",
    "vlanNum"
})
public class AddressObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Address_Value")
    protected StringObjectPropertyType addressValue;
    @XmlElement(name = "VLAN_Name")
    protected StringObjectPropertyType vlanName;
    @XmlElement(name = "VLAN_Num")
    protected IntegerObjectPropertyType vlanNum;
    @XmlAttribute(name = "category")
    protected CategoryTypeEnum category;
    @XmlAttribute(name = "is_source")
    protected Boolean isSource;
    @XmlAttribute(name = "is_destination")
    protected Boolean isDestination;
    @XmlAttribute(name = "is_spoofed")
    protected Boolean isSpoofed;

    /**
     * Gets the value of the addressValue property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getAddressValue() {
        return addressValue;
    }

    /**
     * Sets the value of the addressValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setAddressValue(StringObjectPropertyType value) {
        this.addressValue = value;
    }

    /**
     * Gets the value of the vlanName property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getVLANName() {
        return vlanName;
    }

    /**
     * Sets the value of the vlanName property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setVLANName(StringObjectPropertyType value) {
        this.vlanName = value;
    }

    /**
     * Gets the value of the vlanNum property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getVLANNum() {
        return vlanNum;
    }

    /**
     * Sets the value of the vlanNum property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setVLANNum(IntegerObjectPropertyType value) {
        this.vlanNum = value;
    }

    /**
     * Gets the value of the category property.
     * 
     * @return
     *     possible object is
     *     {@link CategoryTypeEnum }
     *     
     */
    public CategoryTypeEnum getCategory() {
        if (category == null) {
            return CategoryTypeEnum.IPV_4_ADDR;
        } else {
            return category;
        }
    }

    /**
     * Sets the value of the category property.
     * 
     * @param value
     *     allowed object is
     *     {@link CategoryTypeEnum }
     *     
     */
    public void setCategory(CategoryTypeEnum value) {
        this.category = value;
    }

    /**
     * Gets the value of the isSource property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsSource() {
        return isSource;
    }

    /**
     * Sets the value of the isSource property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsSource(Boolean value) {
        this.isSource = value;
    }

    /**
     * Gets the value of the isDestination property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsDestination() {
        return isDestination;
    }

    /**
     * Sets the value of the isDestination property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsDestination(Boolean value) {
        this.isDestination = value;
    }

    /**
     * Gets the value of the isSpoofed property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsSpoofed() {
        return isSpoofed;
    }

    /**
     * Sets the value of the isSpoofed property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsSpoofed(Boolean value) {
        this.isSpoofed = value;
    }

}
