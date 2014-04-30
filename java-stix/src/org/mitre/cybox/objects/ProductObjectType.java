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
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The ProductObjectType type is intended to characterize software or hardware products.
 * 
 * <p>Java class for ProductObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ProductObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Edition" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Language" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Product" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Update" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Vendor" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Version" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Device_Details" type="{http://cybox.mitre.org/common-2}ObjectPropertiesType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ProductObjectType", namespace = "http://cybox.mitre.org/objects#ProductObject-2", propOrder = {
    "edition",
    "language",
    "product",
    "update",
    "vendor",
    "version",
    "deviceDetails"
})
public class ProductObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Edition")
    protected StringObjectPropertyType edition;
    @XmlElement(name = "Language")
    protected StringObjectPropertyType language;
    @XmlElement(name = "Product")
    protected StringObjectPropertyType product;
    @XmlElement(name = "Update")
    protected StringObjectPropertyType update;
    @XmlElement(name = "Vendor")
    protected StringObjectPropertyType vendor;
    @XmlElement(name = "Version")
    protected StringObjectPropertyType version;
    @XmlElement(name = "Device_Details")
    protected ObjectPropertiesType deviceDetails;

    /**
     * Gets the value of the edition property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getEdition() {
        return edition;
    }

    /**
     * Sets the value of the edition property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setEdition(StringObjectPropertyType value) {
        this.edition = value;
    }

    /**
     * Gets the value of the language property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getLanguage() {
        return language;
    }

    /**
     * Sets the value of the language property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setLanguage(StringObjectPropertyType value) {
        this.language = value;
    }

    /**
     * Gets the value of the product property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getProduct() {
        return product;
    }

    /**
     * Sets the value of the product property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setProduct(StringObjectPropertyType value) {
        this.product = value;
    }

    /**
     * Gets the value of the update property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getUpdate() {
        return update;
    }

    /**
     * Sets the value of the update property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setUpdate(StringObjectPropertyType value) {
        this.update = value;
    }

    /**
     * Gets the value of the vendor property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getVendor() {
        return vendor;
    }

    /**
     * Sets the value of the vendor property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setVendor(StringObjectPropertyType value) {
        this.vendor = value;
    }

    /**
     * Gets the value of the version property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getVersion() {
        return version;
    }

    /**
     * Sets the value of the version property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setVersion(StringObjectPropertyType value) {
        this.version = value;
    }

    /**
     * Gets the value of the deviceDetails property.
     * 
     * @return
     *     possible object is
     *     {@link ObjectPropertiesType }
     *     
     */
    public ObjectPropertiesType getDeviceDetails() {
        return deviceDetails;
    }

    /**
     * Sets the value of the deviceDetails property.
     * 
     * @param value
     *     allowed object is
     *     {@link ObjectPropertiesType }
     *     
     */
    public void setDeviceDetails(ObjectPropertiesType value) {
        this.deviceDetails = value;
    }

}
