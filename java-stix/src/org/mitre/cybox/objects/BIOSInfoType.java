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
import org.mitre.cybox.common_2.DateObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The BIOSInfoType type specifies information about a system's BIOS.
 * 
 * <p>Java class for BIOSInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BIOSInfoType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="BIOS_Date" type="{http://cybox.mitre.org/common-2}DateObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="BIOS_Version" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="BIOS_Manufacturer" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="BIOS_Release_Date" type="{http://cybox.mitre.org/common-2}DateObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="BIOS_Serial_Number" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BIOSInfoType", namespace = "http://cybox.mitre.org/objects#SystemObject-2", propOrder = {
    "biosDate",
    "biosVersion",
    "biosManufacturer",
    "biosReleaseDate",
    "biosSerialNumber"
})
public class BIOSInfoType {

    @XmlElement(name = "BIOS_Date")
    protected DateObjectPropertyType biosDate;
    @XmlElement(name = "BIOS_Version")
    protected StringObjectPropertyType biosVersion;
    @XmlElement(name = "BIOS_Manufacturer")
    protected StringObjectPropertyType biosManufacturer;
    @XmlElement(name = "BIOS_Release_Date")
    protected DateObjectPropertyType biosReleaseDate;
    @XmlElement(name = "BIOS_Serial_Number")
    protected StringObjectPropertyType biosSerialNumber;

    /**
     * Gets the value of the biosDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public DateObjectPropertyType getBIOSDate() {
        return biosDate;
    }

    /**
     * Sets the value of the biosDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public void setBIOSDate(DateObjectPropertyType value) {
        this.biosDate = value;
    }

    /**
     * Gets the value of the biosVersion property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getBIOSVersion() {
        return biosVersion;
    }

    /**
     * Sets the value of the biosVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setBIOSVersion(StringObjectPropertyType value) {
        this.biosVersion = value;
    }

    /**
     * Gets the value of the biosManufacturer property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getBIOSManufacturer() {
        return biosManufacturer;
    }

    /**
     * Sets the value of the biosManufacturer property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setBIOSManufacturer(StringObjectPropertyType value) {
        this.biosManufacturer = value;
    }

    /**
     * Gets the value of the biosReleaseDate property.
     * 
     * @return
     *     possible object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public DateObjectPropertyType getBIOSReleaseDate() {
        return biosReleaseDate;
    }

    /**
     * Sets the value of the biosReleaseDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateObjectPropertyType }
     *     
     */
    public void setBIOSReleaseDate(DateObjectPropertyType value) {
        this.biosReleaseDate = value;
    }

    /**
     * Gets the value of the biosSerialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getBIOSSerialNumber() {
        return biosSerialNumber;
    }

    /**
     * Sets the value of the biosSerialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setBIOSSerialNumber(StringObjectPropertyType value) {
        this.biosSerialNumber = value;
    }

}
