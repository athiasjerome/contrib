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
import org.mitre.cybox.common_2.IntegerObjectPropertyType;


/**
 * These flag types are used to control or identify fragments in an IP packet. It is a three-bit field, each of the three bits are defined by a field with a string value that indicates the meaning of whether or not the bit is set.
 * 
 * <p>Java class for IPv4FlagsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IPv4FlagsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Reserved" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Do_Not_Fragment" type="{http://cybox.mitre.org/objects#PacketObject-2}DoNotFragmentType" minOccurs="0"/>
 *         &lt;element name="More_Fragments" type="{http://cybox.mitre.org/objects#PacketObject-2}MoreFragmentsType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IPv4FlagsType", propOrder = {
    "reserved",
    "doNotFragment",
    "moreFragments"
})
public class IPv4FlagsType {

    @XmlElement(name = "Reserved")
    protected IntegerObjectPropertyType reserved;
    @XmlElement(name = "Do_Not_Fragment")
    protected DoNotFragmentType doNotFragment;
    @XmlElement(name = "More_Fragments")
    protected MoreFragmentsType moreFragments;

    /**
     * Gets the value of the reserved property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getReserved() {
        return reserved;
    }

    /**
     * Sets the value of the reserved property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setReserved(IntegerObjectPropertyType value) {
        this.reserved = value;
    }

    /**
     * Gets the value of the doNotFragment property.
     * 
     * @return
     *     possible object is
     *     {@link DoNotFragmentType }
     *     
     */
    public DoNotFragmentType getDoNotFragment() {
        return doNotFragment;
    }

    /**
     * Sets the value of the doNotFragment property.
     * 
     * @param value
     *     allowed object is
     *     {@link DoNotFragmentType }
     *     
     */
    public void setDoNotFragment(DoNotFragmentType value) {
        this.doNotFragment = value;
    }

    /**
     * Gets the value of the moreFragments property.
     * 
     * @return
     *     possible object is
     *     {@link MoreFragmentsType }
     *     
     */
    public MoreFragmentsType getMoreFragments() {
        return moreFragments;
    }

    /**
     * Sets the value of the moreFragments property.
     * 
     * @param value
     *     allowed object is
     *     {@link MoreFragmentsType }
     *     
     */
    public void setMoreFragments(MoreFragmentsType value) {
        this.moreFragments = value;
    }

}
