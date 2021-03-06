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
 * The WindowsEventObjectType type is intended to characterize Windows event (synchronization) objects.
 * 
 * <p>Java class for WindowsEventObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsEventObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Handle" type="{http://cybox.mitre.org/objects#WinHandleObject-2}WindowsHandleObjectType" minOccurs="0"/>
 *         &lt;element name="Name" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Type" type="{http://cybox.mitre.org/objects#WinEventObject-2}WinEventType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsEventObjectType", namespace = "http://cybox.mitre.org/objects#WinEventObject-2", propOrder = {
    "handle",
    "name",
    "type"
})
public class WindowsEventObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Handle")
    protected WindowsHandleObjectType handle;
    @XmlElement(name = "Name")
    protected StringObjectPropertyType name;
    @XmlElement(name = "Type")
    protected WinEventType type;

    /**
     * Gets the value of the handle property.
     * 
     * @return
     *     possible object is
     *     {@link WindowsHandleObjectType }
     *     
     */
    public WindowsHandleObjectType getHandle() {
        return handle;
    }

    /**
     * Sets the value of the handle property.
     * 
     * @param value
     *     allowed object is
     *     {@link WindowsHandleObjectType }
     *     
     */
    public void setHandle(WindowsHandleObjectType value) {
        this.handle = value;
    }

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setName(StringObjectPropertyType value) {
        this.name = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link WinEventType }
     *     
     */
    public WinEventType getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link WinEventType }
     *     
     */
    public void setType(WinEventType value) {
        this.type = value;
    }

}
