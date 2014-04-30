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
 * The IComHandlerActionType type characterizes IComHandler actions.
 * 
 * <p>Java class for IComHandlerActionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IComHandlerActionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="COM_Data" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="COM_Class_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IComHandlerActionType", namespace = "http://cybox.mitre.org/objects#WinTaskObject-2", propOrder = {
    "comData",
    "comClassID"
})
public class IComHandlerActionType {

    @XmlElement(name = "COM_Data")
    protected StringObjectPropertyType comData;
    @XmlElement(name = "COM_Class_ID")
    protected StringObjectPropertyType comClassID;

    /**
     * Gets the value of the comData property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCOMData() {
        return comData;
    }

    /**
     * Sets the value of the comData property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCOMData(StringObjectPropertyType value) {
        this.comData = value;
    }

    /**
     * Gets the value of the comClassID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCOMClassID() {
        return comClassID;
    }

    /**
     * Sets the value of the comClassID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCOMClassID(StringObjectPropertyType value) {
        this.comClassID = value;
    }

}