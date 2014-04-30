//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.maec.xmlschema.maec_bundle_4;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.namespace.QName;


/**
 * The BehaviorCollectionType provides a Capability for characterizing collections of behaviors.
 * 
 * <p>Java class for BehaviorCollectionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BehaviorCollectionType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://maec.mitre.org/XMLSchema/maec-bundle-4}BaseCollectionType">
 *       &lt;sequence>
 *         &lt;element name="Purpose" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Behavior_List" type="{http://maec.mitre.org/XMLSchema/maec-bundle-4}BehaviorListType"/>
 *       &lt;/sequence>
 *       &lt;attribute name="id" use="required" type="{http://www.w3.org/2001/XMLSchema}QName" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BehaviorCollectionType", propOrder = {
    "purpose",
    "behaviorList"
})
public class BehaviorCollectionType
    extends BaseCollectionType
{

    @XmlElement(name = "Purpose")
    protected String purpose;
    @XmlElement(name = "Behavior_List", required = true)
    protected BehaviorListType behaviorList;
    @XmlAttribute(name = "id", required = true)
    protected QName id;

    /**
     * Gets the value of the purpose property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPurpose() {
        return purpose;
    }

    /**
     * Sets the value of the purpose property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPurpose(String value) {
        this.purpose = value;
    }

    /**
     * Gets the value of the behaviorList property.
     * 
     * @return
     *     possible object is
     *     {@link BehaviorListType }
     *     
     */
    public BehaviorListType getBehaviorList() {
        return behaviorList;
    }

    /**
     * Sets the value of the behaviorList property.
     * 
     * @param value
     *     allowed object is
     *     {@link BehaviorListType }
     *     
     */
    public void setBehaviorList(BehaviorListType value) {
        this.behaviorList = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setId(QName value) {
        this.id = value;
    }

}