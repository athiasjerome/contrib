//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.maec.xmlschema.maec_bundle_4;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.cybox_2.ActionReferenceType;


/**
 * The BehavioralActionReferenceType defines an action reference that can be used as part of a Behavior.
 * 
 * <p>Java class for BehavioralActionReferenceType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BehavioralActionReferenceType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/cybox-2}ActionReferenceType">
 *       &lt;attribute name="behavioral_ordering" type="{http://www.w3.org/2001/XMLSchema}positiveInteger" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BehavioralActionReferenceType")
public class BehavioralActionReferenceType
    extends ActionReferenceType
{

    @XmlAttribute(name = "behavioral_ordering")
    @XmlSchemaType(name = "positiveInteger")
    protected BigInteger behavioralOrdering;

    /**
     * Gets the value of the behavioralOrdering property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getBehavioralOrdering() {
        return behavioralOrdering;
    }

    /**
     * Sets the value of the behavioralOrdering property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setBehavioralOrdering(BigInteger value) {
        this.behavioralOrdering = value;
    }

}
