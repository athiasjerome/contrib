//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.common_2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The DigitalSignaturesType is used for representing a list of digital signatures.
 * 
 * <p>Java class for DigitalSignaturesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DigitalSignaturesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Digital_Signature" type="{http://cybox.mitre.org/common-2}DigitalSignatureInfoType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DigitalSignaturesType", propOrder = {
    "digitalSignature"
})
public class DigitalSignaturesType {

    @XmlElement(name = "Digital_Signature")
    protected List<DigitalSignatureInfoType> digitalSignature;

    /**
     * Gets the value of the digitalSignature property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the digitalSignature property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDigitalSignature().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link DigitalSignatureInfoType }
     * 
     * 
     */
    public List<DigitalSignatureInfoType> getDigitalSignature() {
        if (digitalSignature == null) {
            digitalSignature = new ArrayList<DigitalSignatureInfoType>();
        }
        return this.digitalSignature;
    }

}
