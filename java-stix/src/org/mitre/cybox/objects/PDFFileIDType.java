//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The PDFTrailerIDType captures the details of a PDF ID value stored in a trailer.
 * 
 * <p>Java class for PDFFileIDType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFFileIDType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ID_String" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" maxOccurs="2"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFFileIDType", namespace = "http://cybox.mitre.org/objects#PDFFileObject-1", propOrder = {
    "idString"
})
public class PDFFileIDType {

    @XmlElement(name = "ID_String", required = true)
    protected List<StringObjectPropertyType> idString;

    /**
     * Gets the value of the idString property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the idString property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIDString().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link StringObjectPropertyType }
     * 
     * 
     */
    public List<StringObjectPropertyType> getIDString() {
        if (idString == null) {
            idString = new ArrayList<StringObjectPropertyType>();
        }
        return this.idString;
    }

}
