//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlType;


/**
 * The PEResourceListType specifies a list of resources found in the PE file.
 * 
 * <p>Java class for PEResourceListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PEResourceListType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://cybox.mitre.org/objects#WinExecutableFileObject-2}Resource" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PEResourceListType", namespace = "http://cybox.mitre.org/objects#WinExecutableFileObject-2", propOrder = {
    "resource"
})
public class PEResourceListType {

    @XmlElementRef(name = "Resource", namespace = "http://cybox.mitre.org/objects#WinExecutableFileObject-2", type = JAXBElement.class)
    protected List<JAXBElement<? extends PEResourceType>> resource;

    /**
     * Specifies an field of a list of resources.Gets the value of the resource property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the resource property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getResource().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link JAXBElement }{@code <}{@link PEResourceType }{@code >}
     * {@link JAXBElement }{@code <}{@link PEVersionInfoResourceType }{@code >}
     * 
     * 
     */
    public List<JAXBElement<? extends PEResourceType>> getResource() {
        if (resource == null) {
            resource = new ArrayList<JAXBElement<? extends PEResourceType>>();
        }
        return this.resource;
    }

}
