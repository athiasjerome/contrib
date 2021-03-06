//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.capec.capec_2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for Reference_Type complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Reference_Type">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Reference_Author" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="Reference_Title" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Section" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Edition" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Publication" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Publisher" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Date" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
 *         &lt;element name="Reference_PubDate" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Reference_Link" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Reference_ID" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Local_Reference_ID" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Reference_Type", propOrder = {
    "referenceAuthor",
    "referenceTitle",
    "referenceSection",
    "referenceEdition",
    "referencePublication",
    "referencePublisher",
    "referenceDate",
    "referencePubDate",
    "referenceLink"
})
public class ReferenceType {

    @XmlElement(name = "Reference_Author")
    protected List<String> referenceAuthor;
    @XmlElement(name = "Reference_Title")
    protected String referenceTitle;
    @XmlElement(name = "Reference_Section")
    protected String referenceSection;
    @XmlElement(name = "Reference_Edition")
    protected String referenceEdition;
    @XmlElement(name = "Reference_Publication")
    protected String referencePublication;
    @XmlElement(name = "Reference_Publisher")
    protected String referencePublisher;
    @XmlElement(name = "Reference_Date")
    @XmlSchemaType(name = "date")
    protected XMLGregorianCalendar referenceDate;
    @XmlElement(name = "Reference_PubDate")
    protected String referencePubDate;
    @XmlElement(name = "Reference_Link")
    protected String referenceLink;
    @XmlAttribute(name = "Reference_ID")
    protected String referenceID;
    @XmlAttribute(name = "Local_Reference_ID")
    protected String localReferenceID;

    /**
     * Gets the value of the referenceAuthor property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the referenceAuthor property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getReferenceAuthor().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getReferenceAuthor() {
        if (referenceAuthor == null) {
            referenceAuthor = new ArrayList<String>();
        }
        return this.referenceAuthor;
    }

    /**
     * Gets the value of the referenceTitle property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferenceTitle() {
        return referenceTitle;
    }

    /**
     * Sets the value of the referenceTitle property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferenceTitle(String value) {
        this.referenceTitle = value;
    }

    /**
     * Gets the value of the referenceSection property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferenceSection() {
        return referenceSection;
    }

    /**
     * Sets the value of the referenceSection property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferenceSection(String value) {
        this.referenceSection = value;
    }

    /**
     * Gets the value of the referenceEdition property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferenceEdition() {
        return referenceEdition;
    }

    /**
     * Sets the value of the referenceEdition property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferenceEdition(String value) {
        this.referenceEdition = value;
    }

    /**
     * Gets the value of the referencePublication property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferencePublication() {
        return referencePublication;
    }

    /**
     * Sets the value of the referencePublication property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferencePublication(String value) {
        this.referencePublication = value;
    }

    /**
     * Gets the value of the referencePublisher property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferencePublisher() {
        return referencePublisher;
    }

    /**
     * Sets the value of the referencePublisher property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferencePublisher(String value) {
        this.referencePublisher = value;
    }

    /**
     * Gets the value of the referenceDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getReferenceDate() {
        return referenceDate;
    }

    /**
     * Sets the value of the referenceDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setReferenceDate(XMLGregorianCalendar value) {
        this.referenceDate = value;
    }

    /**
     * Gets the value of the referencePubDate property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferencePubDate() {
        return referencePubDate;
    }

    /**
     * Sets the value of the referencePubDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferencePubDate(String value) {
        this.referencePubDate = value;
    }

    /**
     * Gets the value of the referenceLink property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferenceLink() {
        return referenceLink;
    }

    /**
     * Sets the value of the referenceLink property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferenceLink(String value) {
        this.referenceLink = value;
    }

    /**
     * Gets the value of the referenceID property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReferenceID() {
        return referenceID;
    }

    /**
     * Sets the value of the referenceID property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReferenceID(String value) {
        this.referenceID = value;
    }

    /**
     * Gets the value of the localReferenceID property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLocalReferenceID() {
        return localReferenceID;
    }

    /**
     * Sets the value of the localReferenceID property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLocalReferenceID(String value) {
        this.localReferenceID = value;
    }

}
