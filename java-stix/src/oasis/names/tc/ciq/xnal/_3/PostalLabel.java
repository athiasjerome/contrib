//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package oasis.names.tc.ciq.xnal._3;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyAttribute;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.NormalizedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import oasis.names.tc.ciq.ct._3.DataQualityTypeList;
import oasis.names.tc.ciq.xal._3.AddressType;
import oasis.names.tc.ciq.xnl._3.PartyNameType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Addressee" maxOccurs="unbounded" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Designation" maxOccurs="unbounded" minOccurs="0">
 *                     &lt;complexType>
 *                       &lt;simpleContent>
 *                         &lt;extension base="&lt;urn:oasis:names:tc:ciq:ct:3>String">
 *                           &lt;anyAttribute processContents='lax' namespace='##other'/>
 *                         &lt;/extension>
 *                       &lt;/simpleContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
 *                   &lt;element ref="{urn:oasis:names:tc:ciq:xnl:3}PartyName" minOccurs="0"/>
 *                   &lt;element name="DependencyName" maxOccurs="unbounded" minOccurs="0">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;extension base="{urn:oasis:names:tc:ciq:xnl:3}PartyNameType">
 *                           &lt;attribute name="Type" use="required" type="{urn:oasis:names:tc:ciq:xnal:3}DependencyTypeList" />
 *                           &lt;anyAttribute processContents='lax' namespace='##other'/>
 *                         &lt;/extension>
 *                       &lt;/complexContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
 *                 &lt;/sequence>
 *                 &lt;attGroup ref="{urn:oasis:names:tc:ciq:ct:3}grLanguageCode"/>
 *                 &lt;anyAttribute processContents='lax' namespace='##other'/>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element ref="{urn:oasis:names:tc:ciq:xal:3}Address"/>
 *       &lt;/sequence>
 *       &lt;attGroup ref="{urn:oasis:names:tc:ciq:ct:3}grLanguageCode"/>
 *       &lt;attGroup ref="{urn:oasis:names:tc:ciq:ct:3}grValidityDate"/>
 *       &lt;attGroup ref="{urn:oasis:names:tc:ciq:ct:3}grDataQuality"/>
 *       &lt;attribute name="Status" type="{urn:oasis:names:tc:ciq:ct:3}StatusList" />
 *       &lt;anyAttribute processContents='lax' namespace='##other'/>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "addressee",
    "address"
})
@XmlRootElement(name = "PostalLabel")
public class PostalLabel {

    @XmlElement(name = "Addressee")
    protected List<PostalLabel.Addressee> addressee;
    @XmlElement(name = "Address", namespace = "urn:oasis:names:tc:ciq:xal:3", required = true)
    protected AddressType address;
    @XmlAttribute(name = "Status", namespace = "urn:oasis:names:tc:ciq:xnal:3")
    protected String status;
    @XmlAttribute(name = "LanguageCode", namespace = "urn:oasis:names:tc:ciq:ct:3")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "language")
    protected String languageCode;
    @XmlAttribute(name = "DateValidFrom", namespace = "urn:oasis:names:tc:ciq:ct:3")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar dateValidFrom;
    @XmlAttribute(name = "DateValidTo", namespace = "urn:oasis:names:tc:ciq:ct:3")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar dateValidTo;
    @XmlAttribute(name = "DataQualityType", namespace = "urn:oasis:names:tc:ciq:ct:3")
    protected DataQualityTypeList dataQualityType;
    @XmlAttribute(name = "ValidFrom", namespace = "urn:oasis:names:tc:ciq:ct:3")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFrom;
    @XmlAttribute(name = "ValidTo", namespace = "urn:oasis:names:tc:ciq:ct:3")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validTo;
    @XmlAnyAttribute
    private Map<QName, String> otherAttributes = new HashMap<QName, String>();

    /**
     * Gets the value of the addressee property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the addressee property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAddressee().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PostalLabel.Addressee }
     * 
     * 
     */
    public List<PostalLabel.Addressee> getAddressee() {
        if (addressee == null) {
            addressee = new ArrayList<PostalLabel.Addressee>();
        }
        return this.addressee;
    }

    /**
     * Gets the value of the address property.
     * 
     * @return
     *     possible object is
     *     {@link AddressType }
     *     
     */
    public AddressType getAddress() {
        return address;
    }

    /**
     * Sets the value of the address property.
     * 
     * @param value
     *     allowed object is
     *     {@link AddressType }
     *     
     */
    public void setAddress(AddressType value) {
        this.address = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStatus(String value) {
        this.status = value;
    }

    /**
     * Gets the value of the languageCode property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLanguageCode() {
        return languageCode;
    }

    /**
     * Sets the value of the languageCode property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLanguageCode(String value) {
        this.languageCode = value;
    }

    /**
     * Gets the value of the dateValidFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getDateValidFrom() {
        return dateValidFrom;
    }

    /**
     * Sets the value of the dateValidFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setDateValidFrom(XMLGregorianCalendar value) {
        this.dateValidFrom = value;
    }

    /**
     * Gets the value of the dateValidTo property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getDateValidTo() {
        return dateValidTo;
    }

    /**
     * Sets the value of the dateValidTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setDateValidTo(XMLGregorianCalendar value) {
        this.dateValidTo = value;
    }

    /**
     * Gets the value of the dataQualityType property.
     * 
     * @return
     *     possible object is
     *     {@link DataQualityTypeList }
     *     
     */
    public DataQualityTypeList getDataQualityType() {
        return dataQualityType;
    }

    /**
     * Sets the value of the dataQualityType property.
     * 
     * @param value
     *     allowed object is
     *     {@link DataQualityTypeList }
     *     
     */
    public void setDataQualityType(DataQualityTypeList value) {
        this.dataQualityType = value;
    }

    /**
     * Gets the value of the validFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidFrom() {
        return validFrom;
    }

    /**
     * Sets the value of the validFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidFrom(XMLGregorianCalendar value) {
        this.validFrom = value;
    }

    /**
     * Gets the value of the validTo property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidTo() {
        return validTo;
    }

    /**
     * Sets the value of the validTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidTo(XMLGregorianCalendar value) {
        this.validTo = value;
    }

    /**
     * Gets a map that contains attributes that aren't bound to any typed property on this class.
     * 
     * <p>
     * the map is keyed by the name of the attribute and 
     * the value is the string value of the attribute.
     * 
     * the map returned by this method is live, and you can add new attribute
     * by updating the map directly. Because of this design, there's no setter.
     * 
     * 
     * @return
     *     always non-null
     */
    public Map<QName, String> getOtherAttributes() {
        return otherAttributes;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="Designation" maxOccurs="unbounded" minOccurs="0">
     *           &lt;complexType>
     *             &lt;simpleContent>
     *               &lt;extension base="&lt;urn:oasis:names:tc:ciq:ct:3>String">
     *                 &lt;anyAttribute processContents='lax' namespace='##other'/>
     *               &lt;/extension>
     *             &lt;/simpleContent>
     *           &lt;/complexType>
     *         &lt;/element>
     *         &lt;element ref="{urn:oasis:names:tc:ciq:xnl:3}PartyName" minOccurs="0"/>
     *         &lt;element name="DependencyName" maxOccurs="unbounded" minOccurs="0">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;extension base="{urn:oasis:names:tc:ciq:xnl:3}PartyNameType">
     *                 &lt;attribute name="Type" use="required" type="{urn:oasis:names:tc:ciq:xnal:3}DependencyTypeList" />
     *                 &lt;anyAttribute processContents='lax' namespace='##other'/>
     *               &lt;/extension>
     *             &lt;/complexContent>
     *           &lt;/complexType>
     *         &lt;/element>
     *       &lt;/sequence>
     *       &lt;attGroup ref="{urn:oasis:names:tc:ciq:ct:3}grLanguageCode"/>
     *       &lt;anyAttribute processContents='lax' namespace='##other'/>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "designation",
        "partyName",
        "dependencyName"
    })
    public static class Addressee {

        @XmlElement(name = "Designation")
        protected List<PostalLabel.Addressee.Designation> designation;
        @XmlElement(name = "PartyName", namespace = "urn:oasis:names:tc:ciq:xnl:3")
        protected PartyNameType partyName;
        @XmlElement(name = "DependencyName")
        protected List<PostalLabel.Addressee.DependencyName> dependencyName;
        @XmlAttribute(name = "LanguageCode", namespace = "urn:oasis:names:tc:ciq:ct:3")
        @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
        @XmlSchemaType(name = "language")
        protected String languageCode;
        @XmlAnyAttribute
        private Map<QName, String> otherAttributes = new HashMap<QName, String>();

        /**
         * Gets the value of the designation property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the designation property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getDesignation().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link PostalLabel.Addressee.Designation }
         * 
         * 
         */
        public List<PostalLabel.Addressee.Designation> getDesignation() {
            if (designation == null) {
                designation = new ArrayList<PostalLabel.Addressee.Designation>();
            }
            return this.designation;
        }

        /**
         * Gets the value of the partyName property.
         * 
         * @return
         *     possible object is
         *     {@link PartyNameType }
         *     
         */
        public PartyNameType getPartyName() {
            return partyName;
        }

        /**
         * Sets the value of the partyName property.
         * 
         * @param value
         *     allowed object is
         *     {@link PartyNameType }
         *     
         */
        public void setPartyName(PartyNameType value) {
            this.partyName = value;
        }

        /**
         * Gets the value of the dependencyName property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the dependencyName property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getDependencyName().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link PostalLabel.Addressee.DependencyName }
         * 
         * 
         */
        public List<PostalLabel.Addressee.DependencyName> getDependencyName() {
            if (dependencyName == null) {
                dependencyName = new ArrayList<PostalLabel.Addressee.DependencyName>();
            }
            return this.dependencyName;
        }

        /**
         * Gets the value of the languageCode property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getLanguageCode() {
            return languageCode;
        }

        /**
         * Sets the value of the languageCode property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setLanguageCode(String value) {
            this.languageCode = value;
        }

        /**
         * Gets a map that contains attributes that aren't bound to any typed property on this class.
         * 
         * <p>
         * the map is keyed by the name of the attribute and 
         * the value is the string value of the attribute.
         * 
         * the map returned by this method is live, and you can add new attribute
         * by updating the map directly. Because of this design, there's no setter.
         * 
         * 
         * @return
         *     always non-null
         */
        public Map<QName, String> getOtherAttributes() {
            return otherAttributes;
        }


        /**
         * <p>Java class for anonymous complex type.
         * 
         * <p>The following schema fragment specifies the expected content contained within this class.
         * 
         * <pre>
         * &lt;complexType>
         *   &lt;complexContent>
         *     &lt;extension base="{urn:oasis:names:tc:ciq:xnl:3}PartyNameType">
         *       &lt;attribute name="Type" use="required" type="{urn:oasis:names:tc:ciq:xnal:3}DependencyTypeList" />
         *       &lt;anyAttribute processContents='lax' namespace='##other'/>
         *     &lt;/extension>
         *   &lt;/complexContent>
         * &lt;/complexType>
         * </pre>
         * 
         * 
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "")
        public static class DependencyName
            extends PartyNameType
        {

            @XmlAttribute(name = "Type", namespace = "urn:oasis:names:tc:ciq:xnal:3", required = true)
            @XmlJavaTypeAdapter(NormalizedStringAdapter.class)
            protected String externalOasisDependencyTypeListAttribute;

            /**
             * Gets the value of the externalOasisDependencyTypeListAttribute property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getExternalOasisDependencyTypeListAttribute() {
                return externalOasisDependencyTypeListAttribute;
            }

            /**
             * Sets the value of the externalOasisDependencyTypeListAttribute property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setExternalOasisDependencyTypeListAttribute(String value) {
                this.externalOasisDependencyTypeListAttribute = value;
            }

        }


        /**
         * <p>Java class for anonymous complex type.
         * 
         * <p>The following schema fragment specifies the expected content contained within this class.
         * 
         * <pre>
         * &lt;complexType>
         *   &lt;simpleContent>
         *     &lt;extension base="&lt;urn:oasis:names:tc:ciq:ct:3>String">
         *       &lt;anyAttribute processContents='lax' namespace='##other'/>
         *     &lt;/extension>
         *   &lt;/simpleContent>
         * &lt;/complexType>
         * </pre>
         * 
         * 
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "", propOrder = {
            "value"
        })
        public static class Designation {

            @XmlValue
            @XmlJavaTypeAdapter(NormalizedStringAdapter.class)
            protected String value;
            @XmlAnyAttribute
            private Map<QName, String> otherAttributes = new HashMap<QName, String>();

            /**
             * Normalized and Collapsed String
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getValue() {
                return value;
            }

            /**
             * Sets the value of the value property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setValue(String value) {
                this.value = value;
            }

            /**
             * Gets a map that contains attributes that aren't bound to any typed property on this class.
             * 
             * <p>
             * the map is keyed by the name of the attribute and 
             * the value is the string value of the attribute.
             * 
             * the map returned by this method is live, and you can add new attribute
             * by updating the map directly. Because of this design, there's no setter.
             * 
             * 
             * @return
             *     always non-null
             */
            public Map<QName, String> getOtherAttributes() {
                return otherAttributes;
            }

        }

    }

}
