//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.capec.capec_2;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;


/**
 * <p>Java class for RelationshipType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RelationshipType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Relationship_Views">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Relationship_View_ID" maxOccurs="unbounded">
 *                     &lt;complexType>
 *                       &lt;simpleContent>
 *                         &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>integer">
 *                           &lt;attribute name="Ordinal">
 *                             &lt;simpleType>
 *                               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *                                 &lt;whiteSpace value="collapse"/>
 *                                 &lt;enumeration value="Primary"/>
 *                               &lt;/restriction>
 *                             &lt;/simpleType>
 *                           &lt;/attribute>
 *                         &lt;/extension>
 *                       &lt;/simpleContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Relationship_Chains" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Relationship_Chain_ID" type="{http://www.w3.org/2001/XMLSchema}integer" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Relationship_Target_Form">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *               &lt;whiteSpace value="collapse"/>
 *               &lt;enumeration value="Category"/>
 *               &lt;enumeration value="Attack Pattern"/>
 *               &lt;enumeration value="View"/>
 *               &lt;enumeration value="Compound_Element"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="Relationship_Nature" maxOccurs="unbounded">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *               &lt;whiteSpace value="collapse"/>
 *               &lt;enumeration value="HasMember"/>
 *               &lt;enumeration value="MemberOf"/>
 *               &lt;enumeration value="ChildOf"/>
 *               &lt;enumeration value="ParentOf"/>
 *               &lt;enumeration value="PeerOf"/>
 *               &lt;enumeration value="Requires"/>
 *               &lt;enumeration value="RequiredBy"/>
 *               &lt;enumeration value="StartsWith"/>
 *               &lt;enumeration value="StartsChain"/>
 *               &lt;enumeration value="CanPrecede"/>
 *               &lt;enumeration value="CanFollow"/>
 *               &lt;enumeration value="CanAlsoBe"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="Relationship_Target_ID" type="{http://www.w3.org/2001/XMLSchema}integer"/>
 *         &lt;element name="Relationship_Description" type="{http://capec.mitre.org/capec-2}Structured_Text_Type" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RelationshipType", propOrder = {
    "relationshipViews",
    "relationshipChains",
    "relationshipTargetForm",
    "relationshipNature",
    "relationshipTargetID",
    "relationshipDescription"
})
public class RelationshipType {

    @XmlElement(name = "Relationship_Views", required = true)
    protected RelationshipType.RelationshipViews relationshipViews;
    @XmlElement(name = "Relationship_Chains")
    protected RelationshipType.RelationshipChains relationshipChains;
    @XmlElement(name = "Relationship_Target_Form", required = true)
    protected String relationshipTargetForm;
    @XmlElement(name = "Relationship_Nature", required = true)
    protected List<String> relationshipNature;
    @XmlElement(name = "Relationship_Target_ID", required = true)
    protected BigInteger relationshipTargetID;
    @XmlElement(name = "Relationship_Description")
    protected StructuredTextType relationshipDescription;

    /**
     * Gets the value of the relationshipViews property.
     * 
     * @return
     *     possible object is
     *     {@link RelationshipType.RelationshipViews }
     *     
     */
    public RelationshipType.RelationshipViews getRelationshipViews() {
        return relationshipViews;
    }

    /**
     * Sets the value of the relationshipViews property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelationshipType.RelationshipViews }
     *     
     */
    public void setRelationshipViews(RelationshipType.RelationshipViews value) {
        this.relationshipViews = value;
    }

    /**
     * Gets the value of the relationshipChains property.
     * 
     * @return
     *     possible object is
     *     {@link RelationshipType.RelationshipChains }
     *     
     */
    public RelationshipType.RelationshipChains getRelationshipChains() {
        return relationshipChains;
    }

    /**
     * Sets the value of the relationshipChains property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelationshipType.RelationshipChains }
     *     
     */
    public void setRelationshipChains(RelationshipType.RelationshipChains value) {
        this.relationshipChains = value;
    }

    /**
     * Gets the value of the relationshipTargetForm property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRelationshipTargetForm() {
        return relationshipTargetForm;
    }

    /**
     * Sets the value of the relationshipTargetForm property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRelationshipTargetForm(String value) {
        this.relationshipTargetForm = value;
    }

    /**
     * Gets the value of the relationshipNature property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the relationshipNature property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRelationshipNature().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getRelationshipNature() {
        if (relationshipNature == null) {
            relationshipNature = new ArrayList<String>();
        }
        return this.relationshipNature;
    }

    /**
     * Gets the value of the relationshipTargetID property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getRelationshipTargetID() {
        return relationshipTargetID;
    }

    /**
     * Sets the value of the relationshipTargetID property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setRelationshipTargetID(BigInteger value) {
        this.relationshipTargetID = value;
    }

    /**
     * Gets the value of the relationshipDescription property.
     * 
     * @return
     *     possible object is
     *     {@link StructuredTextType }
     *     
     */
    public StructuredTextType getRelationshipDescription() {
        return relationshipDescription;
    }

    /**
     * Sets the value of the relationshipDescription property.
     * 
     * @param value
     *     allowed object is
     *     {@link StructuredTextType }
     *     
     */
    public void setRelationshipDescription(StructuredTextType value) {
        this.relationshipDescription = value;
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
     *         &lt;element name="Relationship_Chain_ID" type="{http://www.w3.org/2001/XMLSchema}integer" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "relationshipChainID"
    })
    public static class RelationshipChains {

        @XmlElement(name = "Relationship_Chain_ID")
        protected List<BigInteger> relationshipChainID;

        /**
         * Gets the value of the relationshipChainID property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the relationshipChainID property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getRelationshipChainID().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link BigInteger }
         * 
         * 
         */
        public List<BigInteger> getRelationshipChainID() {
            if (relationshipChainID == null) {
                relationshipChainID = new ArrayList<BigInteger>();
            }
            return this.relationshipChainID;
        }

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
     *         &lt;element name="Relationship_View_ID" maxOccurs="unbounded">
     *           &lt;complexType>
     *             &lt;simpleContent>
     *               &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>integer">
     *                 &lt;attribute name="Ordinal">
     *                   &lt;simpleType>
     *                     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
     *                       &lt;whiteSpace value="collapse"/>
     *                       &lt;enumeration value="Primary"/>
     *                     &lt;/restriction>
     *                   &lt;/simpleType>
     *                 &lt;/attribute>
     *               &lt;/extension>
     *             &lt;/simpleContent>
     *           &lt;/complexType>
     *         &lt;/element>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "relationshipViewID"
    })
    public static class RelationshipViews {

        @XmlElement(name = "Relationship_View_ID", required = true)
        protected List<RelationshipType.RelationshipViews.RelationshipViewID> relationshipViewID;

        /**
         * Gets the value of the relationshipViewID property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the relationshipViewID property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getRelationshipViewID().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link RelationshipType.RelationshipViews.RelationshipViewID }
         * 
         * 
         */
        public List<RelationshipType.RelationshipViews.RelationshipViewID> getRelationshipViewID() {
            if (relationshipViewID == null) {
                relationshipViewID = new ArrayList<RelationshipType.RelationshipViews.RelationshipViewID>();
            }
            return this.relationshipViewID;
        }


        /**
         * <p>Java class for anonymous complex type.
         * 
         * <p>The following schema fragment specifies the expected content contained within this class.
         * 
         * <pre>
         * &lt;complexType>
         *   &lt;simpleContent>
         *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>integer">
         *       &lt;attribute name="Ordinal">
         *         &lt;simpleType>
         *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
         *             &lt;whiteSpace value="collapse"/>
         *             &lt;enumeration value="Primary"/>
         *           &lt;/restriction>
         *         &lt;/simpleType>
         *       &lt;/attribute>
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
        public static class RelationshipViewID {

            @XmlValue
            protected BigInteger value;
            @XmlAttribute(name = "Ordinal")
            protected String ordinal;

            /**
             * Gets the value of the value property.
             * 
             * @return
             *     possible object is
             *     {@link BigInteger }
             *     
             */
            public BigInteger getValue() {
                return value;
            }

            /**
             * Sets the value of the value property.
             * 
             * @param value
             *     allowed object is
             *     {@link BigInteger }
             *     
             */
            public void setValue(BigInteger value) {
                this.value = value;
            }

            /**
             * Gets the value of the ordinal property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getOrdinal() {
                return ordinal;
            }

            /**
             * Sets the value of the ordinal property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setOrdinal(String value) {
                this.ordinal = value;
            }

        }

    }

}