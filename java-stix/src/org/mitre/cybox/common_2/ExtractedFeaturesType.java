//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.common_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The ExtractedFeaturesType is a type representing a description of features extracted from an object such as a file.
 * 
 * <p>Java class for ExtractedFeaturesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ExtractedFeaturesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Strings" type="{http://cybox.mitre.org/common-2}ExtractedStringsType" minOccurs="0"/>
 *         &lt;element name="Imports" type="{http://cybox.mitre.org/common-2}ImportsType" minOccurs="0"/>
 *         &lt;element name="Functions" type="{http://cybox.mitre.org/common-2}FunctionsType" minOccurs="0"/>
 *         &lt;element name="Code_Snippets" type="{http://cybox.mitre.org/common-2}CodeSnippetsType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ExtractedFeaturesType", propOrder = {
    "strings",
    "imports",
    "functions",
    "codeSnippets"
})
public class ExtractedFeaturesType {

    @XmlElement(name = "Strings")
    protected ExtractedStringsType strings;
    @XmlElement(name = "Imports")
    protected ImportsType imports;
    @XmlElement(name = "Functions")
    protected FunctionsType functions;
    @XmlElement(name = "Code_Snippets")
    protected CodeSnippetsType codeSnippets;

    /**
     * Gets the value of the strings property.
     * 
     * @return
     *     possible object is
     *     {@link ExtractedStringsType }
     *     
     */
    public ExtractedStringsType getStrings() {
        return strings;
    }

    /**
     * Sets the value of the strings property.
     * 
     * @param value
     *     allowed object is
     *     {@link ExtractedStringsType }
     *     
     */
    public void setStrings(ExtractedStringsType value) {
        this.strings = value;
    }

    /**
     * Gets the value of the imports property.
     * 
     * @return
     *     possible object is
     *     {@link ImportsType }
     *     
     */
    public ImportsType getImports() {
        return imports;
    }

    /**
     * Sets the value of the imports property.
     * 
     * @param value
     *     allowed object is
     *     {@link ImportsType }
     *     
     */
    public void setImports(ImportsType value) {
        this.imports = value;
    }

    /**
     * Gets the value of the functions property.
     * 
     * @return
     *     possible object is
     *     {@link FunctionsType }
     *     
     */
    public FunctionsType getFunctions() {
        return functions;
    }

    /**
     * Sets the value of the functions property.
     * 
     * @param value
     *     allowed object is
     *     {@link FunctionsType }
     *     
     */
    public void setFunctions(FunctionsType value) {
        this.functions = value;
    }

    /**
     * Gets the value of the codeSnippets property.
     * 
     * @return
     *     possible object is
     *     {@link CodeSnippetsType }
     *     
     */
    public CodeSnippetsType getCodeSnippets() {
        return codeSnippets;
    }

    /**
     * Sets the value of the codeSnippets property.
     * 
     * @param value
     *     allowed object is
     *     {@link CodeSnippetsType }
     *     
     */
    public void setCodeSnippets(CodeSnippetsType value) {
        this.codeSnippets = value;
    }

}
