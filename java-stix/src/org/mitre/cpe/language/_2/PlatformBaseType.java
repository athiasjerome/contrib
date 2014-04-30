//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cpe.language._2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * The platform element represents the description
 *                         or qualifications of a particular IT platform type. The platform is defined
 *                         by the logical-test child element.
 * 
 * <p>Java class for PlatformBaseType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PlatformBaseType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="title" type="{http://cpe.mitre.org/language/2.0}TextType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="remark" type="{http://cpe.mitre.org/language/2.0}TextType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://cpe.mitre.org/language/2.0}logical-test"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PlatformBaseType", propOrder = {
    "title",
    "remark",
    "logicalTest"
})
@XmlSeeAlso({
    PlatformType.class
})
public class PlatformBaseType {

    protected List<TextType> title;
    protected List<TextType> remark;
    @XmlElement(name = "logical-test", required = true)
    protected LogicalTestType logicalTest;

    /**
     * Gets the value of the title property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the title property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTitle().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link TextType }
     * 
     * 
     */
    public List<TextType> getTitle() {
        if (title == null) {
            title = new ArrayList<TextType>();
        }
        return this.title;
    }

    /**
     * Gets the value of the remark property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the remark property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRemark().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link TextType }
     * 
     * 
     */
    public List<TextType> getRemark() {
        if (remark == null) {
            remark = new ArrayList<TextType>();
        }
        return this.remark;
    }

    /**
     * Gets the value of the logicalTest property.
     * 
     * @return
     *     possible object is
     *     {@link LogicalTestType }
     *     
     */
    public LogicalTestType getLogicalTest() {
        return logicalTest;
    }

    /**
     * Sets the value of the logicalTest property.
     * 
     * @param value
     *     allowed object is
     *     {@link LogicalTestType }
     *     
     */
    public void setLogicalTest(LogicalTestType value) {
        this.logicalTest = value;
    }

}
