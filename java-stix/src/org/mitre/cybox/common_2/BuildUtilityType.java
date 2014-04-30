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
 * The BuildUtilityType contains information identifying the utility used to build this application.
 * 
 * <p>Java class for BuildUtilityType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BuildUtilityType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Build_Utility_Name" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="Build_Utility_Platform_Specification" type="{http://cybox.mitre.org/common-2}PlatformSpecificationType"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BuildUtilityType", propOrder = {
    "buildUtilityName",
    "buildUtilityPlatformSpecification"
})
public class BuildUtilityType {

    @XmlElement(name = "Build_Utility_Name", required = true)
    protected String buildUtilityName;
    @XmlElement(name = "Build_Utility_Platform_Specification", required = true)
    protected PlatformSpecificationType buildUtilityPlatformSpecification;

    /**
     * Gets the value of the buildUtilityName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getBuildUtilityName() {
        return buildUtilityName;
    }

    /**
     * Sets the value of the buildUtilityName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setBuildUtilityName(String value) {
        this.buildUtilityName = value;
    }

    /**
     * Gets the value of the buildUtilityPlatformSpecification property.
     * 
     * @return
     *     possible object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public PlatformSpecificationType getBuildUtilityPlatformSpecification() {
        return buildUtilityPlatformSpecification;
    }

    /**
     * Sets the value of the buildUtilityPlatformSpecification property.
     * 
     * @param value
     *     allowed object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public void setBuildUtilityPlatformSpecification(PlatformSpecificationType value) {
        this.buildUtilityPlatformSpecification = value;
    }

}
