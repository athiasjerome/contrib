//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.09 at 05:02:22 PM EDT 
//


package org.mitre.maec.xmlschema.maec_package_2;

import java.math.BigDecimal;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The ClusteringAlgorithmParametersType captures any parameters that may have been used in a malware clustering algorithm.
 * 
 * <p>Java class for ClusteringAlgorithmParametersType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ClusteringAlgorithmParametersType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Distance_Threshold" type="{http://www.w3.org/2001/XMLSchema}decimal" minOccurs="0"/>
 *         &lt;element name="Number_of_Iterations" type="{http://www.w3.org/2001/XMLSchema}positiveInteger" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ClusteringAlgorithmParametersType", propOrder = {
    "distanceThreshold",
    "numberOfIterations"
})
public class ClusteringAlgorithmParametersType {

    @XmlElement(name = "Distance_Threshold")
    protected BigDecimal distanceThreshold;
    @XmlElement(name = "Number_of_Iterations")
    @XmlSchemaType(name = "positiveInteger")
    protected BigInteger numberOfIterations;

    /**
     * Gets the value of the distanceThreshold property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getDistanceThreshold() {
        return distanceThreshold;
    }

    /**
     * Sets the value of the distanceThreshold property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setDistanceThreshold(BigDecimal value) {
        this.distanceThreshold = value;
    }

    /**
     * Gets the value of the numberOfIterations property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getNumberOfIterations() {
        return numberOfIterations;
    }

    /**
     * Sets the value of the numberOfIterations property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setNumberOfIterations(BigInteger value) {
        this.numberOfIterations = value;
    }

}