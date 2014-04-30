//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package gov.nist.scap.schema.cvss_v2._1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for cvssImpactBaseType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="cvssImpactBaseType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="base_metrics" type="{http://scap.nist.gov/schema/cvss-v2/1.0}baseMetricsType"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "cvssImpactBaseType", propOrder = {
    "baseMetrics"
})
@XmlSeeAlso({
    CvssImpactTemporalType.class
})
public class CvssImpactBaseType {

    @XmlElement(name = "base_metrics", required = true)
    protected BaseMetricsType baseMetrics;

    /**
     * Gets the value of the baseMetrics property.
     * 
     * @return
     *     possible object is
     *     {@link BaseMetricsType }
     *     
     */
    public BaseMetricsType getBaseMetrics() {
        return baseMetrics;
    }

    /**
     * Sets the value of the baseMetrics property.
     * 
     * @param value
     *     allowed object is
     *     {@link BaseMetricsType }
     *     
     */
    public void setBaseMetrics(BaseMetricsType value) {
        this.baseMetrics = value;
    }

}
