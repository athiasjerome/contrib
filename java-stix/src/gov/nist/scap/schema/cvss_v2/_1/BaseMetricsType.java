//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package gov.nist.scap.schema.cvss_v2._1;

import java.math.BigDecimal;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for baseMetricsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="baseMetricsType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://scap.nist.gov/schema/cvss-v2/1.0}metricsType">
 *       &lt;sequence>
 *         &lt;element name="score" type="{http://scap.nist.gov/schema/cvss-v2/1.0}zeroToTenDecimalType" minOccurs="0"/>
 *         &lt;element name="exploit-subscore" type="{http://scap.nist.gov/schema/cvss-v2/1.0}zeroToTenDecimalType" minOccurs="0"/>
 *         &lt;element name="impact-subscore" type="{http://scap.nist.gov/schema/cvss-v2/1.0}zeroToTenDecimalType" minOccurs="0"/>
 *         &lt;group ref="{http://scap.nist.gov/schema/cvss-v2/1.0}baseVectorsGroup"/>
 *         &lt;element name="source" type="{http://www.w3.org/2001/XMLSchema}anyURI"/>
 *         &lt;element name="generated-on-datetime" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "baseMetricsType", propOrder = {
    "score",
    "exploitSubscore",
    "impactSubscore",
    "accessVector",
    "accessComplexity",
    "authentication",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
    "source",
    "generatedOnDatetime"
})
public class BaseMetricsType
    extends MetricsType
{

    protected BigDecimal score;
    @XmlElement(name = "exploit-subscore")
    protected BigDecimal exploitSubscore;
    @XmlElement(name = "impact-subscore")
    protected BigDecimal impactSubscore;
    @XmlElement(name = "access-vector")
    protected AccessVectorType accessVector;
    @XmlElement(name = "access-complexity")
    protected AccessComplexityType accessComplexity;
    protected AuthenticationType authentication;
    @XmlElement(name = "confidentiality-impact")
    protected CiaType confidentialityImpact;
    @XmlElement(name = "integrity-impact")
    protected CiaType integrityImpact;
    @XmlElement(name = "availability-impact")
    protected CiaType availabilityImpact;
    @XmlElement(required = true)
    @XmlSchemaType(name = "anyURI")
    protected String source;
    @XmlElement(name = "generated-on-datetime")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar generatedOnDatetime;

    /**
     * Gets the value of the score property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getScore() {
        return score;
    }

    /**
     * Sets the value of the score property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setScore(BigDecimal value) {
        this.score = value;
    }

    /**
     * Gets the value of the exploitSubscore property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getExploitSubscore() {
        return exploitSubscore;
    }

    /**
     * Sets the value of the exploitSubscore property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setExploitSubscore(BigDecimal value) {
        this.exploitSubscore = value;
    }

    /**
     * Gets the value of the impactSubscore property.
     * 
     * @return
     *     possible object is
     *     {@link BigDecimal }
     *     
     */
    public BigDecimal getImpactSubscore() {
        return impactSubscore;
    }

    /**
     * Sets the value of the impactSubscore property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigDecimal }
     *     
     */
    public void setImpactSubscore(BigDecimal value) {
        this.impactSubscore = value;
    }

    /**
     * Gets the value of the accessVector property.
     * 
     * @return
     *     possible object is
     *     {@link AccessVectorType }
     *     
     */
    public AccessVectorType getAccessVector() {
        return accessVector;
    }

    /**
     * Sets the value of the accessVector property.
     * 
     * @param value
     *     allowed object is
     *     {@link AccessVectorType }
     *     
     */
    public void setAccessVector(AccessVectorType value) {
        this.accessVector = value;
    }

    /**
     * Gets the value of the accessComplexity property.
     * 
     * @return
     *     possible object is
     *     {@link AccessComplexityType }
     *     
     */
    public AccessComplexityType getAccessComplexity() {
        return accessComplexity;
    }

    /**
     * Sets the value of the accessComplexity property.
     * 
     * @param value
     *     allowed object is
     *     {@link AccessComplexityType }
     *     
     */
    public void setAccessComplexity(AccessComplexityType value) {
        this.accessComplexity = value;
    }

    /**
     * Gets the value of the authentication property.
     * 
     * @return
     *     possible object is
     *     {@link AuthenticationType }
     *     
     */
    public AuthenticationType getAuthentication() {
        return authentication;
    }

    /**
     * Sets the value of the authentication property.
     * 
     * @param value
     *     allowed object is
     *     {@link AuthenticationType }
     *     
     */
    public void setAuthentication(AuthenticationType value) {
        this.authentication = value;
    }

    /**
     * Gets the value of the confidentialityImpact property.
     * 
     * @return
     *     possible object is
     *     {@link CiaType }
     *     
     */
    public CiaType getConfidentialityImpact() {
        return confidentialityImpact;
    }

    /**
     * Sets the value of the confidentialityImpact property.
     * 
     * @param value
     *     allowed object is
     *     {@link CiaType }
     *     
     */
    public void setConfidentialityImpact(CiaType value) {
        this.confidentialityImpact = value;
    }

    /**
     * Gets the value of the integrityImpact property.
     * 
     * @return
     *     possible object is
     *     {@link CiaType }
     *     
     */
    public CiaType getIntegrityImpact() {
        return integrityImpact;
    }

    /**
     * Sets the value of the integrityImpact property.
     * 
     * @param value
     *     allowed object is
     *     {@link CiaType }
     *     
     */
    public void setIntegrityImpact(CiaType value) {
        this.integrityImpact = value;
    }

    /**
     * Gets the value of the availabilityImpact property.
     * 
     * @return
     *     possible object is
     *     {@link CiaType }
     *     
     */
    public CiaType getAvailabilityImpact() {
        return availabilityImpact;
    }

    /**
     * Sets the value of the availabilityImpact property.
     * 
     * @param value
     *     allowed object is
     *     {@link CiaType }
     *     
     */
    public void setAvailabilityImpact(CiaType value) {
        this.availabilityImpact = value;
    }

    /**
     * Gets the value of the source property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSource() {
        return source;
    }

    /**
     * Sets the value of the source property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSource(String value) {
        this.source = value;
    }

    /**
     * Gets the value of the generatedOnDatetime property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getGeneratedOnDatetime() {
        return generatedOnDatetime;
    }

    /**
     * Sets the value of the generatedOnDatetime property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setGeneratedOnDatetime(XMLGregorianCalendar value) {
        this.generatedOnDatetime = value;
    }

}
