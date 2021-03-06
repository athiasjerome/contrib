//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.incident_1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;


/**
 * <p>Java class for COATimeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="COATimeType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Start" type="{http://stix.mitre.org/common-1}DateTimeWithPrecisionType" minOccurs="0"/>
 *         &lt;element name="End" type="{http://stix.mitre.org/common-1}DateTimeWithPrecisionType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "COATimeType", propOrder = {
    "start",
    "end"
})
public class COATimeType {

    @XmlElement(name = "Start")
    protected DateTimeWithPrecisionType start;
    @XmlElement(name = "End")
    protected DateTimeWithPrecisionType end;

    /**
     * Gets the value of the start property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeWithPrecisionType }
     *     
     */
    public DateTimeWithPrecisionType getStart() {
        return start;
    }

    /**
     * Sets the value of the start property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeWithPrecisionType }
     *     
     */
    public void setStart(DateTimeWithPrecisionType value) {
        this.start = value;
    }

    /**
     * Gets the value of the end property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeWithPrecisionType }
     *     
     */
    public DateTimeWithPrecisionType getEnd() {
        return end;
    }

    /**
     * Sets the value of the end property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeWithPrecisionType }
     *     
     */
    public void setEnd(DateTimeWithPrecisionType value) {
        this.end = value;
    }

}
