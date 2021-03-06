//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package gov.nist.scap.schema.cvss_v2._1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;


/**
 * <p>Java class for collateralDamagePotentialType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="collateralDamagePotentialType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://scap.nist.gov/schema/cvss-v2/1.0>collateralDamagePotentialEnumType">
 *       &lt;attGroup ref="{http://scap.nist.gov/schema/cvss-v2/1.0}vectorAttributeGroup"/>
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "collateralDamagePotentialType", propOrder = {
    "value"
})
public class CollateralDamagePotentialType {

    @XmlValue
    protected CollateralDamagePotentialEnumType value;
    @XmlAttribute(name = "approximated")
    protected Boolean approximated;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link CollateralDamagePotentialEnumType }
     *     
     */
    public CollateralDamagePotentialEnumType getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link CollateralDamagePotentialEnumType }
     *     
     */
    public void setValue(CollateralDamagePotentialEnumType value) {
        this.value = value;
    }

    /**
     * Gets the value of the approximated property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isApproximated() {
        if (approximated == null) {
            return false;
        } else {
            return approximated;
        }
    }

    /**
     * Sets the value of the approximated property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setApproximated(Boolean value) {
        this.approximated = value;
    }

}
