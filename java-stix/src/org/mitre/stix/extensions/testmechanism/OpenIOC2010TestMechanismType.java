//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.extensions.testmechanism;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import com.mandiant.schemas._2010.ioc.IndicatorOfCompromise;
import org.mitre.stix.indicator_2.TestMechanismType;


/**
 * The OpenIOC2010TestMechanismType provides an extension to the TestMechanismType which imports and leverages the 2010 Open IOC schema in order to include OpenIOC elements as the test mechanism.
 * 
 * <p>Java class for OpenIOC2010TestMechanismType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="OpenIOC2010TestMechanismType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://stix.mitre.org/Indicator-2}TestMechanismType">
 *       &lt;sequence>
 *         &lt;element name="ioc" type="{http://schemas.mandiant.com/2010/ioc}IndicatorOfCompromise"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "OpenIOC2010TestMechanismType", namespace = "http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1", propOrder = {
    "ioc"
})
public class OpenIOC2010TestMechanismType
    extends TestMechanismType
{

    @XmlElement(required = true)
    protected IndicatorOfCompromise ioc;

    /**
     * Gets the value of the ioc property.
     * 
     * @return
     *     possible object is
     *     {@link IndicatorOfCompromise }
     *     
     */
    public IndicatorOfCompromise getIoc() {
        return ioc;
    }

    /**
     * Sets the value of the ioc property.
     * 
     * @param value
     *     allowed object is
     *     {@link IndicatorOfCompromise }
     *     
     */
    public void setIoc(IndicatorOfCompromise value) {
        this.ioc = value;
    }

}
