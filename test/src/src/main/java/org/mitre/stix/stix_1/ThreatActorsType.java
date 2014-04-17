//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.08 at 09:40:17 PM EDT 
//


package org.mitre.stix.stix_1;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.common_1.ThreatActorBaseType;


/**
 * <p>Java class for ThreatActorsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ThreatActorsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Threat_Actor" type="{http://stix.mitre.org/common-1}ThreatActorBaseType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ThreatActorsType", propOrder = {
    "threatActor"
})
public class ThreatActorsType {

    @XmlElement(name = "Threat_Actor", required = true)
    protected List<ThreatActorBaseType> threatActor;

    /**
     * Gets the value of the threatActor property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the threatActor property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getThreatActor().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ThreatActorBaseType }
     * 
     * 
     */
    public List<ThreatActorBaseType> getThreatActor() {
        if (threatActor == null) {
            threatActor = new ArrayList<ThreatActorBaseType>();
        }
        return this.threatActor;
    }

}