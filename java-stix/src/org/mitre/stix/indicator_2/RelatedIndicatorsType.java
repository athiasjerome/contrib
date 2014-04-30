//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.indicator_2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.common_1.GenericRelationshipListType;
import org.mitre.stix.common_1.RelatedIndicatorType;


/**
 * <p>Java class for RelatedIndicatorsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RelatedIndicatorsType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://stix.mitre.org/common-1}GenericRelationshipListType">
 *       &lt;sequence>
 *         &lt;element name="Related_Indicator" type="{http://stix.mitre.org/common-1}RelatedIndicatorType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RelatedIndicatorsType", propOrder = {
    "relatedIndicator"
})
public class RelatedIndicatorsType
    extends GenericRelationshipListType
{

    @XmlElement(name = "Related_Indicator", required = true)
    protected List<RelatedIndicatorType> relatedIndicator;

    /**
     * Gets the value of the relatedIndicator property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the relatedIndicator property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRelatedIndicator().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link RelatedIndicatorType }
     * 
     * 
     */
    public List<RelatedIndicatorType> getRelatedIndicator() {
        if (relatedIndicator == null) {
            relatedIndicator = new ArrayList<RelatedIndicatorType>();
        }
        return this.relatedIndicator;
    }

}
