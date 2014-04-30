//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.common_1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.campaign_1.AttributionType;
import org.mitre.stix.courseofaction_1.RelatedCOAsType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.exploittarget_1.RelatedExploitTargetsType;
import org.mitre.stix.incident_1.AttributedThreatActorsType;
import org.mitre.stix.incident_1.LeveragedTTPsType;
import org.mitre.stix.indicator_2.RelatedCampaignReferencesType;
import org.mitre.stix.indicator_2.SuggestedCOAsType;
import org.mitre.stix.stix_1.RelatedPackagesType;
import org.mitre.stix.threatactor_1.AssociatedActorsType;
import org.mitre.stix.threatactor_1.ObservedTTPsType;
import org.mitre.stix.ttp_1.ExploitTargetsType;


/**
 * Allows the expression of a list of relationships between STIX components. It's extended throughout STIX and should not be used directly. 
 * 
 * <p>Java class for GenericRelationshipListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="GenericRelationshipListType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="scope" type="{http://stix.mitre.org/common-1}RelationshipScopeEnum" default="exclusive" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "GenericRelationshipListType")
@XmlSeeAlso({
    ExploitTargetsType.class,
    org.mitre.stix.ttp_1.RelatedTTPsType.class,
    RelatedCOAsType.class,
    RelatedExploitTargetsType.class,
    PotentialCOAsType.class,
    AffectedSoftwareType.class,
    org.mitre.stix.indicator_2.RelatedIndicatorsType.class,
    org.mitre.stix.indicator_2.RelatedObservablesType.class,
    SuggestedCOAsType.class,
    RelatedCampaignReferencesType.class,
    AttributionType.class,
    org.mitre.stix.campaign_1.RelatedIndicatorsType.class,
    org.mitre.stix.campaign_1.RelatedIncidentsType.class,
    org.mitre.stix.campaign_1.AssociatedCampaignsType.class,
    org.mitre.stix.campaign_1.RelatedTTPsType.class,
    AssociatedActorsType.class,
    org.mitre.stix.threatactor_1.AssociatedCampaignsType.class,
    ObservedTTPsType.class,
    RelatedPackagesType.class,
    AttributedThreatActorsType.class,
    LeveragedTTPsType.class,
    org.mitre.stix.incident_1.RelatedIndicatorsType.class,
    org.mitre.stix.incident_1.RelatedObservablesType.class,
    org.mitre.stix.incident_1.RelatedIncidentsType.class
})
public abstract class GenericRelationshipListType {

    @XmlAttribute(name = "scope")
    protected RelationshipScopeEnum scope;

    /**
     * Gets the value of the scope property.
     * 
     * @return
     *     possible object is
     *     {@link RelationshipScopeEnum }
     *     
     */
    public RelationshipScopeEnum getScope() {
        if (scope == null) {
            return RelationshipScopeEnum.EXCLUSIVE;
        } else {
            return scope;
        }
    }

    /**
     * Sets the value of the scope property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelationshipScopeEnum }
     *     
     */
    public void setScope(RelationshipScopeEnum value) {
        this.scope = value;
    }

}
