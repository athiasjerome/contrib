//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.stix.campaign_1;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.mitre.stix.campaign_1 package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _Campaign_QNAME = new QName("http://stix.mitre.org/Campaign-1", "Campaign");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.mitre.stix.campaign_1
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link CampaignType }
     * 
     */
    public CampaignType createCampaignType() {
        return new CampaignType();
    }

    /**
     * Create an instance of {@link AttributionType }
     * 
     */
    public AttributionType createAttributionType() {
        return new AttributionType();
    }

    /**
     * Create an instance of {@link NamesType }
     * 
     */
    public NamesType createNamesType() {
        return new NamesType();
    }

    /**
     * Create an instance of {@link RelatedIndicatorsType }
     * 
     */
    public RelatedIndicatorsType createRelatedIndicatorsType() {
        return new RelatedIndicatorsType();
    }

    /**
     * Create an instance of {@link RelatedIncidentsType }
     * 
     */
    public RelatedIncidentsType createRelatedIncidentsType() {
        return new RelatedIncidentsType();
    }

    /**
     * Create an instance of {@link AssociatedCampaignsType }
     * 
     */
    public AssociatedCampaignsType createAssociatedCampaignsType() {
        return new AssociatedCampaignsType();
    }

    /**
     * Create an instance of {@link RelatedTTPsType }
     * 
     */
    public RelatedTTPsType createRelatedTTPsType() {
        return new RelatedTTPsType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CampaignType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://stix.mitre.org/Campaign-1", name = "Campaign")
    public JAXBElement<CampaignType> createCampaign(CampaignType value) {
        return new JAXBElement<CampaignType>(_Campaign_QNAME, CampaignType.class, null, value);
    }

}
