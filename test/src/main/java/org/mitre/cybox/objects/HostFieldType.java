//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.09 at 05:02:22 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The HostFieldType captures the details of the HTTP request Host header field.
 * 
 * <p>Java class for HostFieldType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="HostFieldType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Domain_Name" type="{http://cybox.mitre.org/objects#URIObject-2}URIObjectType" minOccurs="0"/>
 *         &lt;element name="Port" type="{http://cybox.mitre.org/objects#PortObject-2}PortObjectType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "HostFieldType", propOrder = {
    "domainName",
    "port"
})
public class HostFieldType {

    @XmlElement(name = "Domain_Name")
    protected URIObjectType domainName;
    @XmlElement(name = "Port")
    protected PortObjectType port;

    /**
     * Gets the value of the domainName property.
     * 
     * @return
     *     possible object is
     *     {@link URIObjectType }
     *     
     */
    public URIObjectType getDomainName() {
        return domainName;
    }

    /**
     * Sets the value of the domainName property.
     * 
     * @param value
     *     allowed object is
     *     {@link URIObjectType }
     *     
     */
    public void setDomainName(URIObjectType value) {
        this.domainName = value;
    }

    /**
     * Gets the value of the port property.
     * 
     * @return
     *     possible object is
     *     {@link PortObjectType }
     *     
     */
    public PortObjectType getPort() {
        return port;
    }

    /**
     * Sets the value of the port property.
     * 
     * @param value
     *     allowed object is
     *     {@link PortObjectType }
     *     
     */
    public void setPort(PortObjectType value) {
        this.port = value;
    }

}