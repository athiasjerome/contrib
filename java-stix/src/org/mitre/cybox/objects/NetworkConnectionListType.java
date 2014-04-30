//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The NetworkConnectionListType type is a list of network connections.
 * 
 * <p>Java class for NetworkConnectionListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetworkConnectionListType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Network_Connection" type="{http://cybox.mitre.org/objects#NetworkConnectionObject-2}NetworkConnectionObjectType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetworkConnectionListType", namespace = "http://cybox.mitre.org/objects#ProcessObject-2", propOrder = {
    "networkConnection"
})
public class NetworkConnectionListType {

    @XmlElement(name = "Network_Connection", required = true)
    protected List<NetworkConnectionObjectType> networkConnection;

    /**
     * Gets the value of the networkConnection property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the networkConnection property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getNetworkConnection().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NetworkConnectionObjectType }
     * 
     * 
     */
    public List<NetworkConnectionObjectType> getNetworkConnection() {
        if (networkConnection == null) {
            networkConnection = new ArrayList<NetworkConnectionObjectType>();
        }
        return this.networkConnection;
    }

}
