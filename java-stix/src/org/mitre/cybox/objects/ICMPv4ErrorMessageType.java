//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * ICMP error messages include destination unreachable messages, source quench messages, redirect messages, and time exceeded messages.
 * 
 * <p>Java class for ICMPv4ErrorMessageType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ICMPv4ErrorMessageType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;choice minOccurs="0">
 *           &lt;element name="Destination_Unreachable" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4DestinationUnreachableType" minOccurs="0"/>
 *           &lt;element name="Source_Quench" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4SourceQuenchType" minOccurs="0"/>
 *           &lt;element name="Redirect_Message" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4RedirectMessageType" minOccurs="0"/>
 *           &lt;element name="Time_Exceeded" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4TimeExceededType" minOccurs="0" form="qualified"/>
 *         &lt;/choice>
 *         &lt;element name="Error_Msg_Content" type="{http://cybox.mitre.org/objects#PacketObject-2}ICMPv4ErrorMessageContentType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ICMPv4ErrorMessageType", propOrder = {
    "destinationUnreachable",
    "sourceQuench",
    "redirectMessage",
    "timeExceeded",
    "errorMsgContent"
})
public class ICMPv4ErrorMessageType {

    @XmlElement(name = "Destination_Unreachable")
    protected ICMPv4DestinationUnreachableType destinationUnreachable;
    @XmlElement(name = "Source_Quench")
    protected ICMPv4SourceQuenchType sourceQuench;
    @XmlElement(name = "Redirect_Message")
    protected ICMPv4RedirectMessageType redirectMessage;
    @XmlElement(name = "Time_Exceeded")
    protected ICMPv4TimeExceededType timeExceeded;
    @XmlElement(name = "Error_Msg_Content")
    protected ICMPv4ErrorMessageContentType errorMsgContent;

    /**
     * Gets the value of the destinationUnreachable property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4DestinationUnreachableType }
     *     
     */
    public ICMPv4DestinationUnreachableType getDestinationUnreachable() {
        return destinationUnreachable;
    }

    /**
     * Sets the value of the destinationUnreachable property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4DestinationUnreachableType }
     *     
     */
    public void setDestinationUnreachable(ICMPv4DestinationUnreachableType value) {
        this.destinationUnreachable = value;
    }

    /**
     * Gets the value of the sourceQuench property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4SourceQuenchType }
     *     
     */
    public ICMPv4SourceQuenchType getSourceQuench() {
        return sourceQuench;
    }

    /**
     * Sets the value of the sourceQuench property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4SourceQuenchType }
     *     
     */
    public void setSourceQuench(ICMPv4SourceQuenchType value) {
        this.sourceQuench = value;
    }

    /**
     * Gets the value of the redirectMessage property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4RedirectMessageType }
     *     
     */
    public ICMPv4RedirectMessageType getRedirectMessage() {
        return redirectMessage;
    }

    /**
     * Sets the value of the redirectMessage property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4RedirectMessageType }
     *     
     */
    public void setRedirectMessage(ICMPv4RedirectMessageType value) {
        this.redirectMessage = value;
    }

    /**
     * Gets the value of the timeExceeded property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4TimeExceededType }
     *     
     */
    public ICMPv4TimeExceededType getTimeExceeded() {
        return timeExceeded;
    }

    /**
     * Sets the value of the timeExceeded property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4TimeExceededType }
     *     
     */
    public void setTimeExceeded(ICMPv4TimeExceededType value) {
        this.timeExceeded = value;
    }

    /**
     * Gets the value of the errorMsgContent property.
     * 
     * @return
     *     possible object is
     *     {@link ICMPv4ErrorMessageContentType }
     *     
     */
    public ICMPv4ErrorMessageContentType getErrorMsgContent() {
        return errorMsgContent;
    }

    /**
     * Sets the value of the errorMsgContent property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICMPv4ErrorMessageContentType }
     *     
     */
    public void setErrorMsgContent(ICMPv4ErrorMessageContentType value) {
        this.errorMsgContent = value;
    }

}
