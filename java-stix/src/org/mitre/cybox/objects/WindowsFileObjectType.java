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
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.SIDType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The WindowsFileObjectType type is intended to characterize Windows files.
 * 
 * <p>Java class for WindowsFileObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsFileObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#FileObject-2}FileObjectType">
 *       &lt;sequence>
 *         &lt;element name="Filename_Accessed_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Filename_Created_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Filename_Modified_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Drive" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Security_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Security_Type" type="{http://cybox.mitre.org/common-2}SIDType" minOccurs="0"/>
 *         &lt;element name="Stream_List" type="{http://cybox.mitre.org/objects#WinFileObject-2}StreamListType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsFileObjectType", namespace = "http://cybox.mitre.org/objects#WinFileObject-2", propOrder = {
    "filenameAccessedTime",
    "filenameCreatedTime",
    "filenameModifiedTime",
    "drive",
    "securityID",
    "securityType",
    "streamList"
})
@XmlSeeAlso({
    WindowsExecutableFileObjectType.class
})
public class WindowsFileObjectType
    extends FileObjectType
{

    @XmlElement(name = "Filename_Accessed_Time")
    protected DateTimeObjectPropertyType filenameAccessedTime;
    @XmlElement(name = "Filename_Created_Time")
    protected DateTimeObjectPropertyType filenameCreatedTime;
    @XmlElement(name = "Filename_Modified_Time")
    protected DateTimeObjectPropertyType filenameModifiedTime;
    @XmlElement(name = "Drive")
    protected StringObjectPropertyType drive;
    @XmlElement(name = "Security_ID")
    protected StringObjectPropertyType securityID;
    @XmlElement(name = "Security_Type")
    protected SIDType securityType;
    @XmlElement(name = "Stream_List")
    protected StreamListType streamList;

    /**
     * Gets the value of the filenameAccessedTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getFilenameAccessedTime() {
        return filenameAccessedTime;
    }

    /**
     * Sets the value of the filenameAccessedTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setFilenameAccessedTime(DateTimeObjectPropertyType value) {
        this.filenameAccessedTime = value;
    }

    /**
     * Gets the value of the filenameCreatedTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getFilenameCreatedTime() {
        return filenameCreatedTime;
    }

    /**
     * Sets the value of the filenameCreatedTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setFilenameCreatedTime(DateTimeObjectPropertyType value) {
        this.filenameCreatedTime = value;
    }

    /**
     * Gets the value of the filenameModifiedTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getFilenameModifiedTime() {
        return filenameModifiedTime;
    }

    /**
     * Sets the value of the filenameModifiedTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setFilenameModifiedTime(DateTimeObjectPropertyType value) {
        this.filenameModifiedTime = value;
    }

    /**
     * Gets the value of the drive property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getDrive() {
        return drive;
    }

    /**
     * Sets the value of the drive property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setDrive(StringObjectPropertyType value) {
        this.drive = value;
    }

    /**
     * Gets the value of the securityID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getSecurityID() {
        return securityID;
    }

    /**
     * Sets the value of the securityID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setSecurityID(StringObjectPropertyType value) {
        this.securityID = value;
    }

    /**
     * Gets the value of the securityType property.
     * 
     * @return
     *     possible object is
     *     {@link SIDType }
     *     
     */
    public SIDType getSecurityType() {
        return securityType;
    }

    /**
     * Sets the value of the securityType property.
     * 
     * @param value
     *     allowed object is
     *     {@link SIDType }
     *     
     */
    public void setSecurityType(SIDType value) {
        this.securityType = value;
    }

    /**
     * Gets the value of the streamList property.
     * 
     * @return
     *     possible object is
     *     {@link StreamListType }
     *     
     */
    public StreamListType getStreamList() {
        return streamList;
    }

    /**
     * Sets the value of the streamList property.
     * 
     * @param value
     *     allowed object is
     *     {@link StreamListType }
     *     
     */
    public void setStreamList(StreamListType value) {
        this.streamList = value;
    }

}