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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.SIDType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The WindowsProcessObjectType type is intended to characterize Windows processes.
 * 
 * <p>Java class for WindowsProcessObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsProcessObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#ProcessObject-2}ProcessObjectType">
 *       &lt;sequence>
 *         &lt;element name="Handle_List" type="{http://cybox.mitre.org/objects#WinHandleObject-2}WindowsHandleListType" minOccurs="0"/>
 *         &lt;element name="Priority" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Section_List" type="{http://cybox.mitre.org/objects#WinProcessObject-2}MemorySectionListType" minOccurs="0"/>
 *         &lt;element name="Security_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Startup_Info" type="{http://cybox.mitre.org/objects#WinProcessObject-2}StartupInfoType" minOccurs="0"/>
 *         &lt;element name="Security_Type" type="{http://cybox.mitre.org/common-2}SIDType" minOccurs="0"/>
 *         &lt;element name="Window_Title" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Thread" type="{http://cybox.mitre.org/objects#WinThreadObject-2}WindowsThreadObjectType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="aslr_enabled" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="dep_enabled" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsProcessObjectType", namespace = "http://cybox.mitre.org/objects#WinProcessObject-2", propOrder = {
    "handleList",
    "priority",
    "sectionList",
    "securityID",
    "startupInfo",
    "securityType",
    "windowTitle",
    "thread"
})
@XmlSeeAlso({
    WindowsServiceObjectType.class
})
public class WindowsProcessObjectType
    extends ProcessObjectType
{

    @XmlElement(name = "Handle_List")
    protected WindowsHandleListType handleList;
    @XmlElement(name = "Priority")
    protected StringObjectPropertyType priority;
    @XmlElement(name = "Section_List")
    protected MemorySectionListType sectionList;
    @XmlElement(name = "Security_ID")
    protected StringObjectPropertyType securityID;
    @XmlElement(name = "Startup_Info")
    protected StartupInfoType startupInfo;
    @XmlElement(name = "Security_Type")
    protected SIDType securityType;
    @XmlElement(name = "Window_Title")
    protected StringObjectPropertyType windowTitle;
    @XmlElement(name = "Thread")
    protected List<WindowsThreadObjectType> thread;
    @XmlAttribute(name = "aslr_enabled")
    protected Boolean aslrEnabled;
    @XmlAttribute(name = "dep_enabled")
    protected Boolean depEnabled;

    /**
     * Gets the value of the handleList property.
     * 
     * @return
     *     possible object is
     *     {@link WindowsHandleListType }
     *     
     */
    public WindowsHandleListType getHandleList() {
        return handleList;
    }

    /**
     * Sets the value of the handleList property.
     * 
     * @param value
     *     allowed object is
     *     {@link WindowsHandleListType }
     *     
     */
    public void setHandleList(WindowsHandleListType value) {
        this.handleList = value;
    }

    /**
     * Gets the value of the priority property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getPriority() {
        return priority;
    }

    /**
     * Sets the value of the priority property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setPriority(StringObjectPropertyType value) {
        this.priority = value;
    }

    /**
     * Gets the value of the sectionList property.
     * 
     * @return
     *     possible object is
     *     {@link MemorySectionListType }
     *     
     */
    public MemorySectionListType getSectionList() {
        return sectionList;
    }

    /**
     * Sets the value of the sectionList property.
     * 
     * @param value
     *     allowed object is
     *     {@link MemorySectionListType }
     *     
     */
    public void setSectionList(MemorySectionListType value) {
        this.sectionList = value;
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
     * Gets the value of the startupInfo property.
     * 
     * @return
     *     possible object is
     *     {@link StartupInfoType }
     *     
     */
    public StartupInfoType getStartupInfo() {
        return startupInfo;
    }

    /**
     * Sets the value of the startupInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link StartupInfoType }
     *     
     */
    public void setStartupInfo(StartupInfoType value) {
        this.startupInfo = value;
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
     * Gets the value of the windowTitle property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getWindowTitle() {
        return windowTitle;
    }

    /**
     * Sets the value of the windowTitle property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setWindowTitle(StringObjectPropertyType value) {
        this.windowTitle = value;
    }

    /**
     * Gets the value of the thread property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the thread property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getThread().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link WindowsThreadObjectType }
     * 
     * 
     */
    public List<WindowsThreadObjectType> getThread() {
        if (thread == null) {
            thread = new ArrayList<WindowsThreadObjectType>();
        }
        return this.thread;
    }

    /**
     * Gets the value of the aslrEnabled property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isAslrEnabled() {
        return aslrEnabled;
    }

    /**
     * Sets the value of the aslrEnabled property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setAslrEnabled(Boolean value) {
        this.aslrEnabled = value;
    }

    /**
     * Gets the value of the depEnabled property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isDepEnabled() {
        return depEnabled;
    }

    /**
     * Sets the value of the depEnabled property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setDepEnabled(Boolean value) {
        this.depEnabled = value;
    }

}
