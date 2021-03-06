//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.UnsignedIntegerObjectPropertyType;
import org.mitre.cybox.common_2.UnsignedLongObjectPropertyType;


/**
 * The VolumeObjectType type is intended to characterize generic drive volumes.
 * 
 * <p>Java class for VolumeObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="VolumeObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Name" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Device_Path" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="File_System_Type" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Total_Allocation_Units" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Sectors_Per_Allocation_Unit" type="{http://cybox.mitre.org/common-2}UnsignedIntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Bytes_Per_Sector" type="{http://cybox.mitre.org/common-2}PositiveIntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Actual_Available_Allocation_Units" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Creation_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="File_System_Flag_List" type="{http://cybox.mitre.org/objects#VolumeObject-2}FileSystemFlagListType" minOccurs="0"/>
 *         &lt;element name="Serial_Number" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="is_mounted" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "VolumeObjectType", namespace = "http://cybox.mitre.org/objects#VolumeObject-2", propOrder = {
    "name",
    "devicePath",
    "fileSystemType",
    "totalAllocationUnits",
    "sectorsPerAllocationUnit",
    "bytesPerSector",
    "actualAvailableAllocationUnits",
    "creationTime",
    "fileSystemFlagList",
    "serialNumber"
})
@XmlSeeAlso({
    UnixVolumeObjectType.class,
    WindowsVolumeObjectType.class
})
public class VolumeObjectType
    extends ObjectPropertiesType
{

    @XmlElement(name = "Name")
    protected StringObjectPropertyType name;
    @XmlElement(name = "Device_Path")
    protected StringObjectPropertyType devicePath;
    @XmlElement(name = "File_System_Type")
    protected StringObjectPropertyType fileSystemType;
    @XmlElement(name = "Total_Allocation_Units")
    protected UnsignedLongObjectPropertyType totalAllocationUnits;
    @XmlElement(name = "Sectors_Per_Allocation_Unit")
    protected UnsignedIntegerObjectPropertyType sectorsPerAllocationUnit;
    @XmlElement(name = "Bytes_Per_Sector")
    protected PositiveIntegerObjectPropertyType bytesPerSector;
    @XmlElement(name = "Actual_Available_Allocation_Units")
    protected UnsignedLongObjectPropertyType actualAvailableAllocationUnits;
    @XmlElement(name = "Creation_Time")
    protected DateTimeObjectPropertyType creationTime;
    @XmlElement(name = "File_System_Flag_List")
    protected FileSystemFlagListType fileSystemFlagList;
    @XmlElement(name = "Serial_Number")
    protected StringObjectPropertyType serialNumber;
    @XmlAttribute(name = "is_mounted")
    protected Boolean isMounted;

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setName(StringObjectPropertyType value) {
        this.name = value;
    }

    /**
     * Gets the value of the devicePath property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getDevicePath() {
        return devicePath;
    }

    /**
     * Sets the value of the devicePath property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setDevicePath(StringObjectPropertyType value) {
        this.devicePath = value;
    }

    /**
     * Gets the value of the fileSystemType property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getFileSystemType() {
        return fileSystemType;
    }

    /**
     * Sets the value of the fileSystemType property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setFileSystemType(StringObjectPropertyType value) {
        this.fileSystemType = value;
    }

    /**
     * Gets the value of the totalAllocationUnits property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getTotalAllocationUnits() {
        return totalAllocationUnits;
    }

    /**
     * Sets the value of the totalAllocationUnits property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setTotalAllocationUnits(UnsignedLongObjectPropertyType value) {
        this.totalAllocationUnits = value;
    }

    /**
     * Gets the value of the sectorsPerAllocationUnit property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedIntegerObjectPropertyType }
     *     
     */
    public UnsignedIntegerObjectPropertyType getSectorsPerAllocationUnit() {
        return sectorsPerAllocationUnit;
    }

    /**
     * Sets the value of the sectorsPerAllocationUnit property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedIntegerObjectPropertyType }
     *     
     */
    public void setSectorsPerAllocationUnit(UnsignedIntegerObjectPropertyType value) {
        this.sectorsPerAllocationUnit = value;
    }

    /**
     * Gets the value of the bytesPerSector property.
     * 
     * @return
     *     possible object is
     *     {@link PositiveIntegerObjectPropertyType }
     *     
     */
    public PositiveIntegerObjectPropertyType getBytesPerSector() {
        return bytesPerSector;
    }

    /**
     * Sets the value of the bytesPerSector property.
     * 
     * @param value
     *     allowed object is
     *     {@link PositiveIntegerObjectPropertyType }
     *     
     */
    public void setBytesPerSector(PositiveIntegerObjectPropertyType value) {
        this.bytesPerSector = value;
    }

    /**
     * Gets the value of the actualAvailableAllocationUnits property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getActualAvailableAllocationUnits() {
        return actualAvailableAllocationUnits;
    }

    /**
     * Sets the value of the actualAvailableAllocationUnits property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setActualAvailableAllocationUnits(UnsignedLongObjectPropertyType value) {
        this.actualAvailableAllocationUnits = value;
    }

    /**
     * Gets the value of the creationTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getCreationTime() {
        return creationTime;
    }

    /**
     * Sets the value of the creationTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setCreationTime(DateTimeObjectPropertyType value) {
        this.creationTime = value;
    }

    /**
     * Gets the value of the fileSystemFlagList property.
     * 
     * @return
     *     possible object is
     *     {@link FileSystemFlagListType }
     *     
     */
    public FileSystemFlagListType getFileSystemFlagList() {
        return fileSystemFlagList;
    }

    /**
     * Sets the value of the fileSystemFlagList property.
     * 
     * @param value
     *     allowed object is
     *     {@link FileSystemFlagListType }
     *     
     */
    public void setFileSystemFlagList(FileSystemFlagListType value) {
        this.fileSystemFlagList = value;
    }

    /**
     * Gets the value of the serialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the value of the serialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setSerialNumber(StringObjectPropertyType value) {
        this.serialNumber = value;
    }

    /**
     * Gets the value of the isMounted property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsMounted() {
        return isMounted;
    }

    /**
     * Sets the value of the isMounted property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsMounted(Boolean value) {
        this.isMounted = value;
    }

}
