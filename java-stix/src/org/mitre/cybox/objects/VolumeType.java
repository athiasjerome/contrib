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
 * VolumeType characterizes the volume information in the Windows prefetch file.
 * 
 * <p>Java class for VolumeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="VolumeType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="VolumeItem" type="{http://cybox.mitre.org/objects#WinVolumeObject-2}WindowsVolumeObjectType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="DeviceItem" type="{http://cybox.mitre.org/objects#DeviceObject-2}DeviceObjectType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "VolumeType", namespace = "http://cybox.mitre.org/objects#WinPrefetchObject-2", propOrder = {
    "volumeItem",
    "deviceItem"
})
public class VolumeType {

    @XmlElement(name = "VolumeItem")
    protected List<WindowsVolumeObjectType> volumeItem;
    @XmlElement(name = "DeviceItem")
    protected List<DeviceObjectType> deviceItem;

    /**
     * Gets the value of the volumeItem property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the volumeItem property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getVolumeItem().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link WindowsVolumeObjectType }
     * 
     * 
     */
    public List<WindowsVolumeObjectType> getVolumeItem() {
        if (volumeItem == null) {
            volumeItem = new ArrayList<WindowsVolumeObjectType>();
        }
        return this.volumeItem;
    }

    /**
     * Gets the value of the deviceItem property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the deviceItem property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDeviceItem().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link DeviceObjectType }
     * 
     * 
     */
    public List<DeviceObjectType> getDeviceItem() {
        if (deviceItem == null) {
            deviceItem = new ArrayList<DeviceObjectType>();
        }
        return this.deviceItem;
    }

}