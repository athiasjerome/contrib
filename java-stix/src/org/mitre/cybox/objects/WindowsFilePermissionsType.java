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
 * The WindowsFilePermissionsType type specifies Windows file permissions. It imports and extends the FilePermissionsType from the CybOX File Object.
 * 
 * <p>Java class for WindowsFilePermissionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsFilePermissionsType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#FileObject-2}FilePermissionsType">
 *       &lt;sequence>
 *         &lt;element name="Full_Control" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="Modify" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="Read" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="Read_And_Execute" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="Write" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsFilePermissionsType", namespace = "http://cybox.mitre.org/objects#WinFileObject-2", propOrder = {
    "fullControl",
    "modify",
    "read",
    "readAndExecute",
    "write"
})
public class WindowsFilePermissionsType
    extends FilePermissionsType
{

    @XmlElement(name = "Full_Control")
    protected Boolean fullControl;
    @XmlElement(name = "Modify")
    protected Boolean modify;
    @XmlElement(name = "Read")
    protected Boolean read;
    @XmlElement(name = "Read_And_Execute")
    protected Boolean readAndExecute;
    @XmlElement(name = "Write")
    protected Boolean write;

    /**
     * Gets the value of the fullControl property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isFullControl() {
        return fullControl;
    }

    /**
     * Sets the value of the fullControl property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setFullControl(Boolean value) {
        this.fullControl = value;
    }

    /**
     * Gets the value of the modify property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isModify() {
        return modify;
    }

    /**
     * Sets the value of the modify property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setModify(Boolean value) {
        this.modify = value;
    }

    /**
     * Gets the value of the read property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isRead() {
        return read;
    }

    /**
     * Sets the value of the read property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setRead(Boolean value) {
        this.read = value;
    }

    /**
     * Gets the value of the readAndExecute property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isReadAndExecute() {
        return readAndExecute;
    }

    /**
     * Sets the value of the readAndExecute property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setReadAndExecute(Boolean value) {
        this.readAndExecute = value;
    }

    /**
     * Gets the value of the write property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isWrite() {
        return write;
    }

    /**
     * Sets the value of the write property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setWrite(Boolean value) {
        this.write = value;
    }

}
