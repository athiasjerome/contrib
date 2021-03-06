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
import org.mitre.cybox.common_2.HashListType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The IExecActionType type characterizes IExec actions.
 * 
 * <p>Java class for IExecActionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IExecActionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Exec_Arguments" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Exec_Program_Path" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Exec_Working_Directory" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Exec_Program_Hashes" type="{http://cybox.mitre.org/common-2}HashListType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IExecActionType", namespace = "http://cybox.mitre.org/objects#WinTaskObject-2", propOrder = {
    "execArguments",
    "execProgramPath",
    "execWorkingDirectory",
    "execProgramHashes"
})
public class IExecActionType {

    @XmlElement(name = "Exec_Arguments")
    protected StringObjectPropertyType execArguments;
    @XmlElement(name = "Exec_Program_Path")
    protected StringObjectPropertyType execProgramPath;
    @XmlElement(name = "Exec_Working_Directory")
    protected StringObjectPropertyType execWorkingDirectory;
    @XmlElement(name = "Exec_Program_Hashes")
    protected HashListType execProgramHashes;

    /**
     * Gets the value of the execArguments property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getExecArguments() {
        return execArguments;
    }

    /**
     * Sets the value of the execArguments property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setExecArguments(StringObjectPropertyType value) {
        this.execArguments = value;
    }

    /**
     * Gets the value of the execProgramPath property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getExecProgramPath() {
        return execProgramPath;
    }

    /**
     * Sets the value of the execProgramPath property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setExecProgramPath(StringObjectPropertyType value) {
        this.execProgramPath = value;
    }

    /**
     * Gets the value of the execWorkingDirectory property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getExecWorkingDirectory() {
        return execWorkingDirectory;
    }

    /**
     * Sets the value of the execWorkingDirectory property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setExecWorkingDirectory(StringObjectPropertyType value) {
        this.execWorkingDirectory = value;
    }

    /**
     * Gets the value of the execProgramHashes property.
     * 
     * @return
     *     possible object is
     *     {@link HashListType }
     *     
     */
    public HashListType getExecProgramHashes() {
        return execProgramHashes;
    }

    /**
     * Sets the value of the execProgramHashes property.
     * 
     * @param value
     *     allowed object is
     *     {@link HashListType }
     *     
     */
    public void setExecProgramHashes(HashListType value) {
        this.execProgramHashes = value;
    }

}
