//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.default_vocabularies_2;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ObjectStateEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ObjectStateEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Exists"/>
 *     &lt;enumeration value="Does Not Exist"/>
 *     &lt;enumeration value="Open"/>
 *     &lt;enumeration value="Closed"/>
 *     &lt;enumeration value="Active"/>
 *     &lt;enumeration value="Inactive"/>
 *     &lt;enumeration value="Locked"/>
 *     &lt;enumeration value="Unlocked"/>
 *     &lt;enumeration value="Started"/>
 *     &lt;enumeration value="Stopped"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ObjectStateEnum-1.0")
@XmlEnum
public enum ObjectStateEnum10 {


    /**
     * Specifies that the object exists.
     * 
     */
    @XmlEnumValue("Exists")
    EXISTS("Exists"),

    /**
     * Specifies that the object does not exist.
     * 
     */
    @XmlEnumValue("Does Not Exist")
    DOES_NOT_EXIST("Does Not Exist"),

    /**
     * Specifies that the object is open.
     * 
     */
    @XmlEnumValue("Open")
    OPEN("Open"),

    /**
     * Specifies that the object is closed.
     * 
     */
    @XmlEnumValue("Closed")
    CLOSED("Closed"),

    /**
     * Specifies that the object is active.
     * 
     */
    @XmlEnumValue("Active")
    ACTIVE("Active"),

    /**
     * Specifies that the object is inactive.
     * 
     */
    @XmlEnumValue("Inactive")
    INACTIVE("Inactive"),

    /**
     * Specifies that the object is locked.
     * 
     */
    @XmlEnumValue("Locked")
    LOCKED("Locked"),

    /**
     * Specifies that the object is unlocked.
     * 
     */
    @XmlEnumValue("Unlocked")
    UNLOCKED("Unlocked"),

    /**
     * Specifies that the object has started.
     * 
     */
    @XmlEnumValue("Started")
    STARTED("Started"),

    /**
     * Specifies that the object has stopped.
     * 
     */
    @XmlEnumValue("Stopped")
    STOPPED("Stopped");
    private final String value;

    ObjectStateEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ObjectStateEnum10 fromValue(String v) {
        for (ObjectStateEnum10 c: ObjectStateEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
