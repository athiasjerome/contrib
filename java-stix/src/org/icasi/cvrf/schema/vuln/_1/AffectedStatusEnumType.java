//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.icasi.cvrf.schema.vuln._1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AffectedStatusEnumType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="AffectedStatusEnumType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}token">
 *     &lt;enumeration value="First Affected"/>
 *     &lt;enumeration value="First Fixed"/>
 *     &lt;enumeration value="Fixed"/>
 *     &lt;enumeration value="Known Affected"/>
 *     &lt;enumeration value="Known Not Affected"/>
 *     &lt;enumeration value="Last Affected"/>
 *     &lt;enumeration value="Recommended"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AffectedStatusEnumType")
@XmlEnum
public enum AffectedStatusEnumType {


    /**
     * The first version known to be affected by this vulnerability.
     * 
     */
    @XmlEnumValue("First Affected")
    FIRST_AFFECTED("First Affected"),

    /**
     * This version is the first fixed version for the vulnerability but may not be the recommended fixed version.
     * 
     */
    @XmlEnumValue("First Fixed")
    FIRST_FIXED("First Fixed"),

    /**
     * This version is contains a fix for the vulnerability but may not be the recommended fixed version.
     * 
     */
    @XmlEnumValue("Fixed")
    FIXED("Fixed"),

    /**
     * This version is known to be affected by the vulnerability.
     * 
     */
    @XmlEnumValue("Known Affected")
    KNOWN_AFFECTED("Known Affected"),

    /**
     * This version is known NOT to be affected by the vulnerability.
     * 
     */
    @XmlEnumValue("Known Not Affected")
    KNOWN_NOT_AFFECTED("Known Not Affected"),

    /**
     * This is the last version in a train known to be affected.  Versions released after this would contain a fix for this vulnerability.
     * 
     */
    @XmlEnumValue("Last Affected")
    LAST_AFFECTED("Last Affected"),

    /**
     * This version has a fix for the vulnerability and is the vendor-recommended version for fixing the vulnerability.
     * 
     */
    @XmlEnumValue("Recommended")
    RECOMMENDED("Recommended");
    private final String value;

    AffectedStatusEnumType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static AffectedStatusEnumType fromValue(String v) {
        for (AffectedStatusEnumType c: AffectedStatusEnumType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
