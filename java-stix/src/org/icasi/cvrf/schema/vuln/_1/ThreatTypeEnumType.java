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
 * <p>Java class for ThreatTypeEnumType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ThreatTypeEnumType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}token">
 *     &lt;enumeration value="Impact"/>
 *     &lt;enumeration value="Exploit Status"/>
 *     &lt;enumeration value="Target Set"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ThreatTypeEnumType")
@XmlEnum
public enum ThreatTypeEnumType {


    /**
     * Impact contains an assessment of the impact on the user or the target set if the vulnerability is successful exploited.
     * 
     */
    @XmlEnumValue("Impact")
    IMPACT("Impact"),

    /**
     * Exploit Status contains a description of the degree to which an exploit for the vulnerability is known.
     * 
     */
    @XmlEnumValue("Exploit Status")
    EXPLOIT_STATUS("Exploit Status"),

    /**
     * Target Set contains a description of the currently known victim population in whatever terms are appropriate.
     * 
     */
    @XmlEnumValue("Target Set")
    TARGET_SET("Target Set");
    private final String value;

    ThreatTypeEnumType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ThreatTypeEnumType fromValue(String v) {
        for (ThreatTypeEnumType c: ThreatTypeEnumType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
