//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.maec.default_vocabularies_1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PersistencePropertiesEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="PersistencePropertiesEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="scope"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "PersistencePropertiesEnum-1.0")
@XmlEnum
public enum PersistencePropertiesEnum10 {


    /**
     * Recommended values are: 'self', or 'other malware/components'.
     * 
     */
    @XmlEnumValue("scope")
    SCOPE("scope");
    private final String value;

    PersistencePropertiesEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static PersistencePropertiesEnum10 fromValue(String v) {
        for (PersistencePropertiesEnum10 c: PersistencePropertiesEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
