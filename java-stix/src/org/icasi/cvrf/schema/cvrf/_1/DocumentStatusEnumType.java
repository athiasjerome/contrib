//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.icasi.cvrf.schema.cvrf._1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DocumentStatusEnumType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="DocumentStatusEnumType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}normalizedString">
 *     &lt;enumeration value="Draft"/>
 *     &lt;enumeration value="Interim"/>
 *     &lt;enumeration value="Final"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "DocumentStatusEnumType")
@XmlEnum
public enum DocumentStatusEnumType {


    /**
     * Pre-release, intended for issuing party’s internal use only, or possibly used externally when the party is seeking feedback or indicating its intentions regarding a specific issue.
     * 
     */
    @XmlEnumValue("Draft")
    DRAFT("Draft"),

    /**
     * The issuing party believes the content is subject to change.
     * 
     */
    @XmlEnumValue("Interim")
    INTERIM("Interim"),

    /**
     * The issuing party asserts the content is unlikely to change.
     * 
     */
    @XmlEnumValue("Final")
    FINAL("Final");
    private final String value;

    DocumentStatusEnumType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DocumentStatusEnumType fromValue(String v) {
        for (DocumentStatusEnumType c: DocumentStatusEnumType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}