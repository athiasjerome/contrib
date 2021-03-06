//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SiLKDirectionTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SiLKDirectionTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="in"/>
 *     &lt;enumeration value="inweb"/>
 *     &lt;enumeration value="innull"/>
 *     &lt;enumeration value="out"/>
 *     &lt;enumeration value="outweb"/>
 *     &lt;enumeration value="outnull"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SiLKDirectionTypeEnum", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2")
@XmlEnum
public enum SiLKDirectionTypeEnum {


    /**
     * Denotes inbound traffic relative to a sensor.
     * 
     */
    @XmlEnumValue("in")
    IN("in"),

    /**
     * Denotes inbound web traffic relative to a sensor. SiLK categorizes a flow as web if the protocol is TCP and either the source port or destination port is one of 80, 443, or 8080.
     * 
     */
    @XmlEnumValue("inweb")
    INWEB("inweb"),

    /**
     * Denotes null inbound traffic relative to a sensor.
     * 
     */
    @XmlEnumValue("innull")
    INNULL("innull"),

    /**
     * Denotes outbound traffic relative to a sensor.
     * 
     */
    @XmlEnumValue("out")
    OUT("out"),

    /**
     * Denotes outbound web traffic relative to a sensor. SiLK categorizes a flow as web if the protocol is TCP and either the source port or destination port is one of 80, 443, or 8080.
     * 
     */
    @XmlEnumValue("outweb")
    OUTWEB("outweb"),

    /**
     * Denotes null outbound traffic relative to a sensor.
     * 
     */
    @XmlEnumValue("outnull")
    OUTNULL("outnull");
    private final String value;

    SiLKDirectionTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SiLKDirectionTypeEnum fromValue(String v) {
        for (SiLKDirectionTypeEnum c: SiLKDirectionTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
