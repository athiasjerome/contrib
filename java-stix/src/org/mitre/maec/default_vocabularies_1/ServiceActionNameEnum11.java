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
 * <p>Java class for ServiceActionNameEnum-1.1.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ServiceActionNameEnum-1.1">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="create service"/>
 *     &lt;enumeration value="delete service"/>
 *     &lt;enumeration value="start service"/>
 *     &lt;enumeration value="stop service"/>
 *     &lt;enumeration value="enumerate services"/>
 *     &lt;enumeration value="modify service configuration"/>
 *     &lt;enumeration value="open service"/>
 *     &lt;enumeration value="send control code to service"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ServiceActionNameEnum-1.1")
@XmlEnum
public enum ServiceActionNameEnum11 {


    /**
     * The 'create service' value specifies the defined action of creating a new service.
     * 
     */
    @XmlEnumValue("create service")
    CREATE_SERVICE("create service"),

    /**
     * The 'delete service' value specifies the defined action of deleting an existing service.
     * 
     */
    @XmlEnumValue("delete service")
    DELETE_SERVICE("delete service"),

    /**
     * The 'start service' value specifies the defined action of starting an existing service.
     * 
     */
    @XmlEnumValue("start service")
    START_SERVICE("start service"),

    /**
     * The 'stop service' value specifies the defined action of stopping an existing service.
     * 
     */
    @XmlEnumValue("stop service")
    STOP_SERVICE("stop service"),

    /**
     * The 'enumerate services' value specifies the defined action of enumerating a specific set of services on a system.
     * 
     */
    @XmlEnumValue("enumerate services")
    ENUMERATE_SERVICES("enumerate services"),

    /**
     * The 'modify service configuration' value specifies the defined action of modifying the configuration parameters of an existing service.
     * 
     */
    @XmlEnumValue("modify service configuration")
    MODIFY_SERVICE_CONFIGURATION("modify service configuration"),

    /**
     * The 'open service' value specifies the defined action of opening an existing service.
     * 
     */
    @XmlEnumValue("open service")
    OPEN_SERVICE("open service"),

    /**
     * Windows-specific.
     * 
     */
    @XmlEnumValue("send control code to service")
    SEND_CONTROL_CODE_TO_SERVICE("send control code to service");
    private final String value;

    ServiceActionNameEnum11(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ServiceActionNameEnum11 fromValue(String v) {
        for (ServiceActionNameEnum11 c: ServiceActionNameEnum11 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}