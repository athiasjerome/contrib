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
 * <p>Java class for MachineAccessControlTacticalObjectivesEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="MachineAccessControlTacticalObjectivesEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="control machine via remote command"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "MachineAccessControlTacticalObjectivesEnum-1.0")
@XmlEnum
public enum MachineAccessControlTacticalObjectivesEnum10 {


    /**
     * The 'control machine via remote command' value indicates that the malware instance is able to execute commands issued to it from a remote source, for the purpose of controlling the machine on which it is resident.
     * 
     */
    @XmlEnumValue("control machine via remote command")
    CONTROL_MACHINE_VIA_REMOTE_COMMAND("control machine via remote command");
    private final String value;

    MachineAccessControlTacticalObjectivesEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static MachineAccessControlTacticalObjectivesEnum10 fromValue(String v) {
        for (MachineAccessControlTacticalObjectivesEnum10 c: MachineAccessControlTacticalObjectivesEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
