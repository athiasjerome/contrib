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
 * <p>Java class for UnixProcessStateEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="UnixProcessStateEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Running"/>
 *     &lt;enumeration value="UninterruptibleSleep"/>
 *     &lt;enumeration value="InterruptibleSleep"/>
 *     &lt;enumeration value="Stopped"/>
 *     &lt;enumeration value="Paging"/>
 *     &lt;enumeration value="Dead"/>
 *     &lt;enumeration value="Zombie"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "UnixProcessStateEnum", namespace = "http://cybox.mitre.org/objects#UnixProcessObject-2")
@XmlEnum
public enum UnixProcessStateEnum {


    /**
     * Specifies a running process or runnable [on run queue] (R).
     * 
     */
    @XmlEnumValue("Running")
    RUNNING("Running"),

    /**
     * Specifies a process in uninterruptable sleep [usually IO] (D).
     * 
     */
    @XmlEnumValue("UninterruptibleSleep")
    UNINTERRUPTIBLE_SLEEP("UninterruptibleSleep"),

    /**
     * Specifies a process in interruptable sleep [waiting for an event to complete] (S).
     * 
     */
    @XmlEnumValue("InterruptibleSleep")
    INTERRUPTIBLE_SLEEP("InterruptibleSleep"),

    /**
     * Specifies a stopped process, either by a job control signal or because it is being traced (T).
     * 
     */
    @XmlEnumValue("Stopped")
    STOPPED("Stopped"),

    /**
     * Specifies a paging process [not valid since the 2.6.xx kernel] (W).
     * 
     */
    @XmlEnumValue("Paging")
    PAGING("Paging"),

    /**
     * Specifies a dead process [should never be seen] (X).
     * 
     */
    @XmlEnumValue("Dead")
    DEAD("Dead"),

    /**
     * Specifies a defunct, zombie process [terminated but not reaped by its parent] (Z).
     * 
     */
    @XmlEnumValue("Zombie")
    ZOMBIE("Zombie");
    private final String value;

    UnixProcessStateEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static UnixProcessStateEnum fromValue(String v) {
        for (UnixProcessStateEnum c: UnixProcessStateEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
