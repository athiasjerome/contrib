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
 * <p>Java class for CommandandControlStrategicObjectivesEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="CommandandControlStrategicObjectivesEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="determine c2 server"/>
 *     &lt;enumeration value="receive data from c2 server"/>
 *     &lt;enumeration value="send data to c2 server"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "CommandandControlStrategicObjectivesEnum-1.0")
@XmlEnum
public enum CommandandControlStrategicObjectivesEnum10 {


    /**
     * The 'determine c2 server' value indicates that the malware instance is able to identify one or more command and control (C2) servers with which to communicate.
     * 
     */
    @XmlEnumValue("determine c2 server")
    DETERMINE_C_2_SERVER("determine c2 server"),

    /**
     * The 'control behavior' value indicates that the malware instance is able to control its behavior through some external stimulus (e.g., a remotely submitted command).
     * 
     */
    @XmlEnumValue("receive data from c2 server")
    RECEIVE_DATA_FROM_C_2_SERVER("receive data from c2 server"),

    /**
     * The 'send data to c2 server' value indicates that the malware instance is able to send some data to a command and control server.
     * 
     */
    @XmlEnumValue("send data to c2 server")
    SEND_DATA_TO_C_2_SERVER("send data to c2 server");
    private final String value;

    CommandandControlStrategicObjectivesEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static CommandandControlStrategicObjectivesEnum10 fromValue(String v) {
        for (CommandandControlStrategicObjectivesEnum10 c: CommandandControlStrategicObjectivesEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
