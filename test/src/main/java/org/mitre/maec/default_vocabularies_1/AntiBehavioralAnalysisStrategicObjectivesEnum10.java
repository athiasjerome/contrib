//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.09 at 05:02:22 PM EDT 
//


package org.mitre.maec.default_vocabularies_1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AntiBehavioralAnalysisStrategicObjectivesEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="AntiBehavioralAnalysisStrategicObjectivesEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="anti-vm"/>
 *     &lt;enumeration value="anti-sandbox"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AntiBehavioralAnalysisStrategicObjectivesEnum-1.0")
@XmlEnum
public enum AntiBehavioralAnalysisStrategicObjectivesEnum10 {


    /**
     * The 'anti-vm' value indicates that the malware instance is able to prevent virtual machine (VM) based behavioral analysis or make it more difficult.
     * 
     */
    @XmlEnumValue("anti-vm")
    ANTI_VM("anti-vm"),

    /**
     * The 'anti-sandbox' value specifies that the malware instance is able to prevent sandbox-based behavioral analysis or make it more difficult.
     * 
     */
    @XmlEnumValue("anti-sandbox")
    ANTI_SANDBOX("anti-sandbox");
    private final String value;

    AntiBehavioralAnalysisStrategicObjectivesEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static AntiBehavioralAnalysisStrategicObjectivesEnum10 fromValue(String v) {
        for (AntiBehavioralAnalysisStrategicObjectivesEnum10 c: AntiBehavioralAnalysisStrategicObjectivesEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}