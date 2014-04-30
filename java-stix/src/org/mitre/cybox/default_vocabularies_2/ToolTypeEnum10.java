//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.default_vocabularies_2;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ToolTypeEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ToolTypeEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="NIDS"/>
 *     &lt;enumeration value="NIPS"/>
 *     &lt;enumeration value="HIDS"/>
 *     &lt;enumeration value="HIPS"/>
 *     &lt;enumeration value="Firewall"/>
 *     &lt;enumeration value="Router"/>
 *     &lt;enumeration value="Proxy"/>
 *     &lt;enumeration value="Gateway"/>
 *     &lt;enumeration value="SNMP/MIBs"/>
 *     &lt;enumeration value="A/V"/>
 *     &lt;enumeration value="DBMS Monitor"/>
 *     &lt;enumeration value="Vulnerability Scanner"/>
 *     &lt;enumeration value="Configuration Scanner"/>
 *     &lt;enumeration value="Asset Scanner"/>
 *     &lt;enumeration value="SIM"/>
 *     &lt;enumeration value="SEM"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ToolTypeEnum-1.0")
@XmlEnum
public enum ToolTypeEnum10 {


    /**
     * The NIDS value specifies the Network Intrusion Detection System tool.
     * 
     */
    NIDS("NIDS"),

    /**
     * The NIPS value specifies the Network Intrusion Protection System tool.
     * 
     */
    NIPS("NIPS"),

    /**
     * The HIDS value specifies the Host-based Intrusion Detection System tool.
     * 
     */
    HIDS("HIDS"),

    /**
     * The HIPS value specifies the Host-based Intrusion Protection System tool.
     * 
     */
    HIPS("HIPS"),

    /**
     * The Firewall value specifies a cyber observation made using a firewall.
     * 
     */
    @XmlEnumValue("Firewall")
    FIREWALL("Firewall"),

    /**
     * The Router value specifies a cyber observation made using a router.
     * 
     */
    @XmlEnumValue("Router")
    ROUTER("Router"),

    /**
     * The Proxy value specifies a cyber observation made using a network proxy.
     * 
     */
    @XmlEnumValue("Proxy")
    PROXY("Proxy"),

    /**
     * The Gateway value specifies a cyber observation made using a network gateway.
     * 
     */
    @XmlEnumValue("Gateway")
    GATEWAY("Gateway"),

    /**
     * The SNMP/MIBs value specifies a cyber observation made using the Simple Network Management Protocol or via the Management Information Bases.
     * 
     */
    @XmlEnumValue("SNMP/MIBs")
    SNMP_MI_BS("SNMP/MIBs"),

    /**
     * The A/V value specifies a cyber observation made using Anti-Virus tools and/or software.
     * 
     */
    @XmlEnumValue("A/V")
    A_V("A/V"),

    /**
     * The DBMS value specifies a cyber observation made using a Database Management System monitor.
     * 
     */
    @XmlEnumValue("DBMS Monitor")
    DBMS_MONITOR("DBMS Monitor"),

    /**
     * The Vulnerability Scanner value specifies a cyber observation made using a vulnerability scanner.
     * 
     */
    @XmlEnumValue("Vulnerability Scanner")
    VULNERABILITY_SCANNER("Vulnerability Scanner"),

    /**
     * The Configuration Scanner value specifies a cyber observation made using a configuration scanner.
     * 
     */
    @XmlEnumValue("Configuration Scanner")
    CONFIGURATION_SCANNER("Configuration Scanner"),

    /**
     * The Asset Scanner value specifies a cyber observation made using an asset scanner.
     * 
     */
    @XmlEnumValue("Asset Scanner")
    ASSET_SCANNER("Asset Scanner"),

    /**
     * The SIM value specifies a cyber observation made using Security Information Management tools.
     * 
     */
    SIM("SIM"),

    /**
     * The SEM value specifies a cyber observation made using Security Event Management tools.
     * 
     */
    SEM("SEM");
    private final String value;

    ToolTypeEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ToolTypeEnum10 fromValue(String v) {
        for (ToolTypeEnum10 c: ToolTypeEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
