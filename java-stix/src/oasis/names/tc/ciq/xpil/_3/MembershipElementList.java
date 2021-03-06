//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package oasis.names.tc.ciq.xpil._3;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for MembershipElementList.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="MembershipElementList">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}normalizedString">
 *     &lt;enumeration value="MembershipNumber"/>
 *     &lt;enumeration value="Privilege"/>
 *     &lt;enumeration value="Restriction"/>
 *     &lt;enumeration value="GroupName"/>
 *     &lt;enumeration value="Category"/>
 *     &lt;enumeration value="Type"/>
 *     &lt;enumeration value="IssuingCountryName"/>
 *     &lt;enumeration value="Role"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "MembershipElementList")
@XmlEnum
public enum MembershipElementList {


    /**
     * Membership identifier, e.g. membership number or some other type of ID
     * 
     */
    @XmlEnumValue("MembershipNumber")
    MEMBERSHIP_NUMBER("MembershipNumber"),

    /**
     * A privilege that the member can enjoy as part of the membership. E.g. access to free events.
     * 
     */
    @XmlEnumValue("Privilege")
    PRIVILEGE("Privilege"),

    /**
     * A restriction that the membership imposes on the member, e.g. do not smoke.
     * 
     */
    @XmlEnumValue("Restriction")
    RESTRICTION("Restriction"),

    /**
     * Larger group or alliance name the membership provides access to.
     * 
     */
    @XmlEnumValue("GroupName")
    GROUP_NAME("GroupName"),

    /**
     * Category of the membership such as Gold, Silver, Platinum, etc
     * 
     */
    @XmlEnumValue("Category")
    CATEGORY("Category"),

    /**
     * Use this if the enumeration list for type of memberhsip is not used.
     * 
     */
    @XmlEnumValue("Type")
    TYPE("Type"),

    /**
     * The country that issues the membership
     * 
     */
    @XmlEnumValue("IssuingCountryName")
    ISSUING_COUNTRY_NAME("IssuingCountryName"),

    /**
     * Role in membership for a person , e.g. secretary, President, treasurer
     * 
     */
    @XmlEnumValue("Role")
    ROLE("Role");
    private final String value;

    MembershipElementList(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static MembershipElementList fromValue(String v) {
        for (MembershipElementList c: MembershipElementList.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
