//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.oval.xmlschema.oval_common_5;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SimpleDatatypeEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SimpleDatatypeEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="binary"/>
 *     &lt;enumeration value="boolean"/>
 *     &lt;enumeration value="evr_string"/>
 *     &lt;enumeration value="fileset_revision"/>
 *     &lt;enumeration value="float"/>
 *     &lt;enumeration value="ios_version"/>
 *     &lt;enumeration value="int"/>
 *     &lt;enumeration value="ipv4_address"/>
 *     &lt;enumeration value="ipv6_address"/>
 *     &lt;enumeration value="string"/>
 *     &lt;enumeration value="version"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SimpleDatatypeEnumeration")
@XmlEnum
public enum SimpleDatatypeEnumeration {


    /**
     * The binary datatype is used to represent hex-encoded data that is in raw (non-printable) form. This datatype conforms to the W3C Recommendation for binary data meaning that each binary octet is encoded as a character tuple, consisting of two hexadecimal digits {[0-9a-fA-F]} representing the octet code.  Expected operations within OVAL for binary values are 'equals' and 'not equal'.
     * 
     */
    @XmlEnumValue("binary")
    BINARY("binary"),

    /**
     * The boolean datatype represents standard boolean data, either true or false.  This datatype conforms to the W3C Recommendation for boolean data meaning that the following literals are legal values: {true, false, 1, 0}.  Expected operations within OVAL for boolean values are 'equals' and 'not equal'.
     * 
     */
    @XmlEnumValue("boolean")
    BOOLEAN("boolean"),

    /**
     * The evr_string datatype represents the epoch, version, and release fields as a single version string. It has the form "EPOCH:VERSION-RELEASE". Comparisons involving this datatype should follow the algorithm of librpm's rpmvercmp() function. Expected operations within OVAL for evr_string values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
     * 
     */
    @XmlEnumValue("evr_string")
    EVR_STRING("evr_string"),

    /**
     * The fileset_revision datatype represents the version string related to filesets in HP-UX. An example would be 'A.03.61.00'. For more information, see the HP-UX "Software Distributor Administration Guide" (http://h20000.www2.hp.com/bc/docs/support/SupportManual/c01919399/c01919399.pdf).  Expected operations within OVAL for fileset_version values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
     * 
     */
    @XmlEnumValue("fileset_revision")
    FILESET_REVISION("fileset_revision"),

    /**
     * The float datatype describes standard float data.  This datatype conforms to the W3C Recommendation for float data meaning it is patterned after the IEEE single-precision 32-bit floating point type.  The format consists of a decimal followed, optionally, by the character 'E' or 'e', followed by an integer exponent.  The special values positive and negative infinity and not-a-number have are represented by INF, -INF and NaN, respectively.  Expected operations within OVAL for float values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
     * 
     */
    @XmlEnumValue("float")
    FLOAT("float"),

    /**
     * The ios_version datatype describes Cisco IOS Train strings. These are in essence version strings for IOS. Please refer to Cisco's IOS Reference Guide for information on how to compare different Trains as they follow a very specific pattern. Expected operations within OVAL for ios_version values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
     * 
     */
    @XmlEnumValue("ios_version")
    IOS_VERSION("ios_version"),

    /**
     * The int datatype describes standard integer data.  This datatype conforms to the W3C Recommendation for integer data which follows the standard mathematical concept of the integer numbers.  (no decimal point and infinite range)  Expected operations within OVAL for int values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', 'less than or equal', 'bitwise and', and 'bitwise or'.
     * 
     */
    @XmlEnumValue("int")
    INT("int"),

    /**
     * The 'superset of' operation is used to compare sets of IP addresses. When using this operation, an IP address prefix defines the set of IP addresses as specified by CIDR notation and a IP address defines the set of one IP address. The result will be 'true', if the actual set of IP addresses on the system is a superset of the set defined by the stated entity. This means that every IP address in the set of IP addresses defined in the stated entity is present in the set of IP addresses on the system. Otherwise, the result will be 'false'.
     * 
     */
    @XmlEnumValue("ipv4_address")
    IPV_4_ADDRESS("ipv4_address"),

    /**
     * The 'superset of' operation is used to compare sets of IP addresses. When using this operation, an IP address prefix defines the set of IP addresses as specified by CIDR notation and a IP address defines the set of one IP address. The result will be 'true', if the actual set of IP addresses on the system is a superset of the set defined by the stated entity. This means that every IP address in the set of IP addresses defined in the stated entity is present in the set of IP addresses on the system. Otherwise, the result will be 'false'.
     * 
     */
    @XmlEnumValue("ipv6_address")
    IPV_6_ADDRESS("ipv6_address"),

    /**
     * The string datatype describes standard string data. This datatype conforms to the W3C Recommendation for string data.  Expected operations within OVAL for string values are 'equals', 'not equal', 'case insensitive equals', 'case insensitive not equal', 'pattern match'.
     * 
     */
    @XmlEnumValue("string")
    STRING("string"),

    /**
     * Version strings with a different number of components shall be padded with zeros to make them the same size. For example, if the version strings '1.2.3' and '6.7.8.9' are being compared, then the short one should be padded to become '1.2.3.0'.
     * 
     */
    @XmlEnumValue("version")
    VERSION("version");
    private final String value;

    SimpleDatatypeEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SimpleDatatypeEnumeration fromValue(String v) {
        for (SimpleDatatypeEnumeration c: SimpleDatatypeEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
