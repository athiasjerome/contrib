//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package oasis.names.tc.ciq.xal._3;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SubLocalityNameTypeList.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SubLocalityNameTypeList">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}normalizedString">
 *     &lt;enumeration value="Name"/>
 *     &lt;enumeration value="Number"/>
 *     &lt;enumeration value="ReferenceLocation"/>
 *     &lt;enumeration value="Type"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SubLocalityNameTypeList")
@XmlEnum
public enum SubLocalityNameTypeList {

    @XmlEnumValue("Name")
    NAME("Name"),
    @XmlEnumValue("Number")
    NUMBER("Number"),
    @XmlEnumValue("ReferenceLocation")
    REFERENCE_LOCATION("ReferenceLocation"),

    /**
     * Other supporting information 
     * 
     */
    @XmlEnumValue("Type")
    TYPE("Type");
    private final String value;

    SubLocalityNameTypeList(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SubLocalityNameTypeList fromValue(String v) {
        for (SubLocalityNameTypeList c: SubLocalityNameTypeList.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
