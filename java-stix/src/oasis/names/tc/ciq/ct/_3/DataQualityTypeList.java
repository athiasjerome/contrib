//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package oasis.names.tc.ciq.ct._3;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DataQualityTypeList.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="DataQualityTypeList">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Valid"/>
 *     &lt;enumeration value="Invalid"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "DataQualityTypeList", namespace = "urn:oasis:names:tc:ciq:ct:3")
@XmlEnum
public enum DataQualityTypeList {


    /**
     * The data was validated and is considered to be true and correct.
     * 
     */
    @XmlEnumValue("Valid")
    VALID("Valid"),

    /**
     * Indicates that at least some part of the content is known to be incorrect.
     * 
     */
    @XmlEnumValue("Invalid")
    INVALID("Invalid");
    private final String value;

    DataQualityTypeList(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DataQualityTypeList fromValue(String v) {
        for (DataQualityTypeList c: DataQualityTypeList.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}