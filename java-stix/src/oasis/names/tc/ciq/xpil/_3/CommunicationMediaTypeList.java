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
 * <p>Java class for CommunicationMediaTypeList.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="CommunicationMediaTypeList">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}normalizedString">
 *     &lt;enumeration value="Cellphone"/>
 *     &lt;enumeration value="Fax"/>
 *     &lt;enumeration value="Pager"/>
 *     &lt;enumeration value="Telephone"/>
 *     &lt;enumeration value="VOIP"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "CommunicationMediaTypeList")
@XmlEnum
public enum CommunicationMediaTypeList {

    @XmlEnumValue("Cellphone")
    CELLPHONE("Cellphone"),
    @XmlEnumValue("Fax")
    FAX("Fax"),
    @XmlEnumValue("Pager")
    PAGER("Pager"),
    @XmlEnumValue("Telephone")
    TELEPHONE("Telephone"),
    VOIP("VOIP");
    private final String value;

    CommunicationMediaTypeList(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static CommunicationMediaTypeList fromValue(String v) {
        for (CommunicationMediaTypeList c: CommunicationMediaTypeList.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
