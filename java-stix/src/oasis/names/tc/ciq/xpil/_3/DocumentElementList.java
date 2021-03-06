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
 * <p>Java class for DocumentElementList.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="DocumentElementList">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}normalizedString">
 *     &lt;enumeration value="DocumentID"/>
 *     &lt;enumeration value="DocumentName"/>
 *     &lt;enumeration value="Privilege"/>
 *     &lt;enumeration value="Restriction"/>
 *     &lt;enumeration value="GroupName"/>
 *     &lt;enumeration value="VerificationCode"/>
 *     &lt;enumeration value="Category"/>
 *     &lt;enumeration value="IssuePlace"/>
 *     &lt;enumeration value="AccessCode"/>
 *     &lt;enumeration value="Type"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "DocumentElementList")
@XmlEnum
public enum DocumentElementList {


    /**
     * Usually the number of the document, which can be alphanumeric
     * 
     */
    @XmlEnumValue("DocumentID")
    DOCUMENT_ID("DocumentID"),

    /**
     * Name of the document.e.g. VISA, MASTERCARD for credit cards
     * 
     */
    @XmlEnumValue("DocumentName")
    DOCUMENT_NAME("DocumentName"),

    /**
     * A privilege the holder of the document was grunted. E.g. security access level
     * 
     */
    @XmlEnumValue("Privilege")
    PRIVILEGE("Privilege"),

    /**
     * A restriction imposed on the holder of the document. E.g. learners license
     * 
     */
    @XmlEnumValue("Restriction")
    RESTRICTION("Restriction"),

    /**
     * A name of a larger group that recognises this document or supports it.
     * 
     */
    @XmlEnumValue("GroupName")
    GROUP_NAME("GroupName"),

    /**
     * Verirfication/security code as in credit card
     * 
     */
    @XmlEnumValue("VerificationCode")
    VERIFICATION_CODE("VerificationCode"),

    /**
     * Category of the document such as Donor Type in License,
     * Gold Card, Silver Card, Platinum Card, etc
     * 
     */
    @XmlEnumValue("Category")
    CATEGORY("Category"),

    /**
     * Place of issue of the document. e.g.  Sydney, Australia
     * 
     */
    @XmlEnumValue("IssuePlace")
    ISSUE_PLACE("IssuePlace"),

    /**
     * Access/Security code of the document
     * 
     */
    @XmlEnumValue("AccessCode")
    ACCESS_CODE("AccessCode"),

    /**
     * Use this if the enumeration list for type of document is not used.
     * 
     */
    @XmlEnumValue("Type")
    TYPE("Type");
    private final String value;

    DocumentElementList(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DocumentElementList fromValue(String v) {
        for (DocumentElementList c: DocumentElementList.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
