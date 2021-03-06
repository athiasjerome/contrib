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
 * <p>Java class for UserActionNameEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="UserActionNameEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="add user"/>
 *     &lt;enumeration value="delete user"/>
 *     &lt;enumeration value="enumerate users"/>
 *     &lt;enumeration value="get user attributes"/>
 *     &lt;enumeration value="logon as user"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "UserActionNameEnum-1.0")
@XmlEnum
public enum UserActionNameEnum10 {


    /**
     * The 'add user' value specifies the defined action of adding a new user.
     * 
     */
    @XmlEnumValue("add user")
    ADD_USER("add user"),

    /**
     * The 'delete user' value specifies the defined action of deleting an existing user.
     * 
     */
    @XmlEnumValue("delete user")
    DELETE_USER("delete user"),

    /**
     * The 'enumerate users' value specifies the defined action of enumerating all users.
     * 
     */
    @XmlEnumValue("enumerate users")
    ENUMERATE_USERS("enumerate users"),

    /**
     * The 'get user attributes' value specifies the defined action of getting the attributes of an existing user.
     * 
     */
    @XmlEnumValue("get user attributes")
    GET_USER_ATTRIBUTES("get user attributes"),

    /**
     * The 'logon as user' value specifies the defined action of logging on as a specific user.
     * 
     */
    @XmlEnumValue("logon as user")
    LOGON_AS_USER("logon as user");
    private final String value;

    UserActionNameEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static UserActionNameEnum10 fromValue(String v) {
        for (UserActionNameEnum10 c: UserActionNameEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
