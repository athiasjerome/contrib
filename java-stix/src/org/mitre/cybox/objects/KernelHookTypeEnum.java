//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for KernelHookTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="KernelHookTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="IAT_API"/>
 *     &lt;enumeration value="Inline_Function"/>
 *     &lt;enumeration value="Instruction_Hooking"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "KernelHookTypeEnum", namespace = "http://cybox.mitre.org/objects#WinKernelHookObject-2")
@XmlEnum
public enum KernelHookTypeEnum {


    /**
     * Specifies a kernel hook type of IAT_API.
     * 
     */
    IAT_API("IAT_API"),

    /**
     * Specifies an inline function type of kernel hook.
     * 
     */
    @XmlEnumValue("Inline_Function")
    INLINE_FUNCTION("Inline_Function"),

    /**
     * Specifies an instruction hooking type of kernel hook.
     * 
     */
    @XmlEnumValue("Instruction_Hooking")
    INSTRUCTION_HOOKING("Instruction_Hooking");
    private final String value;

    KernelHookTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static KernelHookTypeEnum fromValue(String v) {
        for (KernelHookTypeEnum c: KernelHookTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}